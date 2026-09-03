"""Tests for the filesystem-like per-user permissions model (permissions.py) and
the leak surfaces it must close in vault.list_directory / tools.search.vault_search.
"""

from contextlib import contextmanager

import json
import pytest

import obsidian_vault_mcp.config as config
import obsidian_vault_mcp.context as context
import obsidian_vault_mcp.permissions as permissions
from obsidian_vault_mcp.tools.search import vault_search
from obsidian_vault_mcp.tools.sharing import vault_share, vault_shares, vault_unshare
from obsidian_vault_mcp.vault import list_directory, read_file, write_file_atomic


@contextmanager
def _as_user(username):
    token = context.set_request_context(
        principal="test-token", request_id="test-request", client=None, username=username,
    )
    try:
        yield
    finally:
        context.reset_request_context(token)


@pytest.fixture(autouse=True)
def _reset_permissions_state(tmp_path, monkeypatch):
    """Isolate every test's permission config and runtime share store.

    monkeypatch.setattr (not env-var + reload) is used throughout this file, so
    plain teardown correctly reverts these module attributes -- there's no
    fixture-ordering hazard here the way there was in test_config.py's env-var
    reload fixture.
    """
    monkeypatch.setattr(config, "VAULT_SHARES_PATH", tmp_path / "shares.json")
    permissions._grants.clear()
    yield
    permissions._grants.clear()


def _enable(monkeypatch, user_roots: dict | None = None, default_roots=None):
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", True)
    monkeypatch.setattr(config, "VAULT_USER_ROOTS", user_roots or {})
    if default_roots is not None:
        monkeypatch.setattr(config, "VAULT_DEFAULT_ROOTS", default_roots)


# --- effective_bits / can_read / can_write -----------------------------------

def test_disabled_permissions_allow_everything(monkeypatch):
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", False)
    assert permissions.effective_bits("nobody", "anything.md") == frozenset({"r", "w"})
    assert permissions.can_read(None, "anything.md")
    assert permissions.can_write(None, "anything.md")


def test_no_username_is_default_deny(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("", "rw")]})
    assert permissions.effective_bits(None, "notes.md") == frozenset()
    assert not permissions.can_read(None, "notes.md")


def test_unmatched_user_is_default_deny(monkeypatch):
    _enable(monkeypatch, user_roots={})
    assert permissions.effective_bits("alice", "notes.md") == frozenset()


def test_longest_prefix_match_wins(monkeypatch):
    _enable(monkeypatch, user_roots={
        "alice": [("", "r"), ("projects/acme", "rw")],
    })
    assert permissions.effective_bits("alice", "projects/acme/notes.md") == frozenset({"r", "w"})
    assert permissions.effective_bits("alice", "other.md") == frozenset({"r"})


def test_strictly_longer_empty_bits_carve_out_denies(monkeypatch):
    _enable(monkeypatch, user_roots={
        "alice": [("", "rw"), ("secret", "")],
    })
    assert permissions.effective_bits("alice", "secret/file.md") == frozenset()
    assert permissions.effective_bits("alice", "other.md") == frozenset({"r", "w"})


def test_equal_length_tie_unions_permissively(monkeypatch):
    """An empty-bits entry does NOT carve out against a same-length permissive
    entry -- only a *strictly longer* empty-bits prefix carves. This is the one
    non-obvious rule in the model (see permissions.py's effective_bits docstring)."""
    _enable(monkeypatch, user_roots={
        "alice": [("docs", "rw")],
    })
    permissions.grant_share(granter="bob", subject="alice", prefix="docs", bits=frozenset())
    assert permissions.effective_bits("alice", "docs/file.md") == frozenset({"r", "w"})


# --- runtime share store: grant/revoke, cascade, idempotent re-share --------

def test_grant_share_is_idempotent_on_reshare(monkeypatch):
    _enable(monkeypatch)
    e1 = permissions.grant_share(granter="bob", subject="alice", prefix="docs", bits=frozenset("r"))
    e2 = permissions.grant_share(granter="bob", subject="alice", prefix="docs", bits=frozenset("rw"))
    assert e1.grant_id == e2.grant_id
    assert len(permissions.list_shares_by_subject("alice")) == 1
    assert permissions.effective_bits("alice", "docs/x.md") == frozenset({"r", "w"})


def test_revoke_share_cascades_to_derived_grants(monkeypatch):
    _enable(monkeypatch)
    root = permissions.grant_share(granter="bob", subject="alice", prefix="docs", bits=frozenset("rw"))
    child = permissions.grant_share(
        granter="alice", subject="carol", prefix="docs/sub", bits=frozenset("r"),
        derived_from=root.grant_id,
    )
    removed = permissions.revoke_share(prefix="docs", subject="alice")
    removed_ids = {e.grant_id for e in removed}
    assert root.grant_id in removed_ids
    assert child.grant_id in removed_ids
    assert permissions.find_share(subject="alice", prefix="docs") is None
    assert permissions.find_share(subject="carol", prefix="docs/sub") is None


def test_revoke_share_missing_grant_raises_keyerror(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(KeyError):
        permissions.revoke_share(prefix="nope", subject="alice")


def test_shares_persist_across_reload(monkeypatch, tmp_path):
    _enable(monkeypatch)
    permissions.grant_share(granter="bob", subject="alice", prefix="docs", bits=frozenset("r"))
    on_disk = json.loads(config.VAULT_SHARES_PATH.read_text())
    assert on_disk["version"] == 1
    assert len(on_disk["grants"]) == 1

    permissions._grants.clear()
    permissions._load_shares()
    assert permissions.find_share(subject="alice", prefix="docs") is not None


# --- leak tests: list_directory / vault_search must not reveal denied paths --

def test_list_directory_hides_everything_outside_the_grant(monkeypatch, vault_dir):
    _enable(monkeypatch, user_roots={
        "alice": [("subfolder/nested-note.md", "r")],
    })
    with _as_user("alice"):
        results = list_directory("", depth=2)

    paths = [item["path"] for item in results]
    assert paths == ["subfolder/nested-note.md"]


def test_list_directory_denies_outright_with_no_readable_descendant(monkeypatch, vault_dir):
    """Unlike list_directory(""), which alice's grant is always a descendant of
    (empty prefix matches everything), a sibling prefix she has no grant at, on,
    or under must fail outright rather than return an empty (indistinguishable
    from "this happens to be empty") listing."""
    (vault_dir / "other-area").mkdir()
    _enable(monkeypatch, user_roots={
        "alice": [("subfolder/nested-note.md", "r")],
    })
    with _as_user("alice"):
        with pytest.raises(permissions.PermissionDenied):
            list_directory("other-area")


def test_vault_search_only_returns_matches_the_user_can_read(monkeypatch, vault_dir):
    """Both test-note.md and subfolder/nested-note.md contain "note" -- with alice
    granted only the nested file, a search for "note" must surface exactly one
    match, not two-then-filtered-to-one-with-a-visible-gap."""
    _enable(monkeypatch, user_roots={
        "alice": [("subfolder/nested-note.md", "r")],
    })
    with _as_user("alice"):
        result = json.loads(vault_search("note"))

    assert result["total_matches"] == 1
    assert result["results"][0]["path"] == "subfolder/nested-note.md"


def test_vault_search_denies_outright_on_unreadable_path_prefix(monkeypatch, vault_dir):
    _enable(monkeypatch, user_roots={
        "alice": [("subfolder/nested-note.md", "r")],
    })
    with _as_user("alice"):
        result = json.loads(vault_search("note", path_prefix="other-area"))

    assert result.get("error") == "Permission denied"


# --- tools/sharing.py: vault_share / vault_unshare / vault_shares -----------

def test_vault_share_disabled_returns_explicit_error(monkeypatch):
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", False)
    with _as_user("alice"):
        result = json.loads(vault_share("docs", "bob", "r"))
    assert "not enabled" in result["error"]


def test_vault_share_rejects_self_share(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("", "rw")]})
    with _as_user("alice"):
        result = json.loads(vault_share("docs", "alice", "r"))
    assert "yourself" in result["error"]


def test_vault_share_rejects_unknown_user(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("", "rw")]})
    monkeypatch.setattr(config, "VAULT_OAUTH_USERS", {"alice": "x"})
    with _as_user("alice"):
        result = json.loads(vault_share("docs", "carol", "r"))
    assert "Unknown user" in result["error"]


def test_vault_share_rejects_granting_more_than_you_have(monkeypatch):
    """alice only has read at docs -- she must not be able to hand out write."""
    _enable(monkeypatch, user_roots={"alice": [("docs", "r")]})
    monkeypatch.setattr(config, "VAULT_OAUTH_USERS", {"alice": "x", "bob": "y"})
    with _as_user("alice"):
        result = json.loads(vault_share("docs", "bob", "rw"))
    assert "error" in result
    assert permissions.find_share(subject="bob", prefix="docs") is None


def test_vault_share_then_vault_shares_and_unshare_roundtrip(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("docs", "rw")]})
    monkeypatch.setattr(config, "VAULT_OAUTH_USERS", {"alice": "x", "bob": "y"})

    with _as_user("alice"):
        shared = json.loads(vault_share("docs", "bob", "r"))
        assert shared["path"] == "docs"
        assert shared["user"] == "bob"
        assert shared["access"] == "r"

        listing = json.loads(vault_shares())
        assert listing["granted"][0]["user"] == "bob"

    with _as_user("bob"):
        listing = json.loads(vault_shares())
        assert listing["received"][0]["path"] == "docs"
        assert permissions.can_read("bob", "docs/file.md")

    with _as_user("bob"):
        # bob didn't grant this share, so bob cannot revoke it.
        result = json.loads(vault_unshare("docs", "bob"))
        assert result["error"] == "Permission denied"

    with _as_user("alice"):
        result = json.loads(vault_unshare("docs", "bob"))
        assert result["revoked"] is True

    assert not permissions.can_read("bob", "docs/file.md")


def test_vault_unshare_unknown_share_reports_not_found(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("", "rw")]})
    with _as_user("alice"):
        result = json.loads(vault_unshare("docs", "bob"))
    assert "No share found" in result["error"]


# --- permissions.scope_path / home_root: auto-prefix into a user's own root -

def test_home_root_is_first_configured_root(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw"), ("shared", "r")]})
    assert permissions.home_root("alice") == "alice"


def test_home_root_none_without_permissions_or_username(monkeypatch):
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", False)
    assert permissions.home_root("alice") is None
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    assert permissions.home_root(None) is None


def test_scope_path_prefixes_inaccessible_path_under_home_root(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    assert permissions.scope_path("alice", "note.md", frozenset("w")) == "alice/note.md"
    assert permissions.scope_path("alice", "", frozenset("r")) == "alice"


def test_scope_path_leaves_already_accessible_path_unchanged(monkeypatch):
    """A path already valid as given -- the user's own root, or something
    shared with them under a different prefix -- must never be double-prefixed."""
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    permissions.grant_share(granter="bob", subject="alice", prefix="bob-shared", bits=frozenset("r"))

    assert permissions.scope_path("alice", "alice/note.md", frozenset("w")) == "alice/note.md"
    assert permissions.scope_path("alice", "bob-shared/x.md", frozenset("r")) == "bob-shared/x.md"


def test_scope_path_gives_up_honestly_when_home_prefix_still_lacks_bits(monkeypatch):
    """If prefixing with home still doesn't grant `need` (e.g. a read-only
    home but a write was requested), return the path unchanged so the normal
    enforcement path raises its own honest denial -- never mask one denial
    reason with a different, confusing one."""
    _enable(monkeypatch, user_roots={"alice": [("alice", "r")]})
    assert permissions.scope_path("alice", "note.md", frozenset("w")) == "note.md"


def test_scope_path_noop_when_permissions_disabled(monkeypatch):
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", False)
    assert permissions.scope_path("alice", "note.md", frozenset("w")) == "note.md"


# --- integration: a bare filename actually lands in the user's own root ----

def test_write_file_auto_scopes_into_users_home_root(monkeypatch, vault_dir):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    with _as_user("alice"):
        write_file_atomic("note.md", "hello from alice")
        content, _ = read_file("note.md")
    assert content == "hello from alice"
    assert (vault_dir / "alice" / "note.md").read_text() == "hello from alice"
    assert not (vault_dir / "note.md").exists()


def test_write_file_does_not_double_prefix_an_already_rooted_path(monkeypatch, vault_dir):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    with _as_user("alice"):
        write_file_atomic("alice/note.md", "hello")
    assert (vault_dir / "alice" / "note.md").read_text() == "hello"
    assert not (vault_dir / "alice" / "alice" / "note.md").exists()


def test_write_file_auto_scope_never_escapes_into_another_users_real_root(monkeypatch, vault_dir):
    """A path that happens to start with another user's root name, but was
    never shared, gets nested under the WRITER's own root (a subfolder that
    merely happens to be named "bob") -- it must never actually reach bob's
    real files, since scope_path only ever prepends the caller's own home,
    so the rewritten candidate is always confined under that home."""
    (vault_dir / "bob").mkdir()
    (vault_dir / "bob" / "secret.md").write_text("bob's real secret")
    _enable(monkeypatch, user_roots={
        "alice": [("alice", "rw")],
        "bob": [("bob", "rw")],
    })
    with _as_user("alice"):
        write_file_atomic("bob/secret.md", "alice's note, unrelated to bob's file")
        content, _ = read_file("bob/secret.md")
    assert content == "alice's note, unrelated to bob's file"
    # Landed under alice's own root as a nested "bob" folder, not bob's real one.
    assert (vault_dir / "alice" / "bob" / "secret.md").read_text() == "alice's note, unrelated to bob's file"
    assert (vault_dir / "bob" / "secret.md").read_text() == "bob's real secret"


# --- vault_share: the grantor's own path also gets auto-scoped -------------

def test_vault_share_auto_scopes_under_grantors_home(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    monkeypatch.setattr(config, "VAULT_OAUTH_USERS", {"alice": "x", "bob": "y"})
    with _as_user("alice"):
        shared = json.loads(vault_share("Recipes", "bob", "r"))
    assert shared["path"] == "alice/Recipes"
    assert permissions.can_read("bob", "alice/Recipes/pasta.md")


def test_vault_unshare_finds_share_via_home_prefix_fallback(monkeypatch):
    _enable(monkeypatch, user_roots={"alice": [("alice", "rw")]})
    monkeypatch.setattr(config, "VAULT_OAUTH_USERS", {"alice": "x", "bob": "y"})
    with _as_user("alice"):
        json.loads(vault_share("Recipes", "bob", "r"))
        result = json.loads(vault_unshare("Recipes", "bob"))
    assert result["revoked"] is True
    assert result["path"] == "alice/Recipes"
    assert permissions.find_share(subject="bob", prefix="alice/Recipes") is None
