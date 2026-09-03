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
from obsidian_vault_mcp.vault import list_directory


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
