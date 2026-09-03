"""Tests for environment-driven configuration (VAULT_MCP_ALLOWED_HOSTS,
VAULT_USER_<GROUP>_* per-user credential triples)."""

import importlib
import os

import pytest

import obsidian_vault_mcp.config as config_module


@pytest.fixture(autouse=True)
def _restore_config(monkeypatch):
    """Reload config after each test so the module-level parse doesn't leak.

    Must explicitly delenv here rather than rely on monkeypatch's own
    auto-revert-on-teardown: fixture teardown order is reverse-of-setup, and this
    fixture requests `monkeypatch` as a dependency, so `monkeypatch` is set up
    *before* this fixture and therefore torn down (auto-reverting env) *after* this
    fixture's own post-yield code already ran. Reloading here without first
    explicitly clearing would reload against still-dirty env and leak this test's
    values into every test that runs afterward for the rest of the session --
    exactly what happened before this comment existed (VAULT_USER_BROKEN_* leaking
    into unrelated test_extensions.py failures).
    """
    yield
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    for key in list(os.environ):
        if key.startswith("VAULT_USER_"):
            monkeypatch.delenv(key, raising=False)
    importlib.reload(config_module)


def test_allowed_hosts_defaults_empty(monkeypatch):
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == []


def test_allowed_hosts_parsed_stripped_and_compacted(monkeypatch):
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "vault-mcp.example.com, second.example.com ,")
    cfg = importlib.reload(config_module)
    # Whitespace trimmed; empty fragments (trailing comma) dropped.
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == ["vault-mcp.example.com", "second.example.com"]


def test_server_appends_to_loopback_defaults(monkeypatch):
    """server.py must APPEND operator hosts to loopback, never replace them."""
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "vault-mcp.example.com")
    importlib.reload(config_module)
    server_module = importlib.import_module("obsidian_vault_mcp.server")
    importlib.reload(server_module)
    try:
        hosts = server_module.mcp.settings.transport_security.allowed_hosts
        assert "127.0.0.1:*" in hosts
        assert "localhost:*" in hosts
        assert "[::1]:*" in hosts
        assert "vault-mcp.example.com" in hosts
    finally:
        # Restore server module to ambient env so later test files are unaffected.
        monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
        importlib.reload(config_module)
        importlib.reload(server_module)


# --- VAULT_USER_<GROUP>_* per-user credential triples ---------------------------
#
# Exercises _load_users_from_env() itself, not just the resulting dicts (every
# other test file monkeypatches config.VAULT_OAUTH_USERS/VAULT_MCP_TOKENS directly,
# which never runs this parsing at all).

def _clear_user_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("VAULT_USER_"):
            monkeypatch.delenv(key, raising=False)


def test_no_user_env_vars_yields_empty_config(monkeypatch):
    _clear_user_env(monkeypatch)
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_OAUTH_USERS == {}
    assert cfg.VAULT_MCP_TOKENS == {}
    assert cfg._INCOMPLETE_USER_GROUPS == []


def test_single_complete_triple(monkeypatch):
    _clear_user_env(monkeypatch)
    monkeypatch.setenv("VAULT_USER_ALICE_USERNAME", "alice")
    monkeypatch.setenv("VAULT_USER_ALICE_PASSWORD", "hunter2")
    monkeypatch.setenv("VAULT_USER_ALICE_TOKEN", "alice-token")
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_OAUTH_USERS == {"alice": "hunter2"}
    assert cfg.VAULT_MCP_TOKENS == {"alice": "alice-token"}
    assert cfg._INCOMPLETE_USER_GROUPS == []


def test_multiple_users_independent_groups(monkeypatch):
    """Two people's env vars, from what would be two separate Kubernetes Secrets --
    confirms one person's credentials never leak into or depend on another's."""
    _clear_user_env(monkeypatch)
    monkeypatch.setenv("VAULT_USER_ALICE_USERNAME", "alice")
    monkeypatch.setenv("VAULT_USER_ALICE_PASSWORD", "hunter2")
    monkeypatch.setenv("VAULT_USER_ALICE_TOKEN", "alice-token")
    monkeypatch.setenv("VAULT_USER_BOB_USERNAME", "bob")
    monkeypatch.setenv("VAULT_USER_BOB_PASSWORD", "correct-horse")
    monkeypatch.setenv("VAULT_USER_BOB_TOKEN", "bob-token")
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_OAUTH_USERS == {"alice": "hunter2", "bob": "correct-horse"}
    assert cfg.VAULT_MCP_TOKENS == {"alice": "alice-token", "bob": "bob-token"}
    assert cfg._INCOMPLETE_USER_GROUPS == []


def test_incomplete_triple_excluded_and_flagged(monkeypatch):
    """A username with no matching password/token (e.g. a typo'd Secret key) must
    not silently end up in either dict -- and must be named so validate_config()
    can fail closed instead of that person's login just quietly not working."""
    _clear_user_env(monkeypatch)
    monkeypatch.setenv("VAULT_USER_ALICE_USERNAME", "alice")
    monkeypatch.setenv("VAULT_USER_ALICE_PASSWORD", "hunter2")
    monkeypatch.setenv("VAULT_USER_ALICE_TOKEN", "alice-token")
    monkeypatch.setenv("VAULT_USER_BROKEN_USERNAME", "carol")
    # no VAULT_USER_BROKEN_PASSWORD / _TOKEN set
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_OAUTH_USERS == {"alice": "hunter2"}
    assert cfg.VAULT_MCP_TOKENS == {"alice": "alice-token"}
    assert cfg._INCOMPLETE_USER_GROUPS == ["BROKEN"]

    with pytest.raises(ValueError, match="BROKEN"):
        cfg.validate_config()
