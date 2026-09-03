"""Test fixtures for the Obsidian vault MCP server."""

import importlib
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    """Create a temporary vault directory with sample files."""
    vault = tmp_path / "test-vault"
    vault.mkdir()

    # test-note.md with frontmatter
    (vault / "test-note.md").write_text(
        "---\nstatus: active\ntype: note\n---\n\nThis is a test note with some content.\n"
    )

    # subfolder/nested-note.md with frontmatter
    subfolder = vault / "subfolder"
    subfolder.mkdir()
    (subfolder / "nested-note.md").write_text(
        "---\nstatus: draft\ntype: client-hub\nclient: TestCorp\n---\n\nNested note content.\n"
    )

    # no-frontmatter.md
    (vault / "no-frontmatter.md").write_text("Just plain text, no frontmatter here.\n")

    # .obsidian/config.json (should be excluded)
    obsidian_dir = vault / ".obsidian"
    obsidian_dir.mkdir()
    (obsidian_dir / "config.json").write_text('{"theme": "dark"}')

    # Set environment variable for config module
    monkeypatch.setenv("VAULT_PATH", str(vault))
    monkeypatch.setenv("VAULT_USER_TESTER_USERNAME", "tester")
    monkeypatch.setenv("VAULT_USER_TESTER_PASSWORD", "test-password")
    monkeypatch.setenv("VAULT_USER_TESTER_TOKEN", "test-token-12345")

    # Actually reload (not just re-import, which is a no-op on an already-imported
    # module) so VAULT_OAUTH_USERS/VAULT_MCP_TOKENS reflect the VAULT_USER_TESTER_*
    # vars just set above -- validate_config() now fails closed on an empty
    # VAULT_OAUTH_USERS (see config._validate_users_have_tokens), and server.serve()
    # calls it, so any test driving serve() needs this fixture to have actually
    # populated a user, not left config's module-level globals at whatever they were
    # when config.py first happened to be imported.
    import obsidian_vault_mcp.config as config
    importlib.reload(config)
    config.VAULT_PATH = Path(str(vault))

    yield vault
