"""Daily-note tools: path resolution, read (no create), append (create+template)."""

import json
from contextlib import contextmanager
from datetime import datetime

from obsidian_vault_mcp import config, context, server
from obsidian_vault_mcp.tools.daily import (
    vault_daily_note_append,
    vault_daily_note_path,
    vault_daily_note_read,
)


@contextmanager
def _as_user(username):
    token = context.set_request_context(
        principal="test-token", request_id="test-request", client=None, username=username,
    )
    try:
        yield
    finally:
        context.reset_request_context(token)


def _set_daily(monkeypatch, folder="", fmt="%Y-%m-%d", template=""):
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FOLDER", folder)
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FORMAT", fmt)
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_TEMPLATE", template)


def test_path_uses_format_and_folder(vault_dir, monkeypatch):
    _set_daily(monkeypatch, folder="journal", fmt="%Y-%m-%d")
    result = json.loads(vault_daily_note_path())
    assert result["path"] == "journal/" + datetime.now().strftime("%Y-%m-%d") + ".md"
    assert result["folder"] == "journal"


def test_read_missing_returns_error_and_does_not_create(vault_dir, monkeypatch):
    _set_daily(monkeypatch)
    result = json.loads(vault_daily_note_read())
    assert "error" in result and "not found" in result["error"].lower()
    assert not (vault_dir / result["path"]).exists()


def test_append_creates_with_template_then_appends(vault_dir, monkeypatch):
    _set_daily(monkeypatch, template="# %Y-%m-%d\n")
    first = json.loads(vault_daily_note_append("first line"))
    assert first["created"] is True
    assert first["daily_note"] is True

    path = json.loads(vault_daily_note_path())["path"]
    body = (vault_dir / path).read_text(encoding="utf-8")
    assert body.startswith("# " + datetime.now().strftime("%Y-%m-%d"))
    assert "first line" in body

    second = json.loads(vault_daily_note_append("second line"))
    assert second["created"] is False
    body2 = (vault_dir / path).read_text(encoding="utf-8")
    assert "first line" in body2 and "second line" in body2


def test_read_after_append_returns_content(vault_dir, monkeypatch):
    _set_daily(monkeypatch)
    vault_daily_note_append("hello daily")
    result = json.loads(vault_daily_note_read())
    assert "error" not in result
    assert "hello daily" in result["content"]


def test_daily_note_auto_scopes_under_users_home_root_when_permissions_enabled(vault_dir, monkeypatch):
    """VAULT_DAILY_NOTES_FOLDER is global (not per-user); with permissions
    enabled and a user confined to their own root, the daily note must still
    land in THEIR space rather than being denied at the (inaccessible) global
    folder -- this was a real gap: enabling permissions broke daily notes for
    every user until path scoping was added."""
    _set_daily(monkeypatch, folder="")  # global folder = vault root
    monkeypatch.setattr(config, "VAULT_PERMISSIONS_ENABLED", True)
    monkeypatch.setattr(config, "VAULT_USER_ROOTS", {"shannon": [("shannon", "rw")]})

    today = datetime.now().strftime("%Y-%m-%d") + ".md"
    with _as_user("shannon"):
        path_result = json.loads(vault_daily_note_path())
        assert path_result["path"] == f"shannon/{today}"

        append_result = json.loads(vault_daily_note_append("shannon's thought"))
        assert "error" not in append_result
        assert append_result["path"] == f"shannon/{today}"

        read_result = json.loads(vault_daily_note_read())
        assert "shannon's thought" in read_result["content"]

    assert (vault_dir / "shannon" / today).exists()
    assert not (vault_dir / today).exists()


def test_tools_registered_and_append_wired(vault_dir, monkeypatch):
    for name in ("vault_daily_note_path", "vault_daily_note_read", "vault_daily_note_append"):
        assert server.mcp._tool_manager.get_tool(name) is not None
    _set_daily(monkeypatch)
    # server wrapper validates input and reaches the helper end to end
    result = json.loads(server.vault_daily_note_append("via wrapper"))
    assert result["created"] is True
    assert "via wrapper" in json.loads(vault_daily_note_read())["content"]
