"""Daily-note convenience tools.

Resolve, read, and append to a date-stamped daily note. The path is built from
the server's local date and three config knobs:

- ``VAULT_DAILY_NOTES_FOLDER``   directory for daily notes ("" = vault root)
- ``VAULT_DAILY_NOTES_FORMAT``   strftime pattern for the filename (default %Y-%m-%d)
- ``VAULT_DAILY_NOTES_TEMPLATE`` strftime template prepended when the note is first created

Pure filesystem: no plugin, no network. Writes go through the existing
``vault_append`` path (atomic write); paths go through ``resolve_vault_path``.

VAULT_DAILY_NOTES_FOLDER is a single, global setting -- not per-user -- so
with permissions enabled it's transparently rescoped under the *current*
user's own root the same way any other path is (permissions.scope_path),
rather than each person needing their own folder configured. This is
computed once per call, up front, so the path reported back in every
response here is the one actually read/written, not the raw unscoped one.
"""

import json
import logging
from datetime import datetime
from pathlib import PurePosixPath

from .. import config, permissions
from ..context import current_request_context
from ..serialization import dumps
from ..vault import read_file, resolve_vault_path
from .write import vault_append

logger = logging.getLogger(__name__)


def _today():
    """Return the server's current local date."""
    return datetime.now().date()


def _daily_note_path(for_date) -> str:
    """Build the configured daily-note path for a date."""
    filename = for_date.strftime(config.VAULT_DAILY_NOTES_FORMAT)
    if not filename.lower().endswith((".md", ".markdown")):
        filename = f"{filename}.md"
    folder = config.VAULT_DAILY_NOTES_FOLDER.strip().strip("/\\")
    if folder:
        return str(PurePosixPath(folder) / filename)
    return filename


def _scoped_daily_note_path(for_date, need: frozenset) -> str:
    """The daily-note path for `for_date`, transparently rescoped under the
    current user's own root when the configured (global) folder isn't
    accessible to them as-is -- see module docstring."""
    path = _daily_note_path(for_date)
    username = current_request_context().get("username")
    return permissions.scope_path(username, path, need)


def _initial_content(content: str, for_date) -> str:
    """Template (if any) prepended to the first content written to a new note."""
    template = for_date.strftime(config.VAULT_DAILY_NOTES_TEMPLATE)
    if not template:
        return content
    if content and not template.endswith("\n"):
        return f"{template}\n{content}"
    return f"{template}{content}"


def vault_daily_note_path() -> str:
    """Return today's daily-note path using the server's local date."""
    day = _today()
    try:
        path = _scoped_daily_note_path(day, frozenset("r"))
        resolve_vault_path(path)
        return dumps({
            "path": path,
            "date": day.isoformat(),
            "folder": config.VAULT_DAILY_NOTES_FOLDER,
            "format": config.VAULT_DAILY_NOTES_FORMAT,
        })
    except ValueError as e:
        return dumps({"error": str(e)})
    except Exception as e:
        logger.error(f"vault_daily_note_path error: {e}")
        return dumps({"error": str(e)})


def vault_daily_note_read() -> str:
    """Read today's daily note. Returns an error payload when it does not exist
    (does not create it)."""
    day = _today()
    path = _scoped_daily_note_path(day, frozenset("r"))
    try:
        content, metadata = read_file(path)
        return dumps({"path": path, "date": day.isoformat(), "content": content, "metadata": metadata})
    except FileNotFoundError:
        return dumps({"error": f"Daily note not found: {path}", "path": path, "date": day.isoformat()})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_daily_note_read error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


def vault_daily_note_append(content: str) -> str:
    """Append to today's daily note, creating it (with the template) when missing."""
    day = _today()
    path = _scoped_daily_note_path(day, frozenset("w"))
    try:
        try:
            read_file(path)
            created = False
            payload = content
        except FileNotFoundError:
            created = True
            payload = _initial_content(content, day)

        result = json.loads(vault_append(path, payload))
        if "error" not in result:
            result["date"] = day.isoformat()
            result["daily_note"] = True
            result["created"] = created
        return dumps(result)
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_daily_note_append error for {path}: {e}")
        return dumps({"error": str(e), "path": path})
