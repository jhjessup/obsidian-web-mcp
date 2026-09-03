"""Filesystem-like, per-user path permissions, with runtime share/unshare.

Two kinds of grant feed the same model:
  - config roots (VAULT_USER_<GROUP>_ROOTS / VAULT_DEFAULT_ROOTS): operator-set,
    immutable at runtime, loaded once into config.py at import.
  - shares: runtime-mutable grants one user gives another via the vault_share /
    vault_unshare tools, persisted to disk (see _load_shares/_save_shares, modeled
    directly on oauth.py's _load_clients/_save_clients).

VAULT_PERMISSIONS_ENABLED gates all of this off by default: with it unset, every
check in this module is a no-op that allows everything, so landing this feature
doesn't retroactively lock out an existing single-vault-for-everyone deployment.

The single entry point every tool should use is `enforce()`. `can_read()`,
`has_readable_descendant()`, and `readable_roots()` exist for the tools that need
to filter or scope a *set* of paths (vault_list, vault_search, ...) rather than
gate one path.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Literal

from . import config
from .context import current_request_context

logger = logging.getLogger(__name__)

Bits = frozenset[str]  # subset of {"r", "w"}

_VALID_BITS = {"", "r", "rw"}
_DOT_SEGMENT_RE = re.compile(r"^\.")


class PermissionDenied(ValueError):
    """Raised by enforce(). Subclasses ValueError so every existing tool's
    `except ValueError as e: return {"error": str(e)}` handles it with no change."""


@dataclass(frozen=True)
class Entry:
    prefix: str  # normalized, "" means vault root
    bits: Bits
    source: Literal["config", "grant"]
    grant_id: str | None = None
    subject: str | None = None
    grantor: str | None = None
    derived_from: str | None = None
    created_at: str | None = None


def bits_from_str(raw: str) -> Bits:
    """Parse "", "r", or "rw" into a frozenset. Raises ValueError on anything else --
    callers decide whether that's a hard failure (share tools) or a collected,
    deferred one (config parsing, matching this codebase's fail-closed-at-
    validate_config-time convention rather than raising at import)."""
    raw = raw.strip().lower()
    if raw not in _VALID_BITS:
        raise ValueError(f"invalid permission bits {raw!r}; must be one of '', 'r', 'rw'")
    return frozenset(raw)


def normalize_prefix(raw: str) -> str:
    """Vault-relative POSIX form, or raise ValueError.

    Mirrors vault.resolve_vault_path's safety rules (null bytes, traversal,
    dotfile/dot-directory segments) so a grant can never be crafted to name
    something resolve_vault_path would itself refuse to touch (.obsidian, .trash,
    ../escapes) -- there's no reason a share should be able to express a path the
    rest of the server treats as forbidden.
    """
    if "\x00" in raw:
        raise ValueError("Path contains null bytes")
    raw = raw.replace("\\", "/").strip("/")
    if raw in ("", "."):
        return ""
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    for part in parts:
        if part == "..":
            raise ValueError("Path must not contain '..' segments")
        if _DOT_SEGMENT_RE.match(part):
            raise ValueError(
                f"Path component '{part}' starts with '.'; dotfiles and hidden "
                "directories are not allowed"
            )
    return "/".join(parts)


def _prefix_matches(prefix: str, path: str) -> bool:
    if prefix == "":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _entries_for(username: str) -> list[Entry]:
    """Config roots + runtime grants for one user.

    config.VAULT_USER_ROOTS holds raw (prefix, bits_str) string tuples rather than
    Entry objects -- config.py can't import this module (it imports config), so
    normalization and Entry construction happens here, at lookup time, instead of
    at config-parse time. config._validate_user_roots() already calls
    normalize_prefix/bits_from_str (via a function-local import of this module,
    the same cycle-breaking technique config.py already uses elsewhere) to fail
    startup closed on a bad root spec -- the try/except here is defense in depth
    for the case that validation was somehow bypassed, not the primary guard.
    """
    entries = []
    for prefix, bits_str in config.VAULT_USER_ROOTS.get(username, ()):
        try:
            entries.append(Entry(
                prefix=normalize_prefix(prefix), bits=bits_from_str(bits_str),
                source="config", subject=username,
            ))
        except ValueError:
            logger.error(
                "Skipping malformed config root %r:%r for user %r (should have been "
                "caught by validate_config)", prefix, bits_str, username,
            )
    entries.extend(_grants_for_subject(username))
    return entries


def effective_bits(username: str | None, rel_path: str) -> Bits:
    """The union of bits from every matching entry at the *longest* matching
    prefix. Unmatched -> empty set -> default deny. An entry with empty bits at a
    prefix acts as a deny carve-out, but only if that prefix is strictly longer
    than any competing grant -- equal-length ties union permissively. This is the
    one non-obvious rule in this module; get it wrong and a carve-out silently
    stops carving.
    """
    if not config.VAULT_PERMISSIONS_ENABLED:
        return frozenset({"r", "w"})
    if not username:
        return frozenset()

    try:
        path = normalize_prefix(rel_path)
    except ValueError:
        return frozenset()

    best_len = -1
    best_bits: set[str] = set()
    for entry in _entries_for(username):
        if not _prefix_matches(entry.prefix, path):
            continue
        plen = len(entry.prefix)
        if plen > best_len:
            best_len = plen
            best_bits = set(entry.bits)
        elif plen == best_len:
            best_bits |= entry.bits

    return frozenset(best_bits)


def can_read(username: str | None, rel_path: str) -> bool:
    return "r" in effective_bits(username, rel_path)


def can_write(username: str | None, rel_path: str) -> bool:
    return "w" in effective_bits(username, rel_path)


def has_readable_descendant(username: str | None, dir_prefix: str) -> bool:
    """True if some readable entry is at, under, or an ancestor of dir_prefix.

    This is what lets a user granted only a deep path (e.g. "Projects/acme/x.md")
    still call vault_list("") without error, and lets list_directory's walker
    descend into intermediate directories it won't itself emit a row for.
    """
    if not config.VAULT_PERMISSIONS_ENABLED:
        return True
    if not username:
        return False

    try:
        dir_prefix = normalize_prefix(dir_prefix)
    except ValueError:
        return False

    for entry in _entries_for(username):
        if "r" not in entry.bits:
            continue
        if _prefix_matches(entry.prefix, dir_prefix) or _prefix_matches(dir_prefix, entry.prefix):
            return True
    return False


def readable_roots(username: str | None) -> list[str]:
    """Minimal set of prefixes with "r", collapsing any prefix subsumed by a
    shorter one already in the set. Used to scope vault_search to only the
    directories a user can actually see, rather than searching everything and
    hoping the post-filter catches it (see search.py for why that's not enough
    on its own: it can silently exhaust the result cap on denied matches)."""
    if not config.VAULT_PERMISSIONS_ENABLED:
        return [""]
    if not username:
        return []

    prefixes = sorted({e.prefix for e in _entries_for(username) if "r" in e.bits}, key=len)
    roots: list[str] = []
    for p in prefixes:
        if any(_prefix_matches(r, p) for r in roots):
            continue
        roots.append(p)
    return roots


def home_root(username: str | None) -> str | None:
    """A user's own root -- the first entry of their VAULT_USER_<GROUP>_ROOTS --
    or None if they have no configured root (or permissions are disabled). This
    is the prefix scope_path() falls back to for an otherwise-inaccessible path,
    so a user never has to know or type their own root's name."""
    if not config.VAULT_PERMISSIONS_ENABLED or not username:
        return None
    entries = config.VAULT_USER_ROOTS.get(username) or ()
    if not entries:
        return None
    try:
        return normalize_prefix(entries[0][0])
    except ValueError:
        return None


def scope_path(username: str | None, rel_path: str, need: Bits) -> str:
    """Transparently resolve `rel_path` against the user's own root when the
    path as given isn't already accessible, so "note.md" lands in a user's own
    space without them ever needing to type or know their root's name.

    A path that's already accessible as given -- the user's own root, an
    explicit subpath of it, or something shared with them under a different
    prefix entirely -- is returned unchanged; this only ever adds a prefix, it
    never strips or rewrites an already-valid path, so a shared path is never
    double-prefixed into the wrong place. If prefixing with the home root
    still doesn't grant `need` (e.g. their root is read-only and `need`
    includes write), the original path is returned unchanged so the caller's
    own enforcement produces the normal, honest denial for what the user
    actually typed -- this function only ever helps, it never hides or
    replaces a real permission failure with a different one.

    A no-op (returns rel_path verbatim) when permissions are disabled, there's
    no current user, or rel_path fails to normalize -- in all of those cases
    the caller's own subsequent checks are what should raise, not this.
    """
    if not config.VAULT_PERMISSIONS_ENABLED or not username:
        return rel_path
    try:
        normalized = normalize_prefix(rel_path)
    except ValueError:
        return rel_path

    if need.issubset(effective_bits(username, normalized)):
        return rel_path

    home = home_root(username)
    if home is None:
        return rel_path

    candidate = home if not normalized else f"{home}/{normalized}"
    if need.issubset(effective_bits(username, candidate)):
        return candidate
    return rel_path


def enforce(rel_path: str, need: Literal["r", "w"], *, operation: str | None = None) -> None:
    """Raise PermissionDenied if the current request's user lacks `need` at
    rel_path. Also emits a best-effort audit denial record. No-ops entirely when
    VAULT_PERMISSIONS_ENABLED is unset."""
    if not config.VAULT_PERMISSIONS_ENABLED:
        return

    username = current_request_context().get("username")
    bits = effective_bits(username, rel_path)
    if need in bits:
        return

    # Lazy import: audit imports vault, vault will import this module for
    # enforcement, and audit itself calls resolve_vault_path as the server (not a
    # user) -- a top-level import here would cycle.
    from . import audit

    audit.write_denial_record(rel_path, need, bits, operation=operation)

    if need == "r":
        # Byte-identical to read_file()'s own not-found message. A denied read
        # must be indistinguishable from a missing file -- otherwise a caller
        # that can see error text for many paths at once (vault_batch_read)
        # could use the distinct "Permission denied" string as a per-path
        # existence oracle, learning which denied paths are real files versus
        # genuinely absent ones without ever being granted read access to any
        # of them. Writes have no such concern (see below): a write denial to a
        # nonexistent path isn't leaking whether that path exists, since
        # writing to a nonexistent path is legitimately allowed in the first
        # place.
        raise FileNotFoundError(f"Not a file: {rel_path}")

    raise PermissionDenied("Permission denied")


# --- Runtime share store ----------------------------------------------------
#
# Modeled directly on oauth.py's _load_clients/_save_clients: JSON, atomic
# 0600 writes, best-effort load (never raises -- a corrupt file starts empty
# rather than crashing the server). Guarded by a real lock (not just relying on
# single-threaded access like oauth.py does) because FastMCP dispatches sync
# tools on a threadpool and vault_share/vault_unshare are real concurrent writers.

_grants: dict[str, Entry] = {}
_grants_lock = threading.RLock()


def _grants_for_subject(username: str) -> list[Entry]:
    with _grants_lock:
        return [g for g in _grants.values() if g.subject == username]


def _load_shares() -> None:
    path = config.VAULT_SHARES_PATH
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Share registry unreadable at %s (%s); starting empty", path, e)
        return

    if not isinstance(data, dict) or data.get("version") != 1:
        logger.warning("Share registry at %s has an unrecognized shape; starting empty", path)
        return

    loaded: dict[str, Entry] = {}
    for rec in data.get("grants", []):
        try:
            gid = rec["id"]
            entry = Entry(
                prefix=normalize_prefix(rec["prefix"]),
                bits=bits_from_str(rec["bits"]),
                source="grant",
                grant_id=gid,
                subject=rec["subject"],
                grantor=rec["grantor"],
                derived_from=rec.get("derived_from"),
                created_at=rec.get("created_at"),
            )
        except (KeyError, TypeError, ValueError) as e:
            logger.warning("Dropping malformed share record %r: %s", rec, e)
            continue
        loaded[gid] = entry

    with _grants_lock:
        _grants.clear()
        _grants.update(loaded)
    logger.info("Loaded %d share grant(s) from %s", len(loaded), path)


def _save_shares() -> None:
    path = config.VAULT_SHARES_PATH
    with _grants_lock:
        payload = {
            "version": 1,
            "grants": [
                {
                    "id": g.grant_id,
                    "subject": g.subject,
                    "prefix": g.prefix,
                    "bits": "".join(sorted(g.bits, reverse=True)),  # "rw" not "wr"
                    "grantor": g.grantor,
                    "derived_from": g.derived_from,
                    "created_at": g.created_at,
                }
                for g in _grants.values()
            ],
        }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        logger.error("Could not persist share registry to %s (%s)", path, e)


_load_shares()


# --- Grant mutation, called by tools/sharing.py ------------------------------

def grant_share(
    *, granter: str, subject: str, prefix: str, bits: Bits, derived_from: str | None = None,
) -> Entry:
    """Create or replace the (subject, prefix) grant. Caller (tools/sharing.py) is
    responsible for authorization -- this function only persists."""
    prefix = normalize_prefix(prefix)
    with _grants_lock:
        # Re-sharing the same (subject, prefix) replaces bits rather than stacking
        # a second grant -- idempotent, and avoids the store growing unboundedly
        # from repeated upgrade/downgrade of the same share.
        existing_id = next(
            (gid for gid, g in _grants.items() if g.subject == subject and g.prefix == prefix),
            None,
        )
        gid = existing_id or uuid.uuid4().hex
        entry = Entry(
            prefix=prefix, bits=bits, source="grant", grant_id=gid,
            subject=subject, grantor=granter, derived_from=derived_from,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        )
        _grants[gid] = entry
        _save_shares()
    return entry


def revoke_share(*, prefix: str, subject: str) -> list[Entry]:
    """Remove the exact (subject, prefix) grant and cascade to every grant
    derived from it (BFS over derived_from). Returns every removed entry
    (the direct one first, then cascaded ones) so the caller can report the
    blast radius. Raises KeyError if no such grant exists."""
    prefix = normalize_prefix(prefix)
    with _grants_lock:
        target_id = next(
            (gid for gid, g in _grants.items() if g.subject == subject and g.prefix == prefix),
            None,
        )
        if target_id is None:
            raise KeyError(f"No share found for {subject!r} at {prefix!r}")

        removed = [_grants.pop(target_id)]
        frontier = [target_id]
        while frontier:
            current = frontier.pop()
            children = [gid for gid, g in _grants.items() if g.derived_from == current]
            for gid in children:
                removed.append(_grants.pop(gid))
                frontier.append(gid)

        _save_shares()
    return removed


def find_share(*, subject: str, prefix: str) -> Entry | None:
    prefix = normalize_prefix(prefix)
    with _grants_lock:
        return next(
            (g for g in _grants.values() if g.subject == subject and g.prefix == prefix),
            None,
        )


def list_shares_by_grantor(username: str) -> list[Entry]:
    with _grants_lock:
        return [g for g in _grants.values() if g.grantor == username]


def list_shares_by_subject(username: str) -> list[Entry]:
    return _grants_for_subject(username)
