"""Append-only JSON-lines audit log for vault mutations.

When VAULT_AUDIT_LOG_PATH is set, every vault mutation appends one JSON record to that
file: a UTC timestamp, a SHA-256 hash of the bearer token (never the token itself), the
username that token belongs to (see config.VAULT_MCP_TOKENS), the operation, the target
path, and the size + checksum of the target before and after the change. Read/search
operations are logged too when VAULT_AUDIT_LOG_INCLUDE_READS is on.

Auditing is off unless a log path is configured. At startup the path is validated as
writable AND rejected if it resolves inside the vault (where the vault tools could rewrite
it), so a misconfigured path fails the server closed. At runtime the log is best-effort:
a failure to write a record is logged but never alters the tool result -- the audit trail
must not be able to break a write.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .context import current_request_context
from .serialization import dumps
from .vault import resolve_vault_path

logger = logging.getLogger(__name__)

# Operations that change the vault. Always audited when a log path is configured.
MUTATION_OPERATIONS = {
    "vault_write",
    "vault_edit",
    "vault_append",
    "vault_batch_frontmatter_update",
    "vault_move",
    "vault_delete",
    "vault_canvas_add_node",
    "vault_canvas_add_edge",
    "vault_daily_note_append",
}

# Read/search operations. Audited only when VAULT_AUDIT_LOG_INCLUDE_READS is enabled.
READ_OPERATIONS = {
    "vault_read",
    "vault_batch_read",
    "vault_search",
    "vault_search_frontmatter",
    "vault_list",
    "vault_canvas_read",
    "vault_daily_note_read",
}

# Mutations whose result reports per-file outcomes; audited one record per file.
BATCH_OPERATIONS = {"vault_batch_frontmatter_update"}

# Sharing/unsharing a vault path is security-relevant even though it doesn't touch
# file content -- always audited, same as MUTATION_OPERATIONS, never gated behind
# VAULT_AUDIT_LOG_INCLUDE_READS.
SHARE_OPERATIONS = {"vault_share", "vault_unshare"}


def audit_enabled() -> bool:
    """True when append-only audit logging is configured."""
    return bool(config.VAULT_AUDIT_LOG_PATH)


def read_audit_enabled() -> bool:
    """True when read/search operations should also be audited."""
    return audit_enabled() and bool(config.VAULT_AUDIT_LOG_INCLUDE_READS)


def should_audit_operation(operation: str) -> bool:
    """True when this operation should emit a record under the current config.

    False whenever auditing is off, so the wrapper is a true passthrough (no snapshot
    work) on the default path.
    """
    if not audit_enabled():
        return False
    return operation in MUTATION_OPERATIONS or operation in SHARE_OPERATIONS or (
        operation in READ_OPERATIONS and read_audit_enabled()
    )


def audit_log_path() -> Path:
    return Path(config.VAULT_AUDIT_LOG_PATH).expanduser()


def audit_path_writable(path: Path | None = None) -> bool:
    """True when the audit log can be written (creating intermediate dirs if needed).

    An existing log must be a writable file. Otherwise the log is creatable when the
    nearest existing ancestor is a writable directory -- write_audit_record mkdirs the
    intermediate dirs. A path whose parent is a regular file is rejected.
    """
    path = path or audit_log_path()
    try:
        if path.exists():
            return path.is_file() and os.access(path, os.W_OK)
        ancestor = path.parent
        while not ancestor.exists():
            if ancestor.parent == ancestor:
                return False
            ancestor = ancestor.parent
        return ancestor.is_dir() and os.access(ancestor, os.W_OK)
    except OSError:
        return False


def audit_path_inside_vault() -> bool:
    """True when the configured audit log resolves inside the vault.

    A same-vault log is just another file the vault tools can reach: resolve_vault_path
    only blocks traversal and dotfiles, so an authenticated caller could overwrite it via
    vault_write or relocate it via vault_delete, defeating the append-only integrity
    premise. Such a path is rejected at startup (see server.main).
    """
    if not audit_enabled():
        return False
    try:
        log = audit_log_path().resolve()
        vault = config.VAULT_PATH.resolve()
    except OSError:
        return False
    return log == vault or vault in log.parents


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_value(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_path(path: Any) -> dict[str, Any]:
    """Capture (size, checksum) for a vault-relative path; nulls when absent or invalid.

    Routes through resolve_vault_path so a path that escapes the vault is treated as
    absent rather than read.
    """
    empty: dict[str, Any] = {"size": None, "checksum": None}
    if not isinstance(path, str) or not path:
        return empty
    try:
        resolved = resolve_vault_path(path)
    except ValueError:
        return empty
    if not resolved.is_file():
        return empty
    return {"size": resolved.stat().st_size, "checksum": _sha256_file(resolved)}


def before_target_path(operation: str, context: dict[str, Any]) -> Any:
    """The path to snapshot before a mutation runs."""
    if operation == "vault_move":
        return context.get("source")
    return context.get("path") or context.get("source")


def infer_target_path(operation: str, context: dict[str, Any], result: dict[str, Any] | None = None) -> Any:
    """Best-effort target path from the call context and the parsed result payload."""
    result = result or {}
    if operation == "vault_move":
        return result.get("destination") or context.get("destination")
    if operation == "vault_batch_frontmatter_update":
        results = result.get("results")
        if isinstance(results, list):
            paths = [item.get("path") for item in results if isinstance(item, dict) and item.get("path")]
            if paths:
                return paths
    return result.get("path") or context.get("path") or context.get("source")


def build_audit_record(
    *,
    operation: str,
    target_path: Any,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    operation_status: str = "success",
    error: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one normalized audit record from the current request context.

    `details` carries operation-specific fields that don't fit the generic
    before/after-checksum shape (e.g. the grantor/subject/bits of a share
    operation, which has no file content to snapshot).
    """
    ctx = current_request_context()
    before = before or {"size": None, "checksum": None}
    after = after or {"size": None, "checksum": None}
    return {
        "timestamp": _now_utc().isoformat(),
        "token_id_hash": _hash_value(ctx.get("principal")),
        "username": ctx.get("username"),
        "client_id": ctx.get("client"),
        "operation": operation,
        "target_path": target_path,
        "size_before": before.get("size"),
        "size_after": after.get("size"),
        "checksum_before": before.get("checksum"),
        "checksum_after": after.get("checksum"),
        "request_id": ctx.get("request_id") or uuid.uuid4().hex,
        "operation_status": operation_status,
        "error": error,
        "details": details,
    }


def write_denial_record(
    path: str, need: str, effective_bits: str, *, operation: str | None = None
) -> None:
    """Best-effort audit record for a permission denial.

    Called from permissions.enforce() on every denied request, independent of
    VAULT_AUDIT_LOG_INCLUDE_READS -- a denial is a security-relevant event in its
    own right, not a read, so it's not gated behind the read-audit toggle. Like
    write_audit_record, a logging failure here must never surface to the caller
    or affect the PermissionDenied/FileNotFoundError already being raised by
    enforce().
    """
    if not audit_enabled():
        return
    try:
        record = build_audit_record(
            operation=operation or "permission_check",
            target_path=path,
            operation_status="denied",
            error="Permission denied",
            details={"need": need, "effective_bits": effective_bits},
        )
        write_audit_record(record)
    except Exception as exc:
        logger.error("Audit denial record failed: %s", exc)


def write_audit_record(record: dict[str, Any]) -> bool:
    """Append one JSON record. A write failure is logged and swallowed (best-effort)."""
    if not audit_enabled():
        return False
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        line = dumps(record, sort_keys=True) + "\n"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return True
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)
        return False
