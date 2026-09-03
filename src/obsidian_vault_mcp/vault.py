"""Core filesystem operations for the Obsidian vault."""

import fnmatch
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import config, context, permissions


def resolve_vault_path(relative_path: str, *, require: str | None = None) -> Path:
    """Resolve a relative path against the vault root, with safety checks.

    Raises ValueError if the path escapes the vault, contains null bytes,
    or touches dotfile/dot-directory components.

    require=None (the default) performs ONLY the path-safety checks above --
    this is the mode audit.snapshot_path() uses, since it resolves paths as the
    server itself (checksumming before/after a mutation), not as the requesting
    user, and must never be denied by that user's own permissions. Pass
    require="r" or require="w" to additionally enforce the current request's
    permissions (permissions.py) for that path; see permissions.py's module
    docstring for what "current request" means outside a real request (nothing
    is granted).
    """
    if "\x00" in relative_path:
        raise ValueError("Path contains null bytes")

    # Check for dot-prefixed components (blocks .obsidian, .trash, dotfiles)
    parts = Path(relative_path).parts
    for part in parts:
        if part.startswith("."):
            raise ValueError(
                f"Path component '{part}' starts with '.'; dotfiles and hidden directories are not allowed"
            )

    resolved = (config.VAULT_PATH / relative_path).resolve()
    vault_root = config.VAULT_PATH.resolve()

    if not str(resolved).startswith(str(vault_root) + os.sep) and resolved != vault_root:
        raise ValueError("Path resolves outside the vault root")

    if require is not None:
        permissions.enforce(relative_path, require)

    return resolved


def _iso_timestamp(ts: float) -> str:
    """Convert a Unix timestamp to an ISO 8601 string in UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def read_file(relative_path: str) -> tuple[str, dict]:
    """Read a file and return (content, metadata).

    Metadata keys: size (int), modified (ISO str), created (ISO str).
    """
    path = resolve_vault_path(relative_path, require="r")

    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {relative_path}")

    stat = path.stat()
    content = path.read_text(encoding="utf-8")

    metadata = {
        "size": stat.st_size,
        "modified": _iso_timestamp(stat.st_mtime),
        "created": _iso_timestamp(stat.st_birthtime if hasattr(stat, "st_birthtime") else stat.st_ctime),
    }

    return content, metadata


def write_file_atomic(
    relative_path: str, content: str, create_dirs: bool = True
) -> tuple[bool, int]:
    """Write content to a file atomically.

    Returns (is_new_file, bytes_written). Writes to a tempfile in the same
    directory then replaces the target, so readers never see a partial write.
    """
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(
            f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes"
        )

    path = resolve_vault_path(relative_path, require="w")
    is_new = not path.exists()

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then atomic-replace.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
        os.replace(tmp_path, path)
    except BaseException:
        # Clean up the temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new, len(encoded)


def write_bytes_atomic(
    relative_path: str, content: bytes, create_dirs: bool = True, overwrite: bool = True
) -> tuple[bool, int]:
    """Write raw bytes to a file atomically.

    The binary counterpart of write_file_atomic: writes to a tempfile in the same
    directory then puts it in place, so readers never see a partial write.
    Returns (is_new_file, bytes_written).

    With overwrite=False the placement is a true no-clobber: it uses os.link, which fails
    atomically if the target already exists, closing the check-then-write race that a plain
    exists()-then-os.replace would leave open. With overwrite=True it os.replace()s.
    """
    if len(content) > config.MAX_BINARY_SIZE:
        raise ValueError(
            f"Content size {len(content)} bytes exceeds limit of {config.MAX_BINARY_SIZE} bytes"
        )

    path = resolve_vault_path(relative_path, require="w")
    is_new = not path.exists()

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then put it in place atomically.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        if overwrite:
            os.replace(tmp_path, path)
        else:
            # Atomic create: os.link fails if the target exists (no clobber, no race).
            try:
                os.link(tmp_path, path)
            except FileExistsError:
                raise FileExistsError(f"File already exists: {relative_path}")
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            is_new = True
    except BaseException:
        # Clean up the temp file on any failure (os.replace consumes it on success).
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new, len(content)


def move_path(
    source: str, destination: str, create_dirs: bool = True
) -> bool:
    """Move a file or directory from source to destination.

    Both paths are relative to the vault root. Raises if the destination
    already exists.
    """
    # A move deletes the source, so it needs "w" there too -- read alone isn't
    # enough to authorize removing it, even though move_path itself never reads
    # the source's content.
    src = resolve_vault_path(source, require="w")
    dst = resolve_vault_path(destination, require="w")

    if not src.exists():
        raise FileNotFoundError(f"Source does not exist: {source}")

    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")

    if create_dirs:
        dst.parent.mkdir(parents=True, exist_ok=True)

    shutil.move(str(src), str(dst))
    return True


def delete_path(relative_path: str) -> bool:
    """Soft-delete by moving the path into .trash/ at the vault root.

    Refuses to delete non-empty directories.
    """
    path = resolve_vault_path(relative_path, require="w")

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {relative_path}")

    if path.is_dir() and any(path.iterdir()):
        raise ValueError(f"Refusing to delete non-empty directory: {relative_path}")

    trash_dir = config.VAULT_PATH.resolve() / ".trash"
    trash_dir.mkdir(exist_ok=True)

    dest = trash_dir / path.name

    # Avoid collisions in .trash by appending a timestamp
    if dest.exists():
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        dest = trash_dir / f"{path.stem}_{ts}{path.suffix}"

    shutil.move(str(path), str(dest))
    return True


def list_directory(
    relative_path: str,
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> list[dict]:
    """List directory contents recursively up to *depth* levels.

    Returns a list of dicts with keys: name, path (relative to vault),
    type ("file" or "dir"), size, modified.
    """
    depth = min(depth, config.MAX_LIST_DEPTH)

    # Precondition, not a per-entry check: without at least one readable path at
    # or under relative_path, this call has nothing to show -- deny it outright
    # rather than silently returning an empty list, which would be indistinguishable
    # from "this directory happens to be empty".
    username = context.current_request_context().get("username")
    if not permissions.has_readable_descendant(username, relative_path):
        raise permissions.PermissionDenied("Permission denied")

    root = resolve_vault_path(relative_path)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {relative_path}")

    vault_root = config.VAULT_PATH.resolve()
    results: list[dict] = []

    def _walk(dir_path: Path, current_depth: int) -> None:
        if current_depth > depth:
            return

        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: p.name.lower())
        except PermissionError:
            return

        for entry in entries:
            # Skip excluded directories at every level
            if entry.name in config.EXCLUDED_DIRS:
                continue

            is_dir = entry.is_dir()
            rel = str(entry.relative_to(vault_root))

            # Permission gate, computed once per entry regardless of the
            # include_dirs/include_files/pattern filters below: a directory this
            # user can't read AND has no readable descendant under is fully
            # hidden -- no row, no recursion, so its very existence doesn't leak
            # through a listing the way it would if we merely skipped emitting a
            # row but still walked into it. A file this user can't read is
            # likewise invisible, not merely un-openable.
            readable = permissions.can_read(username, rel)
            if is_dir:
                can_descend = readable or permissions.has_readable_descendant(username, rel)
                if not can_descend:
                    continue
            elif not readable:
                continue

            if is_dir and not include_dirs:
                # Still recurse even if we're not listing dirs
                _walk(entry, current_depth + 1)
                continue

            if not is_dir and not include_files:
                continue

            # Apply glob pattern filter
            if pattern and not fnmatch.fnmatch(entry.name, pattern):
                if is_dir:
                    _walk(entry, current_depth + 1)
                continue

            # A directory the user can descend into (readable descendant below)
            # but can't itself read gets recursed into with no row emitted for
            # it -- this is the case a plain "readable" gate would miss.
            if is_dir and not readable:
                _walk(entry, current_depth + 1)
                continue

            try:
                stat = entry.stat()
            except OSError:
                continue

            results.append({
                "name": entry.name,
                "path": rel,
                "type": "dir" if is_dir else "file",
                "size": stat.st_size,
                "modified": _iso_timestamp(stat.st_mtime),
            })

            if is_dir:
                _walk(entry, current_depth + 1)

    _walk(root, 1)
    return results
