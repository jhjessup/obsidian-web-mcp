"""Search tools for the Obsidian vault MCP server."""

import fnmatch
import json
import logging
import shutil
import subprocess
from pathlib import Path

import frontmatter

from .. import config, permissions
from ..context import current_request_context
from ..serialization import dumps
from ..vault import resolve_vault_path

logger = logging.getLogger(__name__)

# vault_search over-fetches this multiple of max_results from the underlying
# ripgrep/Python search before permission-filtering, so that denied matches
# don't silently eat into the caller's requested result count -- without this,
# a user with a narrow grant inside a broadly-searched tree could see fewer
# results than max_results even though more real matches exist deeper in
# their own readable area, indistinguishable from "there just aren't more".
_SEARCH_OVERFETCH_FACTOR = 5


def _search_ripgrep(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Search using ripgrep for performance."""
    cmd = [
        "rg",
        "--json",
        f"--max-count={max_results}",
        f"--glob={file_pattern}",
        "-i",
        f"--context={context_lines}",
    ]

    for excluded in config.EXCLUDED_DIRS:
        cmd.append(f"--glob=!{excluded}/")

    # Pass the user-supplied query with `-e` so a value beginning with "-"
    # (e.g. "--pre=/bin/sh", a ripgrep preprocessor flag that executes an
    # arbitrary program per searched file) is parsed as a SEARCH PATTERN, not
    # as a ripgrep option. Appending it bare here was an argv option-injection
    # that allowed remote code execution via the vault_search query argument.
    cmd += ["-e", query, str(search_path)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    matches = []
    current_match = None

    for line in result.stdout.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if data.get("type") == "match":
            match_data = data["data"]
            file_path = match_data["path"]["text"]
            try:
                rel_path = str(Path(file_path).relative_to(config.VAULT_PATH))
            except ValueError:
                continue

            line_number = match_data["line_number"]
            line_text = match_data["lines"]["text"].rstrip("\n")

            matches.append({
                "path": rel_path,
                "line_number": line_number,
                "match_context": line_text,
            })

            if len(matches) >= max_results:
                break

    return matches


def _search_python(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Fallback Python-based search."""
    query_lower = query.lower()
    matches = []

    for file_path in search_path.rglob("*"):
        if not file_path.is_file():
            continue

        if any(part in config.EXCLUDED_DIRS for part in file_path.parts):
            continue

        if not fnmatch.fnmatch(file_path.name, file_pattern):
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        lines = content.splitlines()
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = "\n".join(lines[start:end])

                try:
                    rel_path = str(file_path.relative_to(config.VAULT_PATH))
                except ValueError:
                    continue

                matches.append({
                    "path": rel_path,
                    "line_number": i + 1,
                    "match_context": context,
                })

                if len(matches) >= max_results:
                    return matches

    return matches


def _search_single_file(
    file_path: Path, query: str, max_results: int, context_lines: int
) -> list[dict]:
    """Search one file directly, for a readable root that's a single file rather
    than a directory (permissions.readable_roots() can return either -- a share
    or config root can name an exact file, e.g. one shared note rather than a
    whole folder). rglob-based directory search would never visit such a path on
    its own since it isn't itself a directory to walk."""
    if not file_path.is_file():
        return []
    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError, OSError):
        return []

    try:
        rel_path = str(file_path.relative_to(config.VAULT_PATH))
    except ValueError:
        return []

    query_lower = query.lower()
    lines = content.splitlines()
    matches = []
    for i, line in enumerate(lines):
        if query_lower in line.lower():
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            matches.append({
                "path": rel_path,
                "line_number": i + 1,
                "match_context": "\n".join(lines[start:end]),
            })
            if len(matches) >= max_results:
                break
    return matches


def _get_frontmatter_excerpt(file_path: Path, max_keys: int = 3) -> dict | None:
    """Read frontmatter from a file, returning first N key-value pairs."""
    try:
        content = file_path.read_text(encoding="utf-8")
        post = frontmatter.loads(content)
        if not post.metadata:
            return None
        keys = list(post.metadata.keys())[:max_keys]
        return {k: post.metadata[k] for k in keys}
    except Exception:
        return None


def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search for text across vault files."""
    try:
        username = current_request_context().get("username")

        if path_prefix:
            if config.VAULT_PERMISSIONS_ENABLED and not permissions.has_readable_descendant(
                username, path_prefix
            ):
                return dumps({"error": "Permission denied"})
            search_path = resolve_vault_path(path_prefix)
            if not search_path.is_dir():
                return dumps({"error": f"Search path is not a directory: {path_prefix}"})
            search_roots = [search_path]
        else:
            if config.VAULT_PERMISSIONS_ENABLED:
                roots = permissions.readable_roots(username)
                if not roots:
                    return dumps({"error": "Permission denied"})
                search_roots = [resolve_vault_path(r) if r else config.VAULT_PATH for r in roots]
            else:
                search_roots = [config.VAULT_PATH]

        # Fetch more than max_results per root, since the permission post-filter
        # below (a backstop for grants/carve-outs nested *inside* a readable
        # root, e.g. a deny sub-prefix) may drop some -- see _SEARCH_OVERFETCH_FACTOR.
        fetch_limit = max_results * _SEARCH_OVERFETCH_FACTOR

        all_matches: list[dict] = []
        for root_path in search_roots:
            if root_path.is_dir():
                if shutil.which("rg"):
                    found = _search_ripgrep(query, root_path, file_pattern, fetch_limit, context_lines)
                else:
                    found = _search_python(query, root_path, file_pattern, fetch_limit, context_lines)
                all_matches.extend(found)
            elif root_path.is_file() and fnmatch.fnmatch(root_path.name, file_pattern):
                all_matches.extend(_search_single_file(root_path, query, fetch_limit, context_lines))

        if config.VAULT_PERMISSIONS_ENABLED:
            all_matches = [m for m in all_matches if permissions.can_read(username, m["path"])]

        truncated = len(all_matches) > max_results
        matches = all_matches[:max_results]

        for match in matches:
            file_full_path = config.VAULT_PATH / match["path"]
            match["frontmatter_excerpt"] = _get_frontmatter_excerpt(file_full_path)

        return dumps({
            "results": matches,
            "total_matches": len(matches),
            "truncated": truncated,
        })
    except ValueError as e:
        return dumps({"error": str(e)})
    except Exception as e:
        logger.error(f"vault_search error: {e}")
        return dumps({"error": str(e)})


def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: str = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
) -> str:
    """Search vault files by frontmatter field values using the in-memory index."""
    from ..server import frontmatter_index

    try:
        username = current_request_context().get("username")

        if (
            path_prefix
            and config.VAULT_PERMISSIONS_ENABLED
            and not permissions.has_readable_descendant(username, path_prefix)
        ):
            return dumps({"error": "Permission denied"})

        results = frontmatter_index.search_by_field(
            field=field,
            value=value,
            match_type=match_type,
            path_prefix=path_prefix,
        )

        if config.VAULT_PERMISSIONS_ENABLED:
            results = [r for r in results if permissions.can_read(username, r["path"])]

        formatted = []
        for item in results[:max_results]:
            path = item["path"]
            fm = item["frontmatter"]
            title = fm.get("title", Path(path).stem)
            formatted.append({
                "path": path,
                "frontmatter": fm,
                "title": title,
            })

        truncated = len(results) > max_results

        return dumps({
            "results": formatted,
            "total": len(formatted),
            "truncated": truncated,
        })
    except Exception as e:
        logger.error(f"vault_search_frontmatter error: {e}")
        return dumps({"error": str(e)})
