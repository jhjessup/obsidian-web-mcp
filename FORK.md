# This is a maintained fork, not a patch queue

This repo (`jhjessup/obsidian-web-mcp`, branch `multi-user-tokens`) is a fork of
[`jimprosser/obsidian-web-mcp`](https://github.com/jimprosser/obsidian-web-mcp)
carrying two features upstream doesn't have. It is not a temporary pile of
patches waiting to be upstreamed and deleted -- it's the actual codebase this
fork's deployments run, tracked by periodic rebase onto upstream `main` rather
than by staying at zero diff.

Everything not listed below is unmodified upstream code (vault CRUD, canvas
support, daily notes, frontmatter search/indexing, the OAuth 2.0/PKCE flow
itself, the FastMCP/MCP transport, the `extensions.py`/`write_events.py`
seams). When in doubt about whether something is fork-owned, `git log
--oneline main..multi-user-tokens` is the authoritative list.

## What this fork owns

**Multi-user auth** (`9db62a2`, `632758e`) -- replaces upstream's single shared
username/password/token with one `VAULT_USER_<GROUP>_USERNAME/_PASSWORD/_TOKEN`
env var triple per person, so each person gets an independent bearer token
(audit attribution) and an independent Kubernetes-Secret-shaped credential unit
(rotate one person without touching another's still-valid line). Touches
`config.py` (the env-var scan) and `auth.py`/`oauth.py` (multi-user login,
per-request username in the audit/permissions context).

This one is a genuine core patch with no available seam: upstream's
`auth.py`/`oauth.py` have no callback/hook point for pluggable credential
sources (`write_events.py` is the only such seam in core, and it's for
post-write notification, not authentication), and the login gate sits deep
enough in the OAuth authorization-code flow that there's no clean place to
delegate it to an extension without upstream adopting multi-tenant auth as a
first-class feature.

**Per-path permissions + sharing** (`bda6afb`, `7231147`) -- a filesystem-like
per-user path permission model (`permissions.py`: longest-prefix-match read/
write bits, config-set roots plus runtime share/unshare grants) enforced
inside `vault.py`'s primitives, plus three new MCP tools (`vault_share`/
`vault_unshare`/`vault_shares` in `tools/sharing.py`) and permission-aware
scoping in `tools/search.py`/`tools/analytics.py`. Gated entirely behind
`VAULT_PERMISSIONS_ENABLED` (off by default; an existing single-vault
deployment is unaffected).

This one *could* partially extract into a separate downstream package via one
new hook in `vault.py` (mirroring `write_events.py`'s shape, but for
authorization rather than notification) -- reviewed and deliberately not done:
the enforcement gate (`resolve_vault_path`'s `require=` check) would extract
cleanly, but the read-side visibility logic in `list_directory`/`search.py`/
`analytics.py` is woven into each tool's own algorithm (a three-valued
show/hide/descend-silently decision in the directory walker, a multi-root
search rewrite with its own overfetch-then-truncate logic to avoid starving
the result cap on denied matches) rather than a simple gate, so extracting it
would mean asking upstream to accept a whole authorization-query interface,
not a small seam. Given the fork's diff is otherwise small, stable, and
already carries 283+ passing tests for this feature, the extraction wasn't
judged worth a permanent two-repo release/version-pinning burden for a solo
operator. Revisit if upstream ever shows interest in multi-tenant auth --
this feature depends on that patch existing anyway.

## What's generic vs. what's deployment-specific

Every value in this fork -- env var names, defaults, validators -- is generic
mechanism, not tied to any one deployment. There is nothing here resembling a
real username, hostname, or filesystem path belonging to any particular
operator. `ENV_CONTRACT.toml` documents the resulting env-var surface so a
deployment repo can lint its own manifests against it without needing to read
this fork's source to reverse-engineer what it expects.
