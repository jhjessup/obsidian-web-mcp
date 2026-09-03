import os
import re
from pathlib import Path

# Vault configuration
VAULT_PATH = Path(os.environ.get("VAULT_PATH", os.path.expanduser("~/Obsidian/MyVault")))
VAULT_MCP_PORT = int(os.environ.get("VAULT_MCP_PORT", "8420"))


_USER_ENV_RE = re.compile(r"^VAULT_USER_(.+)_USERNAME$")


def _parse_roots(raw: str) -> list[tuple[str, str]]:
    """Parse "prefix:bits,prefix2:bits2" (comma- or newline-separated) into raw
    (prefix, bits) string tuples -- NOT validated or normalized here (this module
    can't import permissions.py without cycling back into config; permissions.py
    does that work at lookup time, and config._validate_user_roots does it at
    startup via a function-local import, the same technique _validate_mcp_path
    already uses to reach into auth.py without a top-level cycle).
    """
    pairs: list[tuple[str, str]] = []
    for chunk in raw.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        prefix, sep, bits = chunk.rpartition(":")
        if not sep:
            continue
        pairs.append((prefix.strip(), bits.strip()))
    return pairs


def _load_users_from_env() -> tuple[dict[str, str], dict[str, str], dict[str, list[tuple[str, str]]], list[str]]:
    """Build (VAULT_OAUTH_USERS, VAULT_MCP_TOKENS, VAULT_USER_ROOTS, incomplete_groups)
    from one env-var group per user: VAULT_USER_<GROUP>_USERNAME / _PASSWORD / _TOKEN
    (required) and _ROOTS (optional), where <GROUP> is an arbitrary grouping key (not
    read or validated itself -- it only ties one person's vars together; using the
    username itself, uppercased, is the readable choice but any distinct string works).

    Replaced the old single VAULT_OAUTH_USERS/VAULT_MCP_TOKENS multi-line blobs
    (each holding every user at once) with this per-user-triple shape specifically so
    each person's Kubernetes Secret can be independent -- adding, rotating, or
    removing one person's credentials no longer means regenerating a blob containing
    everyone else's still-current lines too. A person's env vars typically all come
    from one Secret (via envFrom + a per-Secret `prefix:`), but nothing here requires
    that -- this just scans whatever's in the environment. _ROOTS is not secret and
    could live in a ConfigMap instead, but keeping it alongside credentials in the
    same per-person Secret is the lower-friction choice given envFrom+prefix is
    already wired per Secret.

    incomplete_groups (a username set but its password or token missing) is
    returned rather than raised here, so every other config value still loads and
    server.main()'s fail-closed path (validate_config -> sys.exit(1)) is the one
    place startup actually aborts, consistent with every other validated value in
    this module.
    """
    users: dict[str, str] = {}
    tokens: dict[str, str] = {}
    roots: dict[str, list[tuple[str, str]]] = {}
    incomplete: list[str] = []

    for key in os.environ:
        m = _USER_ENV_RE.match(key)
        if not m:
            continue
        group = m.group(1)
        username = os.environ[key].strip()
        password = os.environ.get(f"VAULT_USER_{group}_PASSWORD", "").strip()
        token = os.environ.get(f"VAULT_USER_{group}_TOKEN", "").strip()
        if not username:
            continue
        if not password or not token:
            incomplete.append(group)
            continue
        users[username] = password
        tokens[username] = token
        roots_raw = os.environ.get(f"VAULT_USER_{group}_ROOTS", "").strip()
        if roots_raw:
            roots[username] = _parse_roots(roots_raw)

    return users, tokens, roots, sorted(incomplete)


VAULT_OAUTH_USERS, VAULT_MCP_TOKENS, _VAULT_USER_ROOTS_EXPLICIT, _INCOMPLETE_USER_GROUPS = _load_users_from_env()

# Applied to any configured user with no explicit VAULT_USER_<GROUP>_ROOTS, so the
# common "everyone gets rw on the whole vault, then carve out exceptions with
# VAULT_USER_<GROUP>_ROOTS" deployment doesn't need one identical _ROOTS entry
# repeated in every person's Secret. Same "prefix:bits,..." shape; "" (root)
# defaulting to "rw" (i.e. VAULT_DEFAULT_ROOTS unset) matches this server's
# pre-permissions behavior for anyone who doesn't get an explicit override.
VAULT_DEFAULT_ROOTS = _parse_roots(os.environ.get("VAULT_DEFAULT_ROOTS", ":rw"))

# Only takes effect when VAULT_PERMISSIONS_ENABLED is set (see below) -- until
# then every user's effective roots are irrelevant, since permissions.py's
# effective_bits() short-circuits to full access.
VAULT_USER_ROOTS: dict[str, list[tuple[str, str]]] = {
    username: _VAULT_USER_ROOTS_EXPLICIT.get(username, VAULT_DEFAULT_ROOTS)
    for username in VAULT_OAUTH_USERS
}

# Gates ALL per-path permission enforcement (permissions.py) and the vault_share/
# vault_unshare/vault_shares tools. Off by default: this server has always given
# every logged-in user the whole vault, and flipping this on without every user
# having a deliberate VAULT_USER_<GROUP>_ROOTS (or accepting VAULT_DEFAULT_ROOTS)
# would silently change that -- see permissions.py's module docstring. Accepts
# 1/true/yes/on (case-insensitive), matching VAULT_AUDIT_LOG_INCLUDE_READS below.
VAULT_PERMISSIONS_ENABLED = os.environ.get(
    "VAULT_PERMISSIONS_ENABLED", ""
).strip().lower() in {"1", "true", "yes", "on"}

# Where runtime vault_share/vault_unshare grants are persisted (permissions.py).
# Same directory as OAUTH_CLIENTS_PATH below and for the same reason: in-memory-only
# state doesn't survive a restart, and in k8s that directory must already be backed
# by a PersistentVolume for the OAuth client registry to work, so shares get
# durability for free with no new volume required.
VAULT_SHARES_PATH = Path(os.environ.get(
    "VAULT_SHARES_PATH",
    Path.home() / ".local" / "share" / "vault-mcp" / "shares.json",
))

# Daily-note tools. FOLDER "" means the vault root; FORMAT/TEMPLATE are strftime
# patterns. All optional with safe defaults; resolved paths still go through
# resolve_vault_path.
VAULT_DAILY_NOTES_FOLDER = os.environ.get("VAULT_DAILY_NOTES_FOLDER", "")
VAULT_DAILY_NOTES_FORMAT = os.environ.get("VAULT_DAILY_NOTES_FORMAT", "%Y-%m-%d").strip() or "%Y-%m-%d"
VAULT_DAILY_NOTES_TEMPLATE = os.environ.get("VAULT_DAILY_NOTES_TEMPLATE", "")

# HTTP path the MCP transport is mounted at. Defaults to "/" so connectors that
# POST to the root complete the handshake (#19) -- changing this default would
# break that, so leave it unless you deliberately host under a path prefix.
# Setting it (e.g. "/mcp") lets the server live alongside other services on one
# hostname behind a reverse proxy that cannot rewrite paths (Cloudflare Tunnel).
# Validated in validate_config(): must be absolute and must not collide with an
# auth-exempt path, or it would serve the vault on an unauthenticated route.
VAULT_MCP_PATH = os.environ.get("VAULT_MCP_PATH", "/")

# OAuth 2.0 client credentials (for Claude app integration)
VAULT_OAUTH_CLIENT_ID = os.environ.get("VAULT_OAUTH_CLIENT_ID", "vault-mcp-client")
VAULT_OAUTH_CLIENT_SECRET = os.environ.get("VAULT_OAUTH_CLIENT_SECRET", "")

# Interactive login gate on /oauth/authorize. The OAuth browser step authenticates
# the *human* before any authorization code is issued. Without this, anyone who can
# reach the URL can complete the flow and obtain a vault token (see issues #8/#29).
# A password is required on every authorization, so there is no ambient session
# cookie for a cross-site request to ride on.
#
# VAULT_OAUTH_USERS (built above, from VAULT_USER_<GROUP>_* env vars) holds each
# distinct human who may log in, each with their own token in VAULT_MCP_TOKENS --
# not a single shared pair, because that gave every logged-in client the exact same
# downstream bearer token, making two people indistinguishable in the audit log.

# Allowed redirect URIs for the operator-configured client (VAULT_OAUTH_CLIENT_ID),
# comma-separated. Dynamically-registered clients carry their own redirect_uris; this
# governs only the static operator client. If empty, the operator client cannot use the
# browser authorization-code flow (it can still use the client_credentials grant).
VAULT_OAUTH_REDIRECT_URIS = [u.strip() for u in os.environ.get("VAULT_OAUTH_REDIRECT_URIS", "").split(",") if u.strip()]

# Where the dynamically-registered OAuth client registry is persisted. The registry is
# otherwise in-memory and wiped on every restart, which breaks already-connected MCP
# clients (they replay a client_id the restarted server no longer knows). Persisting it
# keeps connectors working across restarts. It holds per-client secrets, so it is written
# with 0600 perms (see oauth._save_clients). Override with OAUTH_CLIENTS_PATH.
OAUTH_CLIENTS_PATH = Path(os.environ.get(
    "OAUTH_CLIENTS_PATH",
    Path.home() / ".local" / "share" / "vault-mcp" / "oauth_clients.json",
))

# Network bind address. Defaults to loopback so the server is NOT exposed on the LAN;
# Cloudflare Tunnel reaches it over localhost. Set to 0.0.0.0 only if you deliberately
# want direct network exposure.
VAULT_MCP_HOST = os.environ.get("VAULT_MCP_HOST", "127.0.0.1")

# Extra hostnames allowed through the MCP library's DNS-rebinding protection,
# comma-separated. Loopback (127.0.0.1, localhost, [::1]) is always allowed; set this
# to your public tunnel/proxy hostname, e.g. "vault-mcp.example.com". Operator-supplied
# hosts are APPENDED to the loopback defaults in server.py, never replace them.
VAULT_MCP_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("VAULT_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]

# Which client IPs uvicorn trusts to set X-Forwarded-* headers. Because the server
# derives request.base_url from those headers and advertises it in OAuth discovery
# metadata + the RFC 9728 WWW-Authenticate challenge, trusting them from arbitrary
# sources lets an attacker spoof the advertised authorization-server / resource URL
# (X-Forwarded-Host: evil.example) -- a token-redirection vector. The server binds
# loopback and is reached by Cloudflare Tunnel / Caddy over localhost, so the only
# trustworthy forwarder is loopback. Defaults to uvicorn's own default, "127.0.0.1";
# override only if your reverse proxy connects from a different address (e.g. "::1").
# Never set this to "*".
VAULT_MCP_FORWARDED_ALLOW_IPS = os.environ.get("VAULT_MCP_FORWARDED_ALLOW_IPS", "127.0.0.1")

# Canonical public origin for every URL the server advertises -- the OAuth metadata
# endpoints (issuer / authorization_endpoint / token_endpoint / registration_endpoint /
# resource) and the WWW-Authenticate resource_metadata pointer. When set (e.g.
# "https://vault-mcp.example.com") it PINS those URLs so a spoofed Host / X-Forwarded-Host
# header cannot redirect OAuth discovery to an attacker-controlled server. When empty,
# the server falls back to the per-request base_url. A trailing slash is ignored.
VAULT_MCP_PUBLIC_URL = os.environ.get("VAULT_MCP_PUBLIC_URL", "").strip()


def advertised_base_url(request_base_url: str) -> str:
    """Return the canonical origin to advertise, with no trailing slash.

    Prefers the operator-pinned VAULT_MCP_PUBLIC_URL; falls back to the request's
    own base_url. Centralizing this keeps the OAuth metadata endpoints and the
    WWW-Authenticate challenge consistent and spoof-resistant.
    """
    return (VAULT_MCP_PUBLIC_URL or request_base_url).rstrip("/")

# Optional liveness heartbeat. When VAULT_MCP_HEARTBEAT_URL is set, the server GETs
# it every VAULT_MCP_HEARTBEAT_INTERVAL seconds from a daemon thread, for push-style
# uptime monitors (Uptime Kuma, Healthchecks.io, Cronitor, ...). Empty = disabled
# (the default); failures are logged, never fatal. The interval is kept as a raw
# string and parsed in validate_heartbeat() so a bad value fails closed at startup
# rather than crashing the whole server at import time.
VAULT_MCP_HEARTBEAT_URL = os.environ.get("VAULT_MCP_HEARTBEAT_URL", "").strip()
VAULT_MCP_HEARTBEAT_INTERVAL = os.environ.get("VAULT_MCP_HEARTBEAT_INTERVAL", "60").strip()


def validate_heartbeat() -> int | None:
    """Validate the heartbeat config; return the interval (seconds) when enabled.

    Returns None when the heartbeat is disabled (no URL). Raises ValueError (so
    server.main() can exit non-zero and fail CLOSED) when the URL scheme is not
    http(s) or the interval is not a positive integer -- a typo must not boot a
    server that silently never pings, or that tight-loops on interval 0.
    """
    url = VAULT_MCP_HEARTBEAT_URL
    if not url:
        return None

    from urllib.parse import urlsplit

    # The error messages below deliberately never echo the raw values: the URL is a
    # capability URL (secret in the path), and a misconfigured operator might swap the
    # URL/interval env vars -- and server.main() logs whatever this raises.
    try:
        parsed = urlsplit(url)
        port = parsed.port  # raises ValueError on a malformed port
    except ValueError:
        raise ValueError("VAULT_MCP_HEARTBEAT_URL has a malformed port")
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("VAULT_MCP_HEARTBEAT_URL must be an http(s) URL with a host")
    del port  # only accessed to trigger the malformed-port check

    try:
        interval = int(VAULT_MCP_HEARTBEAT_INTERVAL)
    except ValueError:
        raise ValueError(
            "VAULT_MCP_HEARTBEAT_INTERVAL must be an integer number of seconds"
        )
    if interval <= 0:
        raise ValueError("VAULT_MCP_HEARTBEAT_INTERVAL must be a positive integer")
    return interval


# Append-only JSONL audit log of vault mutations. When VAULT_AUDIT_LOG_PATH is set,
# every mutation appends one JSON record (UTC timestamp, SHA-256 hash of the bearer
# token, operation, target path, size + checksum before and after). Empty (the default)
# disables auditing entirely. The raw bearer token is never written -- only its SHA-256
# hash. The path is validated as writable at startup; an unwritable path fails the
# server closed (see server.main) rather than dropping records silently.
VAULT_AUDIT_LOG_PATH = os.environ.get("VAULT_AUDIT_LOG_PATH", "").strip()

# Also record read/search operations (opt-in). Off by default because reads are
# high-volume and may carry privacy weight; mutations are always logged once the audit
# log is enabled. Accepts 1/true/yes/on (case-insensitive).
VAULT_AUDIT_LOG_INCLUDE_READS = os.environ.get(
    "VAULT_AUDIT_LOG_INCLUDE_READS", ""
).strip().lower() in {"1", "true", "yes", "on"}

# Safety limits
MAX_CONTENT_SIZE = 1_000_000  # 1MB max write size
MAX_BINARY_SIZE = 10_000_000  # 10MB max binary write size (images/PDFs run larger than text)
MAX_BATCH_SIZE = 20           # Max files per batch operation
MAX_SEARCH_RESULTS = 50       # Max results per search
DEFAULT_SEARCH_RESULTS = 20
MAX_LIST_DEPTH = 5            # Max directory recursion depth
CONTEXT_LINES = 2             # Default lines of context in search results

# Directories to never expose or modify
EXCLUDED_DIRS = {".obsidian", ".trash", ".git", ".DS_Store"}

# Frontmatter index refresh interval (seconds)
FRONTMATTER_INDEX_DEBOUNCE = 5.0

# Rate limiting (requests per minute) -- track in-memory, enforce per-token
RATE_LIMIT_READ = 100
RATE_LIMIT_WRITE = 30


def _validate_mcp_path(path: str) -> None:
    """Reject a VAULT_MCP_PATH that is malformed or would expose the vault unauthenticated.

    The MCP transport mounts at exactly this path. The default "/" keeps behaviour
    byte-identical and is always valid. Any other value must be an absolute, clean
    path that does NOT land on (or under) an authentication-exempt route -- otherwise
    the bearer middleware would wave the vault transport through without a token.
    """
    if path == "/":
        return
    if not path.startswith("/"):
        raise ValueError(
            f"VAULT_MCP_PATH must be an absolute path starting with '/': {path!r}"
        )
    if path.endswith("/"):
        raise ValueError(
            f"VAULT_MCP_PATH must not end with a trailing slash: {path!r}"
        )
    if "?" in path or "#" in path or "//" in path:
        raise ValueError(
            "VAULT_MCP_PATH must be a clean path with no query string, fragment, "
            f"or empty segments: {path!r}"
        )
    if "%" in path or any(c.isspace() or ord(c) < 0x20 for c in path):
        raise ValueError(
            "VAULT_MCP_PATH must not contain percent-encoding, whitespace, or "
            f"control characters: {path!r}"
        )
    if any(seg in (".", "..") for seg in path.strip("/").split("/")):
        raise ValueError(
            f"VAULT_MCP_PATH must not contain '.' or '..' path segments: {path!r}"
        )
    # Imported lazily: auth imports config, so a top-level import here would cycle.
    from .auth import _AUTH_EXEMPT_PATHS

    reserved_prefixes = ("/oauth", "/.well-known")
    collides = path in _AUTH_EXEMPT_PATHS or any(
        path == prefix or path.startswith(prefix + "/") for prefix in reserved_prefixes
    )
    if collides:
        raise ValueError(
            f"VAULT_MCP_PATH {path!r} collides with an authentication-exempt route; "
            "mounting there would serve the vault without auth. Choose a path that is "
            "not /health and not under /oauth or /.well-known."
        )


def _validate_users_have_tokens() -> None:
    """Every configured login must have a matching bearer token.

    _load_users_from_env() already guarantees VAULT_OAUTH_USERS and VAULT_MCP_TOKENS
    are pairwise consistent (an incomplete VAULT_USER_<GROUP>_* triple is excluded
    from both rather than added to one). What it can't rule out is a *username set
    with its password or token missing* -- that's a real per-Secret typo (e.g. one
    key omitted when generating a person's SealedSecret), and letting that person's
    login silently vanish rather than erroring is exactly the kind of gap that would
    otherwise surface as a confusing runtime 401 instead of an explained startup
    failure.
    """
    if _INCOMPLETE_USER_GROUPS:
        raise ValueError(
            "Incomplete VAULT_USER_<GROUP>_* triple for: " +
            ", ".join(_INCOMPLETE_USER_GROUPS) +
            " -- each group needs all three of _USERNAME, _PASSWORD, and _TOKEN set."
        )


def _validate_user_roots() -> None:
    """Every configured root/share prefix and bits must actually parse, and (when
    permissions are enabled) every user must have at least one root -- a user with
    zero roots can do literally nothing, which is far more likely a missing Secret
    key than an operator's actual intent, so it fails startup rather than silently
    locking that person out.
    """
    # Imported lazily: permissions.py imports config, so a top-level import here
    # would cycle -- same technique _validate_mcp_path uses for auth.py.
    from . import permissions

    bad: list[str] = []
    for username, entries in VAULT_USER_ROOTS.items():
        if VAULT_PERMISSIONS_ENABLED and not entries:
            bad.append(f"{username} (no roots at all)")
            continue
        for prefix, bits in entries:
            try:
                permissions.normalize_prefix(prefix)
                permissions.bits_from_str(bits)
            except ValueError as e:
                bad.append(f"{username} ({prefix!r}:{bits!r}: {e})")

    if bad:
        raise ValueError(
            "Invalid VAULT_USER_<GROUP>_ROOTS / VAULT_DEFAULT_ROOTS entries: " +
            "; ".join(bad)
        )


def _validate_shares_path_outside_vault() -> None:
    """Reject a VAULT_SHARES_PATH that resolves inside the vault.

    Same reasoning as audit.audit_path_inside_vault(): a share registry the vault
    tools can themselves read or overwrite (via vault_write/vault_delete) turns
    "share a path with yourself with full bits" into a privilege-escalation
    primitive. Only checked when permissions are enabled -- the file isn't even
    read or written otherwise.
    """
    if not VAULT_PERMISSIONS_ENABLED:
        return
    try:
        shares_path = VAULT_SHARES_PATH.resolve()
        vault = VAULT_PATH.resolve()
    except OSError:
        return
    if shares_path == vault or vault in shares_path.parents:
        raise ValueError(
            f"VAULT_SHARES_PATH resolves inside the vault ({shares_path}); the vault "
            "tools could rewrite it. Choose a path outside VAULT_PATH."
        )


def validate_config() -> None:
    """Validate operator-supplied configuration at startup.

    Called from server.main() before the server is built, so a bad value fails
    CLOSED with a clear message instead of booting a broken or insecure server.
    """
    _validate_mcp_path(VAULT_MCP_PATH)
    _validate_users_have_tokens()
    _validate_user_roots()
    _validate_shares_path_outside_vault()
