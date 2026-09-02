"""VAULT_MCP_PATH defaults to / and the spec-probe auth exemption is guarded.

The probe route itself is mounted in server.main() (needs a running app), so it
is not unit-tested here; the testable contract is (a) the config default/override
and (b) that auth only exempts GET/HEAD / when MCP is mounted off root.
"""

import importlib

import pytest
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth, config, server


def _reload(monkeypatch, value):
    """Reload config (+auth, which snapshots the path) with VAULT_MCP_PATH set/unset."""
    if value is None:
        monkeypatch.delenv("VAULT_MCP_PATH", raising=False)
    else:
        monkeypatch.setenv("VAULT_MCP_PATH", value)
    importlib.reload(config)
    importlib.reload(auth)


def test_path_defaults_to_root(monkeypatch):
    try:
        _reload(monkeypatch, None)
        assert config.VAULT_MCP_PATH == "/"
    finally:
        _reload(monkeypatch, None)


def test_path_override(monkeypatch):
    try:
        _reload(monkeypatch, "/mcp")
        assert config.VAULT_MCP_PATH == "/mcp"
    finally:
        _reload(monkeypatch, None)


def test_probe_not_exempt_at_root(monkeypatch):
    """Default mount (/) keeps GET/HEAD / fully authenticated."""
    try:
        _reload(monkeypatch, None)
        assert auth._AUTH_EXEMPT_METHOD_PATHS == set()
    finally:
        _reload(monkeypatch, None)


def test_probe_exempt_when_off_root(monkeypatch):
    """Hosting under a prefix frees / for the unauthenticated spec probe."""
    try:
        _reload(monkeypatch, "/mcp")
        assert ("GET", "/") in auth._AUTH_EXEMPT_METHOD_PATHS
        assert ("HEAD", "/") in auth._AUTH_EXEMPT_METHOD_PATHS
    finally:
        _reload(monkeypatch, None)


# --- startup validation of VAULT_MCP_PATH ---------------------------------

@pytest.mark.parametrize("value", ["/", "/mcp", "/mcp/sub", "/a-b_c"])
def test_validate_accepts_clean_paths(value):
    config._validate_mcp_path(value)  # must not raise


@pytest.mark.parametrize(
    "value",
    [
        "",            # empty
        "mcp",         # not absolute
        "/mcp/",       # trailing slash
        "/a?b",        # query string
        "/a#b",        # fragment
        "//a",         # empty segment
    ],
)
def test_validate_rejects_malformed_paths(value):
    with pytest.raises(ValueError):
        config._validate_mcp_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "/health",
        "/oauth",
        "/oauth/token",
        "/oauth/authorize",
        "/.well-known",
        "/.well-known/oauth-protected-resource",
    ],
)
def test_validate_rejects_auth_exempt_collisions(value):
    """Mounting the transport on an exempt route would serve the vault unauthenticated."""
    with pytest.raises(ValueError):
        config._validate_mcp_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "/.",              # bare dot segment
        "/mcp/..",         # parent traversal segment
        "/oauth%2ftoken",  # percent-encoded collision attempt
        "/a b",            # whitespace
        "/a\x01b",         # control character
    ],
)
def test_validate_rejects_dot_encoding_and_control_chars(value):
    """Regression guard for the exact abuse strings the clean-path check now rejects."""
    with pytest.raises(ValueError):
        config._validate_mcp_path(value)


def test_validate_config_fails_closed_on_bad_path(monkeypatch):
    """validate_config() raises (so main() can exit non-zero) for a colliding mount."""
    try:
        _reload(monkeypatch, "/oauth/token")
        with pytest.raises(ValueError):
            config.validate_config()
    finally:
        _reload(monkeypatch, None)


def test_validate_config_passes_for_default_and_override(monkeypatch):
    try:
        _reload(monkeypatch, None)
        config.validate_config()  # default "/" is valid
        _reload(monkeypatch, "/mcp")
        config.validate_config()  # clean prefix is valid
    finally:
        _reload(monkeypatch, None)


# --- end-to-end auth seam on the assembled app -----------------------------
#
# These exercise the real build_app() composition (transport + OAuth + probe +
# bearer middleware), not just the validation helper -- so they fail if main()
# stops calling validate_config(), mounts the probe at root, or the off-root
# exemption drifts.

def _reload_server(monkeypatch, path):
    """Reload config -> auth -> server so mcp/build_app pick up VAULT_MCP_PATH."""
    if path is None:
        monkeypatch.delenv("VAULT_MCP_PATH", raising=False)
    else:
        monkeypatch.setenv("VAULT_MCP_PATH", path)
    importlib.reload(config)
    importlib.reload(auth)
    importlib.reload(server)


def test_assembled_app_default_root_requires_auth(monkeypatch):
    """Default mount: no unauthenticated probe; the transport at / needs a token."""
    try:
        _reload_server(monkeypatch, None)
        monkeypatch.setattr(config, "VAULT_MCP_TOKENS", {"tester": "secret-token"})
        app = server.build_app()
        paths = [getattr(r, "path", None) for r in app.routes]
        assert "/" in paths            # transport mounted at root
        assert "/mcp" not in paths     # nothing mounted off-root by default
        with TestClient(app) as client:
            for method in ("get", "head", "post"):
                r = getattr(client, method)("/")
                assert r.status_code == 401, f"{method} / should be 401 at root"
                # The unauthenticated request must NOT get the liveness probe.
                assert "MCP-Protocol-Version" not in r.headers
    finally:
        _reload_server(monkeypatch, None)


def test_assembled_app_offroot_probe_is_liveness_only(monkeypatch):
    """Off-root: GET/HEAD / is the unauthenticated probe; everything else needs auth."""
    try:
        _reload_server(monkeypatch, "/mcp")
        monkeypatch.setattr(config, "VAULT_MCP_TOKENS", {"tester": "secret-token"})
        app = server.build_app()
        # Non-vacuous: the transport really is mounted off-root, and / is the probe.
        # If build_app stopped mounting the transport, "/mcp" would be absent here
        # (the unauth-401 assertions below pass regardless, since auth precedes routing).
        paths = [getattr(r, "path", None) for r in app.routes]
        assert "/mcp" in paths   # the MCP transport is mounted at the configured path
        assert "/" in paths      # the liveness probe
        with TestClient(app) as client:
            # Unauthenticated liveness probe at / -- returns only the protocol header.
            r = client.get("/")
            assert r.status_code == 200
            assert r.headers.get("MCP-Protocol-Version") == "2025-06-18"
            assert not r.content  # no vault data, just liveness

            # A non-probe method at / is not exempt.
            assert client.post("/").status_code == 401

            # The transport itself stays behind bearer auth.
            assert client.get("/mcp").status_code == 401
            assert client.post("/mcp").status_code == 401
    finally:
        _reload_server(monkeypatch, None)


def test_main_fails_closed_on_colliding_path(monkeypatch, tmp_path):
    """main() must sys.exit(1) on a mount that collides with an exempt route."""
    monkeypatch.setattr(server, "VAULT_PATH", tmp_path)            # pass the is_dir() gate
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/oauth/token")  # colliding mount
    # Prove we never reach serving: blow up if the index or uvicorn is touched.
    monkeypatch.setattr(server.frontmatter_index, "start",
                        lambda: pytest.fail("reached serving despite bad config"))
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
