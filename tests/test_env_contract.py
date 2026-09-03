"""ENV_CONTRACT.toml must exactly enumerate every environment variable
config.py actually reads.

This is the mechanism that catches env-var drift *in the app repo, before it
ships* -- the deployment repo (jessups-gitops) separately lints its
ConfigMap/Secret keys against a copy of ENV_CONTRACT.toml, but that check can
only be as good as this file being kept honest against the real source. A
stale ENV_CONTRACT.toml is exactly as dangerous as a stale k8s manifest: both
let someone believe a variable is read when it isn't (or vice versa).
"""

import ast
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover -- pyproject.toml requires-python is >=3.12
    import tomli as tomllib

import obsidian_vault_mcp.config as config_module

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PY = REPO_ROOT / "src" / "obsidian_vault_mcp" / "config.py"
CONTRACT_PATH = REPO_ROOT / "ENV_CONTRACT.toml"


def _extract_fixed_env_var_names(source: str) -> set[str]:
    """AST-walk config.py for os.environ.get("NAME", ...) / os.environ["NAME"]
    reads with a literal string name. A name built from an f-string or a
    variable (the VAULT_USER_<GROUP>_* dynamic family) is deliberately NOT
    literal and so is skipped here -- that family is cross-checked separately
    in test_dynamic_per_user_family_matches_config_py, since a name enumeration
    can't produce an infinite family.
    """
    tree = ast.parse(source)
    names: set[str] = set()

    def is_os_environ_attr(node: ast.AST, attr: str) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == attr
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            self.generic_visit(node)
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "environ"
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                names.add(node.args[0].value)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            self.generic_visit(node)
            value = node.value
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "environ"
                and isinstance(value.value, ast.Name)
                and value.value.id == "os"
            ):
                idx = node.slice
                if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                    names.add(idx.value)

    Visitor().visit(tree)
    return names


def _load_contract() -> dict:
    with open(CONTRACT_PATH, "rb") as f:
        return tomllib.load(f)


def test_env_contract_file_matches_config_py_fixed_vars():
    actual = _extract_fixed_env_var_names(CONFIG_PY.read_text())
    contract = _load_contract()
    declared = {entry["name"] for entry in contract["fixed"]}

    missing_from_contract = actual - declared
    stale_in_contract = declared - actual

    assert not missing_from_contract, (
        "config.py reads env var(s) not declared in ENV_CONTRACT.toml: "
        f"{sorted(missing_from_contract)} -- add them to ENV_CONTRACT.toml in "
        "the same change."
    )
    assert not stale_in_contract, (
        "ENV_CONTRACT.toml declares env var(s) config.py no longer reads: "
        f"{sorted(stale_in_contract)} -- remove them (or fix config.py) in the "
        "same change. This is the exact class of drift that previously let a "
        "stale k8s Secret's keys go silently unread."
    )


def test_dynamic_per_user_family_matches_config_py():
    """Cross-checks ENV_CONTRACT.toml's [dynamic.per_user] table against the
    actual regex and f-string lookups in config.py's _load_users_from_env,
    rather than against a name enumeration (impossible for an infinite family)."""
    contract = _load_contract()
    dynamic = contract["dynamic"]["per_user"]
    prefix = dynamic["prefix"]

    assert config_module._USER_ENV_RE.pattern == f"^{prefix}(.+)_USERNAME$", (
        "config._USER_ENV_RE no longer matches ENV_CONTRACT.toml's declared "
        "[dynamic.per_user] prefix -- update whichever one is now wrong."
    )

    source = CONFIG_PY.read_text()
    for suffix in dynamic["required_suffixes"] + dynamic["optional_suffixes"]:
        if suffix == "USERNAME":
            continue  # covered by the regex assertion above
        snippet = f"{prefix}{{group}}_{suffix}"
        assert snippet in source, (
            f"ENV_CONTRACT.toml declares VAULT_USER_<GROUP>_{suffix} but config.py's "
            f"_load_users_from_env no longer builds {snippet!r} -- update whichever "
            "one is now wrong."
        )
