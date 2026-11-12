"""The ``memdiver.oracles`` registry, verdict normalisation and the format contract.

The AST tests enforce the paste-safe contract of ``oracles/formats/*.py`` (and
of the inline runtime that is pasted next to them): a format module that
grows a module-level third-party import, a relative import or a ``__file__``
dependency would still pass every in-repo test and only break inside a
generated plugin, so the contract is checked statically here.
"""

from __future__ import annotations

import ast
import dataclasses
import types
from pathlib import Path

import pytest

import memdiver.oracles as registry
from memdiver.oracles import (
    FORMAT_CONTRACT,
    FormatContractError,
    OracleVerdict,
    UnknownFormatError,
    get_format,
    list_formats,
    missing_contract,
    verdict_from,
)

ORACLES_DIR = Path(registry.__file__).parent
FORMAT_FILES = sorted(p for p in (ORACLES_DIR / "formats").glob("*.py") if p.name != "__init__.py")
PASTED_FILES = FORMAT_FILES + [ORACLES_DIR / "_inline_runtime.py"]
# The only third-party packages a format may import, and only lazily:
# cryptography, and pycryptodome (imported as "Crypto"; volatility3[full] ships it).
LAZY_BACKENDS = {"cryptography", "Crypto"}
# A FIXED allow-list of standard-library modules that exist in Python 3.8 (the
# oldest interpreter Volatility 3 runs on). Deliberately not the running
# interpreter's sys.stdlib_module_names: that would admit 3.9+ additions such
# as zoneinfo, graphlib or tomllib, which break a plugin on an older host.
# Extend it consciously when a format genuinely needs another 3.8 module.
PY38_STDLIB_ALLOWED = frozenset({
    "abc", "array", "ast", "base64", "binascii", "bisect", "codecs", "collections",
    "contextlib", "copy", "dataclasses", "enum", "errno", "functools", "hashlib",
    "heapq", "hmac", "importlib", "io", "itertools", "json", "linecache", "logging",
    "math", "operator", "os", "pathlib", "re", "secrets", "string", "struct", "sys",
    "textwrap", "types", "typing", "warnings", "zlib",
})


# ------------------------------------------------------------------ registry


def test_gocryptfs_format_is_discovered_and_complete():
    assert "gocryptfs-gcm" in list_formats()
    module = get_format("gocryptfs-gcm")
    assert module.KIND == "gocryptfs-gcm"
    assert missing_contract(module) == []
    assert module.CANDIDATE_LENGTHS == (32, 64)
    assert isinstance(module.COST_US, (int, float)) and module.COST_US > 0


def test_unknown_kind_raises_keyerror_naming_known_kinds():
    with pytest.raises(UnknownFormatError, match="gocryptfs-gcm"):
        get_format("no-such-format")
    assert issubclass(UnknownFormatError, KeyError)


def test_missing_contract_lists_absent_names():
    partial = types.ModuleType("partial")
    partial.KIND = "partial"
    partial.build_oracle = lambda params, sample: None
    assert missing_contract(partial) == [
        n for n in FORMAT_CONTRACT if n not in ("KIND", "build_oracle")
    ]


def test_duplicate_kind_is_refused(monkeypatch):
    infos = [types.SimpleNamespace(name="a"), types.SimpleNamespace(name="b")]
    fakes = {name: types.ModuleType(name) for name in ("a", "b")}
    for fake in fakes.values():
        fake.KIND = "same-kind"
    package = types.SimpleNamespace(__path__=[])
    monkeypatch.setattr(registry.pkgutil, "iter_modules", lambda path: infos)
    monkeypatch.setattr(
        registry.importlib, "import_module",
        lambda name: package if name.endswith(".formats") else fakes[name.rsplit(".", 1)[1]],
    )
    with pytest.raises(FormatContractError, match="same-kind"):
        registry._discover.__wrapped__()


# ------------------------------------------------------------------ verdicts


def test_verdict_from_contract_dict():
    raw = {"status": "proven", "kind": "k", "detail": "ok", "derived": {"a": 1}}
    verdict = verdict_from(raw)
    assert verdict == OracleVerdict("proven", "k", "ok", {"a": 1})
    assert verdict.proven
    raw["derived"]["a"] = 2  # the verdict holds its own copy
    assert verdict.derived == {"a": 1}


@pytest.mark.parametrize(("obj", "status"), [
    (True, "proven"),
    (False, "rejected"),
    ({"status": "maybe"}, "error"),
    ({"status": "proven", "derived": [1, 2]}, "error"),
    (None, "error"),
    ("proven", "error"),
])
def test_verdict_from_normalises_odd_results(obj, status):
    verdict = verdict_from(obj, kind="fallback-kind")
    assert (verdict.status, verdict.kind) == (status, "fallback-kind")


def test_verdict_from_passes_verdicts_through_and_is_frozen():
    verdict = OracleVerdict("rejected", "k")
    assert verdict_from(verdict) is verdict
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.status = "proven"
    with pytest.raises(ValueError):
        OracleVerdict("probably", "k")


# ------------------------------------------------------- paste-safe contract


class _ImportCollector(ast.NodeVisitor):
    """Collect (top-level package, runs_at_import, relative level) for every import.

    An import "runs at import" unless it sits inside a function body; class
    bodies execute at import time, so they count as module level.
    """

    def __init__(self) -> None:
        self.imports: list[tuple[str, bool, int]] = []
        self._function_depth = 0

    def _enter_function(self, node: ast.AST) -> None:
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    visit_FunctionDef = visit_AsyncFunctionDef = _enter_function

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((alias.name.split(".")[0], self._function_depth == 0, 0))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = (node.module or "").split(".")[0]
        self.imports.append((module, self._function_depth == 0, node.level))


def _imports(path: Path) -> list[tuple[str, bool, int]]:
    collector = _ImportCollector()
    collector.visit(ast.parse(path.read_text(encoding="utf-8")))
    return collector.imports


def test_there_is_at_least_one_format_file():
    assert any(p.name == "gocryptfs_gcm.py" for p in FORMAT_FILES)


@pytest.mark.parametrize("path", PASTED_FILES, ids=lambda p: p.name)
def test_module_level_imports_are_stdlib_only(path):
    at_import = [n for n, top, _ in _imports(path) if top and n not in PY38_STDLIB_ALLOWED]
    assert at_import == [], f"{path.name}: module-level non-stdlib imports {at_import}"


@pytest.mark.parametrize("path", PASTED_FILES, ids=lambda p: p.name)
def test_lazy_imports_are_stdlib_or_a_known_backend(path):
    allowed = PY38_STDLIB_ALLOWED | LAZY_BACKENDS
    if path.name == "_inline_runtime.py":
        allowed = PY38_STDLIB_ALLOWED
    bad = [name for name, _, _ in _imports(path) if name not in allowed]
    assert bad == [], f"{path.name}: imports {bad}"


@pytest.mark.parametrize("path", PASTED_FILES, ids=lambda p: p.name)
def test_source_is_paste_safe(path):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, feature_version=(3, 8))
    assert all(level == 0 for _, _, level in _imports(path)), "relative import"
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "__file__" not in names
    assert not any(
        isinstance(n, ast.ImportFrom) and n.module == "__future__" for n in ast.walk(tree)
    ), "from __future__ breaks pasting mid-file"
    assert not any(line.startswith("# --- memdiver ") for line in text.split("\n"))


def test_allow_list_rejects_post_38_stdlib_modules(tmp_path):
    for late in ("tomllib", "zoneinfo", "graphlib"):
        assert late not in PY38_STDLIB_ALLOWED
    probe = tmp_path / "probe.py"
    probe.write_text("import tomllib\n")
    assert [n for n, top, _ in _imports(probe) if top and n not in PY38_STDLIB_ALLOWED] == [
        "tomllib"
    ]
