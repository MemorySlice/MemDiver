"""Cross-cutting architecture invariants for the presentation-separation refactor.

This module is the holistic "did we actually achieve the goal" check described
in the refactor plan's Context section: MemDiver is exposed through several
surfaces (library, CLI, FastAPI/Web UI, MCP server) that share the same core
compute but must disagree on *presentation* — without a behavior flag (the old
``report_key_status: bool``) leaking into core logic ever again.

Three kinds of guard live here:

1. Static/AST guards pinning the "no bad signalling" rules repo-wide:
   ``report_key_status`` is never PASSED at a production call site,
   ``HTTPException``/real ``print()`` calls never appear in the service
   layers, and the un-migrated legacy dict-returning functions in
   ``app/tools_inspect.py`` are unreachable from any production surface.
2. An envelope-delegation guard: ``_tag_status_error`` (legacy) now delegates
   to ``KeyStatus.from_source`` rather than duplicating its hint text.
3. The plan's end-to-end proof: ONE core producer call on an encrypted
   ``.msl`` opened WITHOUT a key, fed to all three inspect presenters plus
   read directly off the ``ServiceResult`` itself, demonstrating one
   status-carrying result -> four correct surface behaviors.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_result import KeyStatus  # noqa: E402
from memdiver.msl.enums import TagStatus  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Shared AST helpers
# ---------------------------------------------------------------------------


def _py_files(*dirs: str):
    for d in dirs:
        base = ROOT / d
        if base.is_file():
            yield base
            continue
        if not base.exists():
            continue
        yield from base.rglob("*.py")


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _name_or_attr_usages(dirs, target_name: str):
    """Yield ``(path, lineno)`` for every AST reference to ``target_name``,
    whether as a bare name (``HTTPException(...)``) or an attribute
    (``fastapi.HTTPException(...)``). AST-based so docstrings/comments that
    merely mention the word never produce a false positive."""
    hits = []
    for path in _py_files(*dirs):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == target_name:
                hits.append((path, node.lineno))
            elif isinstance(node, ast.Attribute) and node.attr == target_name:
                hits.append((path, node.lineno))
    return hits


# ---------------------------------------------------------------------------
# Invariant 1 (flagship) — report_key_status never PASSED at a production
# call site. It is allowed to remain as a deprecated no-op *parameter* on the
# legacy functions in app/tools_inspect.py.
# ---------------------------------------------------------------------------

_PRODUCTION_SURFACE_FILES = [
    ROOT / "cli.py",
    ROOT / "mcp_server" / "server.py",
    ROOT / "mcp_server" / "presenters.py",
    ROOT / "api" / "main.py",
    *sorted((ROOT / "api" / "routers").rglob("*.py")),
]

_CALL_SITE_PATTERN = re.compile(r"report_key_status\s*=")


def test_report_key_status_never_passed_in_production_surfaces():
    """No production surface passes ``report_key_status=...`` at a call site.

    Mirrors ``grep -rn "report_key_status" api/ cli.py mcp_server/server.py
    mcp_server/presenters.py`` from the plan's flagship proof: the only
    matches allowed anywhere are docstring mentions (no ``=``) or the
    deprecated parameter's own definition inside app/tools_inspect.py.
    """
    offenders = []
    for path in _PRODUCTION_SURFACE_FILES:
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if _CALL_SITE_PATTERN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert offenders == [], (
        "report_key_status passed as an argument at a production call site:\n"
        + "\n".join(offenders)
    )


def test_report_key_status_kept_only_as_deprecated_param_in_app_layer():
    """Every function still carrying ``report_key_status`` as a parameter
    lives in app/tools_inspect.py and is explicitly marked deprecated."""
    tree = _parse(ROOT / "app" / "tools_inspect.py")
    carriers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            param_names = {a.arg for a in node.args.args + node.args.kwonlyargs}
            if "report_key_status" in param_names:
                carriers.append(node)
    assert carriers, "expected at least one legacy function retaining report_key_status"
    for node in carriers:
        docstring = ast.get_docstring(node) or ""
        assert "deprecated" in docstring.lower(), (
            f"{node.name} carries report_key_status but its docstring has no "
            "deprecation notice"
        )


# ---------------------------------------------------------------------------
# Invariant 2 (single funnel) — core/engine/app raise only CapabilityError;
# no HTTPException, no real print(), no legacy {"error"} dict reachable from
# a production surface.
# ---------------------------------------------------------------------------


def test_no_httpexception_in_service_layers():
    """``core/``, ``engine/``, ``app/``, ``api/services/`` never reference
    ``HTTPException`` — that is an HTTP-framework concern confined to the
    routers/adapters, translated at the single API exception handler."""
    hits = _name_or_attr_usages(
        ["core", "engine", "app", str(Path("api") / "services")], "HTTPException"
    )
    assert hits == [], "HTTPException referenced in a service layer: " + ", ".join(
        f"{p.relative_to(ROOT)}:{ln}" for p, ln in hits
    )


def test_no_real_print_calls_in_service_layers():
    """No genuine ``print()`` call in ``core/``, ``engine/``, ``app/``.

    AST-based (rather than textual grep) so docstring code examples
    (``core/phase_normalizer.py``'s ``Usage::`` block) and substring
    coincidences (``_log_module_fingerprint(`` in ``engine/oracle.py``) are
    never mistaken for a real print() call.
    """
    hits = []
    for path in _py_files("core", "engine", "app"):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                hits.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert hits == [], "real print() call found in a service layer: " + ", ".join(hits)


def test_no_error_dict_return_in_app_tools_pipeline():
    """``app/tools_pipeline.py`` never returns the legacy ``{"error": ...}``
    magic dict — pipeline failures are typed ``CapabilityError`` raises."""
    path = ROOT / "app" / "tools_pipeline.py"
    assert path.exists()
    assert 'return {"error"' not in path.read_text()


def test_app_layer_never_imports_up_into_api():
    """The ``app`` layer owns the shared compute/infra; it must never import UP
    into the ``api`` layer.

    Every producer and every piece of shared infrastructure lives in ``app`` (or
    below it: ``core`` / ``engine`` / ``msl`` / ``architect``). The transports in
    ``api`` are thin presenters that import DOWN into ``app``. An ``app`` module
    that imports ``memdiver.api.*`` (e.g. the old ``api.services.analysis_service``
    / ``api.services.reader_cache`` dependencies) is an inverted dependency; this
    test locks that inversion closed. Only the shims in ``api/services`` remain,
    and they import DOWN into ``app`` — never the reverse.
    """
    offenders = []
    for path in _py_files("app"):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # Absolute ``from memdiver.api...`` / ``from api...`` (level 0)
                # and relative ``from ..api...`` (level > 0) both count as upward.
                mod = node.module or ""
                if node.level and node.level > 0:
                    mod = ("." * node.level) + mod
                targets = [mod]
            for t in targets:
                if (
                    t == "memdiver.api"
                    or t.startswith("memdiver.api.")
                    or t == "api"
                    or t.startswith("api.")
                    or ".api." in t
                    or t.endswith(".api")
                ):
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: imports {t}"
                    )
    assert not offenders, (
        "app/ must not import UP into api/. Move the shared code DOWN into app/ "
        "and leave a re-export shim in api/. Offending imports:\n"
        + "\n".join(offenders)
    )


def test_engine_layer_never_imports_up_into_presentation():
    """The ``engine`` layer is pure numeric/compute; it must never import UP into
    the ``presentation`` layer.

    ``presentation`` holds the surface-agnostic text/markdown/plotly builders and
    is allowed to depend DOWN on ``engine`` (result types under ``TYPE_CHECKING``
    plus a lazy ``SIGMA_K2`` constant — the correct direction). The reverse edge
    is an inverted dependency: it used to be masked by deferred in-function
    ``from memdiver.presentation.reports import ...`` calls inside the engine's
    report delegators. P1.2 relocated those writers UP into ``app.reports`` (which
    may import both layers); this test locks the inversion closed so a new engine
    report method can't quietly re-open the cycle. Mirrors
    ``test_app_layer_never_imports_up_into_api``.
    """
    offenders = []
    for path in _py_files("engine"):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and node.level > 0:
                    mod = ("." * node.level) + mod
                targets = [mod]
            for t in targets:
                if (
                    t == "memdiver.presentation"
                    or t.startswith("memdiver.presentation.")
                    or t == "presentation"
                    or t.startswith("presentation.")
                    or ".presentation." in t
                    or t.endswith(".presentation")
                ):
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: imports {t}"
                    )
    assert not offenders, (
        "engine/ must not import UP into presentation/. Engine returns pure data; "
        "render in the app-layer writers (app/reports.py) instead. Offending "
        "imports:\n" + "\n".join(offenders)
    )


def test_engine_layer_never_imports_up_into_app():
    """The ``engine`` layer is pure compute; it must never import UP into ``app``.

    ``app`` (the surface-agnostic service layer) depends DOWN on ``engine`` — the
    correct direction. The reverse edge used to exist: the pipeline runner and
    task runners lived in ``engine/`` yet reached up into ``app.tools_pipeline`` /
    ``app.artifact_cache`` via deferred in-function imports that masked the cycle.
    P1.1 relocated that orchestration layer UP into ``app.pipeline`` so the
    direction is now ``app.pipeline → app.tools_pipeline → engine``. This test
    locks the inversion closed so no new engine module can re-open it. Mirrors
    ``test_app_layer_never_imports_up_into_api`` and
    ``test_engine_layer_never_imports_up_into_presentation``.
    """
    offenders = []
    for path in _py_files("engine"):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and node.level > 0:
                    mod = ("." * node.level) + mod
                targets = [mod]
            for t in targets:
                if (
                    t == "memdiver.app"
                    or t.startswith("memdiver.app.")
                    or t == "app"
                    or t.startswith("app.")
                    or ".app." in t
                    or t.endswith(".app")
                ):
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: imports {t}"
                    )
    assert not offenders, (
        "engine/ must not import UP into app/. Engine returns pure data; the "
        "orchestration that calls app producers lives in app/pipeline/. Offending "
        "imports:\n" + "\n".join(offenders)
    )


def test_legacy_error_dict_functions_unreachable_from_production():
    """app/tools_inspect.py keeps un-migrated legacy functions that still
    ``return {"error": ...}`` dicts (``read_hex``, ``get_session_info``, etc.)
    purely for backward-compat test coverage — the same carve-out the plan
    grants ``report_key_status``. The invariant that actually matters is that
    no production surface calls them directly; every production caller goes
    through the ``*_result`` producers + presenters instead.
    """
    legacy_names = [
        "read_hex", "_read_hex_raw", "_resolve_va", "search_bytes",
        "get_session_info", "get_page_states", "get_processes",
        "get_modules", "get_handles",
    ]
    production_files = [
        ROOT / "cli.py",
        ROOT / "mcp_server" / "server.py",
        ROOT / "mcp_server" / "presenters.py",
        *sorted((ROOT / "api" / "routers").rglob("*.py")),
    ]
    call_patterns = {
        name: re.compile(rf"tools_inspect\.{re.escape(name)}\(") for name in legacy_names
    }
    offenders = []
    for path in production_files:
        text = path.read_text()
        for name, pattern in call_patterns.items():
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)} calls tools_inspect.{name}(")
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# Invariant 4 (envelope) — the legacy _tag_status_error shim delegates to
# KeyStatus.from_source rather than maintaining its own duplicate hint text.
# ---------------------------------------------------------------------------


class _StubSource:
    """Minimal stand-in exposing a ``tag_status`` attribute."""

    def __init__(self, tag_status: TagStatus):
        self.tag_status = tag_status


def test_tag_status_error_delegates_to_key_status_from_source():
    from memdiver.mcp_server import tools_inspect

    for tag_status in (TagStatus.MISSING_KEY, TagStatus.CORRUPTED):
        stub = _StubSource(tag_status)
        legacy = tools_inspect._tag_status_error(stub)
        key = KeyStatus.from_source(stub)
        assert legacy == {"error": key.hint, "tag_status": key.tag_status.value}
        assert key.hint is not None

    for tag_status in (TagStatus.VALID, TagStatus.NOT_ENCRYPTED):
        assert tools_inspect._tag_status_error(_StubSource(tag_status)) is None


# ---------------------------------------------------------------------------
# Invariant 5 — end-to-end: ONE core producer call on a real encrypted .msl
# opened WITHOUT a key, fed through all three inspect presenters plus read
# directly off the ServiceResult, per the plan's Verification section.
# ---------------------------------------------------------------------------


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096):
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(str(path), pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    return str(msl), str(keyfile)


def test_end_to_end_missing_key_four_surface_behaviors(encrypted_msl):
    """One core producer, no key supplied -> four correct surface behaviors.

    (a) present_inspect_http -> payload only, region_count == 0, no
        tag_status/error/status leakage (the API's empty-means-locked
        contract, byte-for-byte).
    (b) present_inspect_cli -> (payload, exit_code, stderr_msg) with exit 1
        and the inline {"error", "tag_status": "missing_key"} dict.
    (c) present_inspect_mcp -> the same inline {"error", "tag_status"} dict.
    (d) the producer's own ServiceResult.status.key.tag_status == MISSING_KEY.

    No ``report_key_status`` argument appears anywhere in this call chain —
    the producer always carries the key state in ``result.status``.
    """
    from memdiver.api.routers.inspect import present_inspect_http
    from memdiver.cli import present_inspect_cli
    from memdiver.core.service_result import Resolution
    from memdiver.mcp_server.presenters import present_inspect_mcp
    from memdiver.mcp_server.session import ToolSession
    from memdiver.mcp_server.tools_inspect import session_info_result

    msl_path, _keyfile = encrypted_msl
    session = ToolSession()

    # ONE core producer call.
    result = session_info_result(session, msl_path)

    # (d) the producer's own status.
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED
    hint = result.status.key.hint
    assert hint is not None

    # (a) API surface: payload only, locked reads back empty (region_count=0).
    http_payload = present_inspect_http(result)
    assert http_payload["region_count"] == 0
    for leaked_key in ("tag_status", "error", "_status", "status", "decrypted", "hint"):
        assert leaked_key not in http_payload

    # core hint is neutral — no surface-specific remedy leaks in.
    assert "--" not in hint
    assert "key_file" not in hint

    # (b) CLI surface: inline diagnostic, exit 1, augmented with the CLI flags.
    from memdiver.cli import _KEY_FLAGS_HINT
    from memdiver.mcp_server.presenters import _KEY_PARAMS_HINT

    cli_payload, exit_code, stderr_msg = present_inspect_cli(result)
    cli_expected = f"{hint}; {_KEY_FLAGS_HINT}"
    assert exit_code == 1
    assert cli_payload == {"error": cli_expected, "tag_status": "missing_key"}
    assert stderr_msg == cli_expected
    assert "--key-file" in cli_payload["error"]  # CLI flags sourced from cli.py

    # (c) MCP surface: same shape, but augmented with the MCP PARAMETER names.
    mcp_payload = present_inspect_mcp(result)
    mcp_expected = f"{hint}; {_KEY_PARAMS_HINT}"
    assert mcp_payload == {"error": mcp_expected, "tag_status": "missing_key"}
    # The CLI dash-flags never appear on the MCP surface, and vice versa.
    assert "--key-file" not in mcp_payload["error"]
    assert "key_file" in mcp_payload["error"]


def test_end_to_end_valid_key_four_surface_behaviors(encrypted_msl):
    """Symmetry check: with the correct key supplied, all three presenters
    pass the payload straight through with no diagnostic and the producer's
    own status reports OK/decrypted."""
    from memdiver.api.routers.inspect import present_inspect_http
    from memdiver.cli import present_inspect_cli
    from memdiver.core.service_result import Resolution
    from memdiver.mcp_server.presenters import present_inspect_mcp
    from memdiver.mcp_server.session import ToolSession
    from memdiver.mcp_server.tools_inspect import session_info_result

    msl_path, keyfile = encrypted_msl
    session = ToolSession()

    result = session_info_result(session, msl_path, key_file=keyfile)

    assert result.status.key.decrypted is True
    assert result.status.resolution == Resolution.OK
    assert result.payload["region_count"] == 1

    assert present_inspect_http(result) is result.payload
    cli_payload, exit_code, stderr_msg = present_inspect_cli(result)
    assert cli_payload is result.payload
    assert exit_code == 0
    assert stderr_msg is None
    assert present_inspect_mcp(result) is result.payload


# ===========================================================================
# STRUCTURAL invariants (added by the presentation-separation follow-up).
#
# The guards above are a denylist pinned to today's known offenders. The guards
# below are structural: they discover offenders instead of hardcoding them, so a
# NEW leak (a new surface, a new error-dict function, an aliased HTTPException)
# fails immediately. Where the codebase still has known residue, it is tracked
# in an explicit *ratchet baseline* that may only SHRINK — a fixed offender left
# in the baseline is flagged stale, so the list cannot rot.
# ===========================================================================


# ---------------------------------------------------------------------------
# Invariant 6 (ratchet) — no NEW presentation-shaped ``return {"error": ...}``
# from a non-deprecated function anywhere in app/. Remaining offenders are the
# G2 residue; each is removed from the baseline as its phase migrates it to a
# ServiceResult/CapabilityError.
# ---------------------------------------------------------------------------

_ERROR_DICT_FIRST_KEYS = {"error"}


def _app_error_dict_returns():
    """Discover ``(relpath, funcname)`` for every ``return {"error": ...}``
    inside a *non-deprecated* function under ``app/``. Innermost enclosing
    function wins; deprecated functions (docstring says so) are the sanctioned
    backward-compat carve-out and are excluded."""
    found = set()
    for path in sorted((ROOT / "app").rglob("*.py")):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        func_of = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                deprecated = "deprecated" in (ast.get_docstring(node) or "").lower()
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        func_of[child.lineno] = (node.name, deprecated)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Dict)
                and node.value.keys
            ):
                first = node.value.keys[0]
                if isinstance(first, ast.Constant) and first.value in _ERROR_DICT_FIRST_KEYS:
                    fn, deprecated = func_of.get(node.lineno, ("<module>", False))
                    if not deprecated:
                        found.add((path.relative_to(ROOT).as_posix(), fn))
    return found


# The G2 residue as of the follow-up audit. Phase 1 migrated every entry to a
# ServiceResult/CapabilityError, so the baseline is now empty and the guard is
# fully structural: any NEW presentation ``{"error": ...}`` return in app/ fails
# ``test_no_new_error_dict_leaks_in_app_layer`` immediately.
_KNOWN_APP_ERROR_DICT_LEAKS = frozenset()


def test_no_new_error_dict_leaks_in_app_layer():
    """No presentation-shaped ``{"error": ...}`` return outside the tracked
    baseline. New leaks must instead raise ``CapabilityError`` / return a
    ``ServiceResult``."""
    new = _app_error_dict_returns() - _KNOWN_APP_ERROR_DICT_LEAKS
    assert not new, (
        'NEW presentation {"error": ...} return(s) in app/ — route through a '
        "ServiceResult/CapabilityError instead:\n"
        + "\n".join(f"  {p}::{fn}" for p, fn in sorted(new))
    )


def test_known_error_dict_leak_baseline_is_not_stale():
    """The ratchet only tightens: once a baseline function stops leaking, it
    must be removed from ``_KNOWN_APP_ERROR_DICT_LEAKS``."""
    stale = _KNOWN_APP_ERROR_DICT_LEAKS - _app_error_dict_returns()
    assert not stale, (
        "These baseline entries no longer leak (good!) — delete them from "
        "_KNOWN_APP_ERROR_DICT_LEAKS so the ratchet keeps tightening:\n"
        + "\n".join(f"  {p}::{fn}" for p, fn in sorted(stale))
    )


# ---------------------------------------------------------------------------
# Invariant 7 — legacy dict functions unreachable from production, INCLUDING
# bare-import call sites (the old ``tools_inspect.<name>(`` regex gave zero
# coverage of cli.py, which imports the names bare).
# ---------------------------------------------------------------------------

_LEGACY_DICT_FUNCS = {
    "read_hex", "_read_hex_raw", "_resolve_va", "search_bytes",
    "get_session_info", "get_page_states", "get_processes",
    "get_modules", "get_handles",
}


def _production_surface_files():
    return [
        ROOT / "cli.py",
        ROOT / "mcp_server" / "server.py",
        ROOT / "mcp_server" / "presenters.py",
        ROOT / "api" / "main.py",
        *sorted((ROOT / "api" / "routers").rglob("*.py")),
    ]


def test_legacy_error_dict_functions_unreachable_including_bare_imports():
    """Stronger sibling of ``test_legacy_error_dict_functions_unreachable_from_production``:
    catches both ``tools_inspect.<name>(`` attribute calls AND bare-name calls of
    a name imported ``from ...tools_inspect import <name>`` (with or without an
    alias) — the form the CLI actually uses."""
    offenders = []
    for path in _production_surface_files():
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        # bare-name aliases: from <...tools_inspect> import <legacy> [as alias]
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith(
                "tools_inspect"
            ):
                for a in node.names:
                    if a.name in _LEGACY_DICT_FUNCS:
                        aliases[a.asname or a.name] = a.name
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr in _LEGACY_DICT_FUNCS
                and isinstance(f.value, ast.Name)
                and f.value.id.endswith("tools_inspect")
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} tools_inspect.{f.attr}(")
            elif isinstance(f, ast.Name) and f.id in aliases:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} {aliases[f.id]}( [bare]")
    assert offenders == [], "legacy dict function reachable from production:\n" + "\n".join(
        offenders
    )


# ---------------------------------------------------------------------------
# Invariant 8 — HTTPException never in a service layer, ALIAS-aware
# (``from fastapi import HTTPException as HExc``).
# ---------------------------------------------------------------------------

_SERVICE_DIRS = ["core", "engine", "app", str(Path("api") / "services")]


def test_no_aliased_httpexception_in_service_layers():
    """Complements ``test_no_httpexception_in_service_layers``: an aliased import
    (``from fastapi import HTTPException as X``) would evade the name/attr check,
    so flag any local alias of ``HTTPException`` used in a service layer."""
    offenders = []
    for path in _py_files(*_SERVICE_DIRS):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        alias_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "fastapi" in node.module:
                for a in node.names:
                    if a.name == "HTTPException" and a.asname:
                        alias_names.add(a.asname)
        if not alias_names:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in alias_names:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} (alias {node.id})")
    assert offenders == [], "aliased HTTPException in a service layer:\n" + "\n".join(offenders)


# ---------------------------------------------------------------------------
# Invariant 9 — no direct user-facing stream writes in service layers
# (``sys.stdout/stderr.write``, ``click.echo``) — the attribute-form output the
# bare-``print`` guard misses.
# ---------------------------------------------------------------------------


def test_no_stream_writes_in_service_layers():
    offenders = []
    for path in _py_files("core", "engine", "app"):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            func = node.func
            if (
                func.attr == "write"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr in {"stdout", "stderr"}
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} <stream>.write(")
            elif (
                func.attr == "echo"
                and isinstance(func.value, ast.Name)
                and func.value.id == "click"
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} click.echo(")
    assert offenders == [], "direct stream write in a service layer:\n" + "\n".join(offenders)


# ---------------------------------------------------------------------------
# Invariant 10 — report_key_status not referenced BY NAME in production (catches
# keyword args and dict-unpack that the ``report_key_status =`` textual guard
# misses). Docstring prose is a single large Constant, so mentions there do not
# trip this exact-value match.
# ---------------------------------------------------------------------------


def test_report_key_status_not_referenced_by_name_in_production():
    offenders = []
    for path in _production_surface_files():
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "report_key_status":
                lineno = getattr(node.value, "lineno", "?")
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} keyword report_key_status=")
            elif isinstance(node, ast.Constant) and node.value == "report_key_status":
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} literal 'report_key_status'")
    assert offenders == [], "report_key_status referenced by name in production:\n" + "\n".join(
        offenders
    )


# ---------------------------------------------------------------------------
# Invariant 11 — the one-producer -> multi-surface presenter split, WITHOUT the
# crypto backend. The flagship E2E tests skip when AES-256-GCM is absent; this
# builds a MISSING_KEY ServiceResult by hand so the presenter split is proven on
# every CI image.
# ---------------------------------------------------------------------------


def test_presenter_split_runs_without_crypto():
    from memdiver.api.routers.inspect import present_inspect_http
    from memdiver.cli import present_inspect_cli
    from memdiver.core.service_result import KeyStatus, ServiceResult
    from memdiver.mcp_server.presenters import present_inspect_mcp

    key = KeyStatus.from_source(_StubSource(TagStatus.MISSING_KEY))
    payload = {"region_count": 0}
    result = ServiceResult.ok(payload).with_key(key)

    # API drops the diagnostic — payload passes straight through, no status leak.
    http_payload = present_inspect_http(result)
    assert http_payload is payload
    for leaked in ("tag_status", "error", "status", "decrypted", "hint"):
        assert leaked not in http_payload

    # CLI + MCP inline the lock signal, each augmenting the neutral core hint
    # with its own surface-specific remedy (flags vs. parameters).
    from memdiver.cli import _KEY_FLAGS_HINT
    from memdiver.mcp_server.presenters import _KEY_PARAMS_HINT

    cli_payload, exit_code, stderr_msg = present_inspect_cli(result)
    cli_expected = f"{key.hint}; {_KEY_FLAGS_HINT}"
    assert exit_code == 1
    assert cli_payload == {"error": cli_expected, "tag_status": "missing_key"}
    assert stderr_msg == cli_expected
    assert present_inspect_mcp(result) == {
        "error": f"{key.hint}; {_KEY_PARAMS_HINT}",
        "tag_status": "missing_key",
    }
    # Flag text lives in the surfaces, not core.
    assert "--" not in key.hint


# ---------------------------------------------------------------------------
# Invariant 11b (G1) — no CLI flag / presentation text in core. The status
# envelope carries only neutral, surface-agnostic hints; each surface presenter
# renders its own remedy (CLI flags, MCP parameters). This scans every string
# literal under core/ for a CLI-flag token so presentation wording can never
# re-enter core.
# ---------------------------------------------------------------------------

_CLI_FLAG_RE = re.compile(r"--[a-z][a-z-]*")
_EXPLICIT_FLAG_TOKENS = ("--key-file", "--passphrase", "--kem-key-file")


def test_no_cli_flag_strings_in_core():
    offenders = []
    for path in sorted((ROOT / "core").rglob("*.py")):
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            text = node.value
            if any(tok in text for tok in _EXPLICIT_FLAG_TOKENS) or _CLI_FLAG_RE.search(text):
                rel = path.relative_to(ROOT).as_posix()
                offenders.append(f"{rel}:{node.lineno} {text!r}")
    assert offenders == [], (
        "CLI flag / presentation text found in core/ — move surface wording into "
        "the CLI/MCP presenters:\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Invariant 12 (parity) — every capability is reachable on every in-scope
# surface, all routed to the same producer. Consumes the capability registry
# introduced in Phase 5; skipped until it lands so the intent is tracked.
# ---------------------------------------------------------------------------


def _import_producer(dotted: str):
    """Import ``pkg.mod.func`` and return the ``func`` object."""
    import importlib

    module_path, _, attr = dotted.rpartition(".")
    module = importlib.import_module(module_path)
    return getattr(module, attr)


def test_capability_registry_producers_import_and_are_callable():
    """Every ``Capability.producer`` dotted path must resolve to a callable.

    A registry entry pointing at a renamed/removed producer is a silent lie
    about the wiring; this catches it at test time."""
    from memdiver.app.capabilities import CAPABILITIES

    broken = []
    for cap in CAPABILITIES:
        try:
            producer = _import_producer(cap.producer)
        except (ImportError, AttributeError) as exc:
            broken.append(f"{cap.name} -> {cap.producer}: {exc}")
            continue
        if not callable(producer):
            broken.append(f"{cap.name} -> {cap.producer}: not callable")
    assert broken == [], "capability producer(s) do not import/are not callable:\n" + "\n".join(
        broken
    )


def test_cross_surface_capability_parity():
    """RATCHET: every capability is wired on every in-scope surface, except a
    documented, non-stale set of gaps.

    Mirrors ``_KNOWN_APP_ERROR_DICT_LEAKS``: the raw gap set (in-scope surfaces
    a capability is NOT yet wired on) must equal ``KNOWN_PARITY_GAPS`` exactly.
    A NEW gap (an unwired capability/surface not in the baseline) fails the
    forward check; a STALE gap (a documented gap that has since been wired)
    fails the reverse check, so the baseline can only shrink."""
    from memdiver.app.capabilities import (
        IN_SCOPE_SURFACES,
        KNOWN_PARITY_GAPS,
        missing_wirings,
    )

    missing = missing_wirings()

    new_gaps = missing - KNOWN_PARITY_GAPS
    assert not new_gaps, (
        "NEW cross-surface parity gap(s) — wire the capability on the surface, "
        "or add it to KNOWN_PARITY_GAPS with justification:\n"
        + "\n".join(f"  {name} missing on {surface}" for name, surface in sorted(new_gaps))
    )

    stale_gaps = KNOWN_PARITY_GAPS - missing
    assert not stale_gaps, (
        "STALE parity gap(s) — these are now wired; delete them from "
        "KNOWN_PARITY_GAPS so the ratchet keeps tightening:\n"
        + "\n".join(f"  {name} on {surface}" for name, surface in sorted(stale_gaps))
    )

    # Guard the baseline against typos: every documented gap names a real
    # capability and an in-scope surface.
    cap_names = {c.name for c in __import__(
        "memdiver.app.capabilities", fromlist=["CAPABILITIES"]).CAPABILITIES}
    for name, surface in KNOWN_PARITY_GAPS:
        assert name in cap_names, f"KNOWN_PARITY_GAPS names unknown capability {name!r}"
        assert surface in IN_SCOPE_SURFACES, (
            f"KNOWN_PARITY_GAPS names out-of-scope surface {surface!r}"
        )


# ---------------------------------------------------------------------------
# Invariant 13 (G9) — the four pipeline producers that open a keyed container
# must SURFACE a locked (missing/wrong-key) dump rather than silently losing
# the key state and misreporting it as a genuine empty/negative result. Each
# is expected to raise EncryptedDumpLockedError. Crypto-fixture-gated like the
# flagship E2E tests (skips when AES-256-GCM is absent).
# ---------------------------------------------------------------------------


def test_g9_four_producers_surface_locked_dump(encrypted_msl, tmp_path):
    import numpy as np

    from memdiver.app import tools_pipeline
    from memdiver.core.service_errors import EncryptedDumpLockedError

    # A second encrypted .msl so the >=2-dump producers have a valid pair; both
    # are opened WITHOUT a key below, so both read back empty (locked).
    msl_path, _keyfile = encrypted_msl
    second = tmp_path / "second.msl"
    _write_encrypted_msl(second, os.urandom(32))
    pair = [msl_path, str(second)]

    with pytest.raises(EncryptedDumpLockedError):
        tools_pipeline.consensus(dump_paths=pair, output_dir=str(tmp_path / "c"))

    with pytest.raises(EncryptedDumpLockedError):
        tools_pipeline.export_pattern(dump_paths=pair, output_dir=str(tmp_path / "e"))

    with pytest.raises(EncryptedDumpLockedError):
        tools_pipeline.n_sweep(
            source_paths=pair,
            oracle_path=str(tmp_path / "unused_oracle.py"),
            output_dir=str(tmp_path / "n"),
            n_values=[2],
        )

    variance_path = tmp_path / "variance.npy"
    np.save(variance_path, np.zeros(64, dtype=np.float32))
    with pytest.raises(EncryptedDumpLockedError):
        tools_pipeline.auto_floor(
            variance_path=str(variance_path),
            reference_path=msl_path,
            oracle_path=str(tmp_path / "unused_oracle.py"),
            output_dir=str(tmp_path / "a"),
            num_dumps=2,
        )


# ---------------------------------------------------------------------------
# Cross-surface SIGNATURE parity (not just capability presence)
# ---------------------------------------------------------------------------
#: MCP pipeline tool -> backing app producer. The presence ratchet
#: (CAPABILITIES) proves each tool is *wired*; this proves each tool forwards
#: every *parameter* of its producer, catching the drift class where the MCP
#: brute_force tool silently lacked variance_threshold / key-material params.
_MCP_TOOL_PRODUCERS = {
    "search_reduce": "search_reduce",
    "brute_force": "brute_force",
    "n_sweep": "n_sweep",
    "emit_plugin": "emit_plugin",
    "consensus": "consensus",
    "auto_floor": "auto_floor",
    "export_pattern": "export_pattern",
    "verify": "verify_key_result",
    "experiment": "experiment_result",
}
#: Producer params that are orchestration internals, never surfaced on any tool.
#: ``key_material`` is the resolved dict a surface *builds* from the individual
#: key_file/passphrase/kem_key_file args, so it is never a direct tool param.
_INTERNAL_PRODUCER_PARAMS = {"on_progress", "on_source", "is_cancelled", "key_material"}
#: Real MCP-surface gaps the parity guard discovered — a shrink-only baseline
#: (same philosophy as capabilities.KNOWN_PARITY_GAPS). Each entry is a producer
#: parameter the MCP tool does not yet forward; close them as encrypted-reference
#: / feature support is intentionally added to that tool (brute_force already
#: closed its key-material gap). This dict may only shrink.
_MCP_ALLOWED_OMISSIONS: dict = {
    # Feature-design params not (yet) surfaced on MCP — a judgment call about the
    # tool's surface, not an encrypted-support bug. Close when intentionally added.
    "emit_plugin": {"min_static_ratio", "write_fields"},
    "consensus": {"persist_welford"},
}


def test_mcp_pipeline_tools_expose_all_producer_params():
    """Signature parity: every MCP pipeline tool forwards every parameter of its
    backing app producer (minus internal orchestration hooks), so a producer
    gaining a parameter can't silently leave the MCP surface behind."""
    import inspect

    pytest.importorskip("mcp")
    from memdiver.app import tools_pipeline
    from memdiver.mcp_server.server import create_server

    server = create_server()
    tools = {t.name: t for t in server._tool_manager.list_tools()}

    problems = []
    for tool_name, producer_attr in _MCP_TOOL_PRODUCERS.items():
        assert tool_name in tools, f"MCP tool {tool_name!r} is not registered"
        producer = getattr(tools_pipeline, producer_attr)
        tool_params = set(inspect.signature(tools[tool_name].fn).parameters)
        producer_params = {
            name for name, p in inspect.signature(producer).parameters.items()
            if p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)
        }
        expected = (producer_params - _INTERNAL_PRODUCER_PARAMS
                    - _MCP_ALLOWED_OMISSIONS.get(tool_name, set()))
        missing = expected - tool_params
        if missing:
            problems.append(f"  {tool_name}: MCP tool omits producer params {sorted(missing)}")
    assert not problems, "MCP signature-parity drift:\n" + "\n".join(problems)
