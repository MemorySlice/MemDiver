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

    # (b) CLI surface: inline diagnostic, exit 1.
    cli_payload, exit_code, stderr_msg = present_inspect_cli(result)
    assert exit_code == 1
    assert cli_payload == {"error": hint, "tag_status": "missing_key"}
    assert stderr_msg == hint

    # (c) MCP surface: the same inline diagnostic shape.
    mcp_payload = present_inspect_mcp(result)
    assert mcp_payload == {"error": hint, "tag_status": "missing_key"}


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
