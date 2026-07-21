"""Facade test for the presentation-separation refactor (Phase 4).

The surface-agnostic service modules were physically relocated from
``memdiver.mcp_server.*`` to ``memdiver.app.*``. The old paths are kept as
re-export shims so existing imports keep working. These tests assert that:

1. Both the old and new import paths resolve to the SAME object (identity),
   for public *and* underscore-prefixed callable symbols that callers use.
2. Both ``import memdiver.mcp_server.<name>`` and
   ``from memdiver.mcp_server.<name> import <sym>`` styles keep working.
3. The additive neutral library exports are importable from ``memdiver``.
"""

import importlib

import pytest

# Relocated modules and a representative set of public + underscored symbols
# that live import sites depend on.
_MODULES = {
    "tools_inspect": [
        "read_hex",
        "read_hex_result",
        "get_entropy",
        "search_bytes_result",
        "get_session_info",
        "_read_hex_raw",
        "_resolve_va",
        "_extract_strings",
        "_tag_status_error",
        "_finalize_inspect",
        "TAIL_OVERLAP",
    ],
    "tools_pipeline": [
        "search_reduce",
        "brute_force",
        "consensus",
        "auto_floor",
    ],
    "tools_xref": [
        "get_cross_references",
        "identify_structure",
    ],
    "tools": [
        "analyze_library",
        "import_dump",
        "list_protocols",
    ],
    "session": [
        "ToolSession",
    ],
    "key_material": [
        "key_material_kwargs",
        "open_dump_source",
        "open_msl_reader",
        "has_key_material",
    ],
}


@pytest.mark.parametrize("name", list(_MODULES))
def test_module_identity(name):
    """The old shim module IS the new relocated module object."""
    old = importlib.import_module(f"memdiver.mcp_server.{name}")
    new = importlib.import_module(f"memdiver.app.{name}")
    assert old is new, f"{name}: shim did not alias the relocated module"


@pytest.mark.parametrize(
    "name,symbol",
    [(name, sym) for name, syms in _MODULES.items() for sym in syms],
)
def test_symbol_identity(name, symbol):
    """Each public/underscored symbol is the SAME object via both paths."""
    old = importlib.import_module(f"memdiver.mcp_server.{name}")
    new = importlib.import_module(f"memdiver.app.{name}")
    assert getattr(old, symbol) is getattr(new, symbol), (
        f"{name}.{symbol} differs across old/new import paths"
    )


def test_from_import_underscored_name():
    """``from memdiver.mcp_server.<mod> import _private`` keeps working."""
    from memdiver.mcp_server.tools_inspect import _read_hex_raw as old_raw
    from memdiver.app.tools_inspect import _read_hex_raw as new_raw

    assert old_raw is new_raw


def test_from_package_import_module():
    """``from memdiver.mcp_server import <mod>`` binds the relocated module."""
    from memdiver.mcp_server import tools as old_tools
    from memdiver.app import tools as new_tools

    assert old_tools is new_tools


def test_library_service_result_exports():
    """Neutral result/error types are importable from the top-level package."""
    from memdiver import (  # noqa: F401
        CapabilityError,
        Diagnostic,
        ErrorCategory,
        KeyStatus,
        Resolution,
        ServiceResult,
        StatusBlock,
    )

    import memdiver

    for name in (
        "ServiceResult",
        "StatusBlock",
        "KeyStatus",
        "Diagnostic",
        "Resolution",
        "CapabilityError",
        "ErrorCategory",
    ):
        assert name in memdiver.__all__, f"{name} missing from memdiver.__all__"
