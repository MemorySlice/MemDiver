"""Library-surface parity proof (Phase 6, G6).

These tests pin the promise that MemDiver's Python *library* surface reaches the
whole feature set — the same surface-agnostic ``app`` producers the CLI, web and
MCP surfaces route to — and that a producer called via the supported public API
returns a status-carrying ``ServiceResult`` (or raises a typed
``CapabilityError``), never a bare ``{"error": ...}`` dict.

They deliberately touch only the public ``import memdiver`` surface plus the
``memdiver.services`` facade, so they stay independent of any concurrently-edited
surface files (``run.py``, ``ui/``, ``frontend/``, ``api/main.py``).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import memdiver  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.core.service_result import Resolution, ServiceResult, StatusBlock  # noqa: E402


# The producers the facade must expose, grouped as they appear in the registry.
_INSPECT_PRODUCERS = [
    "read_hex_result", "read_hex_raw_result", "resolve_va_result",
    "search_bytes_result", "entropy_result", "strings_result",
    "detect_format_result", "session_info_result", "page_states_result",
    "processes_result", "modules_result", "handles_result",
    "connections_result", "module_index_result", "blocks_result",
]
_XREF_PRODUCERS = [
    "get_cross_references_result", "identify_structure_result",
    "apply_structure_result",
]
_PIPELINE_PRODUCERS = [
    "consensus", "search_reduce", "brute_force", "n_sweep", "auto_floor",
    "emit_plugin", "export_pattern", "verify_key_result", "experiment_result",
]
_DATASET_PRODUCERS = [
    "scan_dataset", "list_protocols", "list_phases", "analyze_library",
    "import_dump",
]
_ALL_PRODUCERS = (
    _INSPECT_PRODUCERS + _XREF_PRODUCERS + _PIPELINE_PRODUCERS + _DATASET_PRODUCERS
)


# --- (a) the public API exposes the producers / memdiver.services ----------


def test_services_module_is_public():
    """``import memdiver`` exposes the ``services`` facade in ``__all__``."""
    assert hasattr(memdiver, "services")
    assert "services" in memdiver.__all__


@pytest.mark.parametrize("name", _ALL_PRODUCERS)
def test_producer_reachable_via_services(name):
    """Every ``app`` producer is re-exported on ``memdiver.services`` and is
    callable — the whole feature set, not a reduced subset."""
    assert name in memdiver.services.__all__, f"{name} missing from services.__all__"
    assert callable(getattr(memdiver.services, name))


def test_key_producers_lifted_to_top_level():
    """The most-used producers are lifted onto the ``memdiver`` top level and are
    the SAME objects as on the facade (single source of truth)."""
    lifted = [n for n in _ALL_PRODUCERS if n != "import_dump"]
    for name in lifted:
        assert name in memdiver.__all__, f"{name} not lifted to memdiver.__all__"
        assert getattr(memdiver, name) is getattr(memdiver.services, name)


def test_toolsession_exported():
    """``memdiver.ToolSession`` lets a caller drive the session-based producers."""
    assert "ToolSession" in memdiver.__all__
    assert isinstance(memdiver.ToolSession(), memdiver.services.ToolSession)


def test_top_level_import_dump_remains_the_primitive():
    """Lifting the producers must NOT clobber the existing ``memdiver.import_dump``
    primitive (the ``msl.importer`` one); the app producer stays on the facade."""
    assert memdiver.import_dump.__module__ == "memdiver.msl.importer"
    assert memdiver.services.import_dump.__module__ == "memdiver.app.tools"


# --- (b) a producer called via the public API returns a ServiceResult -------


@pytest.fixture
def plain_dump(tmp_path):
    """A plain (non-MSL) dump with a printable string, for the keyless path."""
    p = tmp_path / "sample.dump"
    p.write_bytes(b"hello world\x00" + bytes(range(256)) * 4)
    return str(p)


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


def test_entropy_producer_returns_service_result_with_status(plain_dump):
    """A producer reached purely through the public API returns a
    ``ServiceResult`` carrying a ``StatusBlock``."""
    session = memdiver.ToolSession()
    result = memdiver.entropy_result(session, plain_dump)

    assert isinstance(result, ServiceResult)
    assert isinstance(result.status, StatusBlock)
    assert result.status.resolution == Resolution.OK
    assert "overall_entropy" in result.payload


def test_session_info_producer_returns_service_result(tmp_path):
    """The structured MSL producer likewise returns a status-carrying
    ``ServiceResult`` when driven through ``memdiver.services``."""
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)

    session = memdiver.services.ToolSession()
    result = memdiver.services.session_info_result(session, str(msl))

    assert isinstance(result, ServiceResult)
    assert isinstance(result.status, StatusBlock)
    assert result.status.resolution == Resolution.OK
    assert result.payload["region_count"] == 1


def test_producer_raises_capability_error_not_error_dict():
    """Hard errors surface as a typed ``CapabilityError`` through the public API,
    never as a bare ``{"error": ...}`` dict."""
    session = memdiver.ToolSession()
    with pytest.raises(CapabilityError):
        memdiver.entropy_result(session, "/no/such/file.dump")


# --- (c) every __all__ name imports cleanly (no dangling names) -------------


def test_no_dangling_names_in_top_level_all():
    dangling = [n for n in memdiver.__all__ if not hasattr(memdiver, n)]
    assert dangling == [], f"dangling names in memdiver.__all__: {dangling}"


def test_no_dangling_names_in_services_all():
    dangling = [n for n in memdiver.services.__all__ if not hasattr(memdiver.services, n)]
    assert dangling == [], f"dangling names in memdiver.services.__all__: {dangling}"


def test_services_covers_every_registry_capability_producer():
    """Every in-scope capability producer in the registry is reachable through
    the public library facade — the parity claim is honest, not aspirational."""
    from memdiver.app.capabilities import CAPABILITIES

    facade_targets = {
        getattr(memdiver.services, n) for n in memdiver.services.__all__
    }
    missing = []
    for cap in CAPABILITIES:
        if "library" not in cap.surfaces:
            continue
        module_path, _, attr = cap.producer.rpartition(".")
        import importlib

        producer = getattr(importlib.import_module(module_path), attr)
        if producer not in facade_targets:
            missing.append(f"{cap.name} -> {cap.producer}")
    assert missing == [], (
        "registry marks these capabilities library-wired but they are NOT on the "
        "public memdiver.services facade:\n" + "\n".join(missing)
    )
