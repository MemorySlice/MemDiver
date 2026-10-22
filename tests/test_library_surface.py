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
    "detect_format_result", "analyze_region_result",
    "session_info_result", "page_states_result",
    "processes_result", "modules_result", "handles_result",
    "connections_result", "module_index_result", "blocks_result",
    "import_provenance_result",
]
_XREF_PRODUCERS = [
    "get_cross_references_result", "identify_structure_result",
    "apply_structure_result",
]
_PIPELINE_PRODUCERS = [
    "consensus", "analyze_candidates", "search_reduce", "brute_force",
    "n_sweep", "auto_floor",
    "emit_plugin", "export_pattern", "manual_export_pattern",
    "verify_key_result", "experiment_result",
    # B1/B3 — the key-location spine.
    "locate_key", "export_key_pattern",
    # C3 — the paired field search built on top of it.
    "locate_field_across_pairs",
    # D1 — running an emitted YARA rule, the other half of export_pattern.
    "scan_yara_rule",
    # D2 — scoring what D1 found against known-true key intervals.
    "score_detector_matches",
    # D3 — running the Volatility3 plugin we emit, the other half of
    # emit_plugin / export_pattern's vol3 format.
    "verify_vol3_plugin",
]
_DATASET_PRODUCERS = [
    "scan_dataset", "list_protocols", "list_phases", "analyze_library",
    "import_dump", "preview_import",
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
    lifted = [n for n in _ALL_PRODUCERS
              if n not in ("import_dump", "preview_import")]
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


# --- import-time region selection surface ----------------------------------


_SELECTION_NAMES = ["preview_import", "RegionSelection", "RegionCategory",
                    "parse_selection"]


@pytest.mark.parametrize("name", _SELECTION_NAMES)
def test_region_selection_names_exported(name):
    """Selection types + preview are public on both memdiver and services."""
    assert name in memdiver.__all__
    assert name in memdiver.services.__all__
    assert getattr(memdiver, name) is not None


def test_top_level_preview_import_is_the_primitive():
    """Like import_dump: top level = msl primitive, services = session tool."""
    assert memdiver.preview_import.__module__ == "memdiver.msl.import_preview"
    assert memdiver.services.preview_import.__module__ == "memdiver.app.tools"
    assert memdiver.RegionSelection is memdiver.services.RegionSelection


def test_services_import_dump_accepts_selection(tmp_path):
    from tests.fixtures import synth_elf_core
    core = tmp_path / "t.core"
    core.write_bytes(synth_elf_core.build_core_bytes())
    session = memdiver.ToolSession()
    preview = memdiver.services.preview_import(session, str(core),
                                               selection="heap")
    assert preview["format"] == "elf_core"
    by_str = memdiver.services.import_dump(
        session, str(core), str(tmp_path / "a.msl"), selection="heap,stack")
    by_obj = memdiver.services.import_dump(
        session, str(core), str(tmp_path / "b.msl"),
        selection=memdiver.parse_selection("heap,stack"))
    assert by_str["selection"] == by_obj["selection"] == "regions=heap,stack"
    assert by_str["regions_written"] == by_obj["regions_written"]
    plain = memdiver.services.import_dump(session, str(core),
                                          str(tmp_path / "c.msl"))
    assert "selection" not in plain


def test_services_import_dump_bad_selection_is_capability_error(tmp_path):
    raw = tmp_path / "r.dump"
    raw.write_bytes(b"\x00" * 64)
    with pytest.raises(CapabilityError):
        memdiver.services.import_dump(memdiver.ToolSession(), str(raw),
                                      str(tmp_path / "r.msl"),
                                      selection="nope")
