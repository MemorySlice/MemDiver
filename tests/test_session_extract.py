"""Tests for MSL session report extraction."""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.session_extract import (
    SessionReport,
    _safe_enum_name,
    extract_session_from_path,
    extract_session_report,
)
from msl.enums import ArchType, OSType
from msl.reader import MslReader
from tests.fixtures.generate_msl_fixtures import (
    ensure_msl_fixtures,
    generate_msl_file,
    _build_file_header,
    _build_end_of_capture,
    _build_memory_region,
)

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "dataset"


@pytest.fixture
def msl_path():
    ensure_msl_fixtures(FIXTURES_ROOT)
    return FIXTURES_ROOT / "msl" / "test_capture.msl"


def test_extract_session_report_basic(msl_path):
    """Full round-trip: extract session report from fixture."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert isinstance(report, SessionReport)
    assert report.pid == 1234
    assert report.os_type == "LINUX"
    assert report.arch_type == "X86_64"
    assert report.region_count >= 1
    assert report.key_hint_count >= 1


def test_session_report_timestamp_iso(msl_path):
    """ISO timestamp formatting works."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    iso = report.timestamp_iso
    assert "T" in iso
    assert "+" in iso or "Z" in iso


def test_session_report_total_captured(msl_path):
    """Captured bytes = captured_page_count * 4096."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert report.total_captured_bytes == report.captured_page_count * 4096


def test_session_report_modules(msl_path):
    """Module list populated from fixture."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert len(report.modules) >= 1
    assert report.modules[0].path == "/usr/lib/libssl.so"


def test_session_report_related_dumps(msl_path):
    """Related dumps populated from fixture."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert len(report.related_dumps) >= 1
    assert report.related_dumps[0].related_pid == 5678


def test_session_report_vas_entries(msl_path):
    """VAS entries populated from fixture."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert len(report.vas_entries) == 3
    types = [e.region_type for e in report.vas_entries]
    assert 0x01 in types  # HEAP
    assert 0x02 in types  # STACK
    assert 0x03 in types  # IMAGE


def test_session_report_key_hints_by_type(msl_path):
    """Phase B1: SessionReport exposes per-type key hint counts."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    # Fixture's _build_key_hint defaults key_type=0x0003 (SESSION_KEY)
    assert isinstance(report.key_hints_by_type, dict)
    assert sum(report.key_hints_by_type.values()) == report.key_hint_count
    # At least one categorized bucket when fixture has any hint
    if report.key_hint_count > 0:
        assert len(report.key_hints_by_type) >= 1


def test_session_report_vas_coverage(msl_path):
    """Phase B1: SessionReport buckets VAS entries by region type name."""
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert isinstance(report.vas_coverage, dict)
    # Counts in coverage dict match total vas_entries length
    assert sum(report.vas_coverage.values()) == len(report.vas_entries)
    # Fixture has HEAP, STACK, IMAGE
    assert "HEAP" in report.vas_coverage
    assert "STACK" in report.vas_coverage
    assert "IMAGE" in report.vas_coverage


def test_session_report_string_extraction_opt_in(msl_path):
    """Phase B1: string extraction is opt-in via include_strings=True."""
    # Default: no strings
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader)
    assert report.string_count == 0
    assert report.string_summary is None

    # Opt-in: populate string_summary + string_count
    with MslReader(msl_path) as reader:
        report = extract_session_report(reader, include_strings=True)
    # String extraction may return 0 matches for synthetic fixture data;
    # the important assertion is that string_summary is populated (not None)
    assert report.string_summary is not None
    assert report.string_count == report.string_summary.total_count


def test_session_report_no_process_identity():
    """Graceful None when no process identity block."""
    import random
    rng = random.Random(99)
    dump_uuid = bytes(rng.getrandbits(8) for _ in range(16))
    blob = _build_file_header(dump_uuid, 1_700_000_000_000_000_000)
    region_block, _ = _build_memory_region()
    blob += region_block
    eoc, _ = _build_end_of_capture(1_700_000_001_000_000_000)
    blob += eoc

    with tempfile.NamedTemporaryFile(suffix=".msl", delete=False) as f:
        f.write(blob)
        tmp_path = Path(f.name)

    try:
        with MslReader(tmp_path) as reader:
            report = extract_session_report(reader)
        assert report.process_identity is None
        assert report.region_count >= 1
    finally:
        tmp_path.unlink()


def test_extract_session_from_path(msl_path):
    """Convenience function opens, extracts, and closes."""
    report = extract_session_from_path(msl_path)
    assert isinstance(report, SessionReport)
    assert report.pid == 1234


def test_safe_enum_name_valid():
    """Known enum value returns name."""
    assert _safe_enum_name(OSType, 0x0001) == "LINUX"
    assert _safe_enum_name(ArchType, 0x0001) == "X86_64"


def test_safe_enum_name_invalid():
    """Unknown enum value returns UNKNOWN."""
    assert _safe_enum_name(OSType, 0x9999) == "UNKNOWN"
