"""Tests for :class:`core.dump_sources.gcore.GCoreDumpSource`."""

from __future__ import annotations

import pytest

from core.dump_source import open_dump
from core.dump_sources.gcore import GCoreDumpSource
from tests._paths import SKIP_REASON, dataset_root


def _gcore_path():
    root = dataset_root()
    if root is None:
        return None
    p = (
        root / "dataset_memory_slice" / "gocryptfs"
        / "dataset_gocryptfs" / "run_0001" / "gcore.core"
    )
    return p if p.is_file() else None


def test_gcore_dispatch() -> None:
    """``open_dump`` must pick the gcore branch for an ELF ET_CORE file."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    source = open_dump(path)
    try:
        assert isinstance(source, GCoreDumpSource)
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()


def test_iter_ranges_covers_content() -> None:
    """PT_LOAD segments cover a non-zero virtual footprint."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        spans = [(start, end) for start, end, _ in src.iter_ranges(view="vas")]
    assert spans, "expected at least one PT_LOAD segment with content"
    total = sum(end - start for start, end in spans)
    assert total > 0


def test_read_range_raw_prefix() -> None:
    """``read_range(0, 16, view="raw")`` returns bytes that start with ELF magic."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        header = src.read_range(0, 16, view="raw")
    assert len(header) == 16
    assert header.startswith(b"\x7fELF")


def test_metadata_shape() -> None:
    """``metadata()`` advertises the gcore format and basic PT_LOAD info."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        meta = src.metadata()
    assert meta["format"] == "gcore"
    assert meta["region_count"] > 0
    assert meta["raw_size"] > 0
    assert isinstance(meta.get("modules"), list)


def test_va_to_file_offset_roundtrip() -> None:
    """Every PT_LOAD start VA maps back through ``va_to_file_offset``."""
    path = _gcore_path()
    if path is None:
        pytest.skip(SKIP_REASON)

    with GCoreDumpSource(path) as src:
        checked = 0
        for start, _end, file_off in src.iter_ranges(view="vas"):
            assert src.va_to_file_offset(start) == file_off
            checked += 1
            if checked >= 5:
                break
        assert checked > 0
