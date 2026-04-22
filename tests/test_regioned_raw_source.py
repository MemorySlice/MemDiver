"""Tests for :class:`core.dump_sources._regioned_base._RegionedRawSource`
and the gdb/lldb dispatchers."""

from pathlib import Path

import pytest

from core.dump_source import open_dump
from core.dump_sources.gdb_raw import GdbRawDumpSource
from core.dump_sources.lldb_raw import LldbRawDumpSource


_DATASET_RUN = Path(
    "/Users/danielbaier/research/projects/github/issues/"
    "2024 fritap issues/2026_success/mempdumps/dataset_memory_slice/"
    "gocryptfs/dataset_gocryptfs/run_0001"
)
_GDB_BIN = _DATASET_RUN / "gdb_raw.bin"
_LLDB_BIN = _DATASET_RUN / "lldb_raw.bin"


def _assert_source_behaves(source, expected_format: str) -> None:
    raw_size = source.size_for("raw")
    vas_size = source.size_for("vas")
    assert raw_size > 0
    assert vas_size > 0
    assert source.size == raw_size

    head = source.read_range(0, 16, view="raw")
    assert len(head) == 16

    head_vas = source.read_range(0, 16, view="vas")
    assert len(head_vas) == 16
    # First bytes of the bin *are* the first bytes of VAS in this layout.
    assert head_vas == head

    ranges = list(source.iter_ranges("vas"))
    assert ranges, "must yield at least one captured region"
    for start_va, end_va, file_offset in ranges:
        assert end_va > start_va
        assert file_offset >= 0
        assert file_offset < raw_size

    # First region: VA translation round-trip.
    first_start, _first_end, first_off = ranges[0]
    assert source.va_to_file_offset(first_start) == first_off
    assert source.va_to_vas_offset(first_start) == first_off
    assert source.va_to_file_offset(first_start - 1) is None

    meta = source.metadata()
    assert meta["format"] == expected_format
    assert meta["raw_size"] == raw_size
    assert meta["vas_size"] == vas_size
    assert meta["region_count"] >= meta["captured_regions"] > 0
    assert meta["padding_bytes"] == raw_size - vas_size


@pytest.mark.skipif(not _GDB_BIN.exists(), reason="gdb_raw.bin dataset missing")
def test_gdb_raw_opens_and_serves() -> None:
    with GdbRawDumpSource(_GDB_BIN) as source:
        _assert_source_behaves(source, "gdb_raw")


@pytest.mark.skipif(not _LLDB_BIN.exists(), reason="lldb_raw.bin dataset missing")
def test_lldb_raw_opens_and_serves() -> None:
    with LldbRawDumpSource(_LLDB_BIN) as source:
        _assert_source_behaves(source, "lldb_raw")


@pytest.mark.skipif(not _GDB_BIN.exists(), reason="gdb_raw.bin dataset missing")
def test_open_dump_dispatches_gdb_raw() -> None:
    with open_dump(_GDB_BIN) as source:
        assert isinstance(source, GdbRawDumpSource)
        assert source.metadata()["format"] == "gdb_raw"


@pytest.mark.skipif(not _LLDB_BIN.exists(), reason="lldb_raw.bin dataset missing")
def test_open_dump_dispatches_lldb_raw() -> None:
    with open_dump(_LLDB_BIN) as source:
        assert isinstance(source, LldbRawDumpSource)
        assert source.metadata()["format"] == "lldb_raw"


@pytest.mark.skipif(not _GDB_BIN.exists(), reason="gdb_raw.maps dataset missing")
def test_open_dump_resolves_maps_sidecar_to_bin() -> None:
    maps_path = _DATASET_RUN / "gdb_raw.maps"
    with open_dump(maps_path) as source:
        assert isinstance(source, GdbRawDumpSource)


def test_missing_maps_raises(tmp_path: Path) -> None:
    bogus = tmp_path / "fake.gdb_raw.bin"
    bogus.write_bytes(b"\x00" * 16)
    src = GdbRawDumpSource(bogus)
    with pytest.raises(FileNotFoundError):
        src.open()
