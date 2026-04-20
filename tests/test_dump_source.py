"""Tests for core/dump_source.py — DumpSource implementations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from core.dump_source import MslDumpSource, RawDumpSource, open_dump
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def raw_path(tmp_path):
    p = tmp_path / "test.dump"
    p.write_bytes(b"\xAA" * 512 + b"\xBB" * 512)
    return p


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


class TestRawDumpSource:
    def test_format_name(self, raw_path):
        src = RawDumpSource(raw_path)
        assert src.format_name == "raw"
        assert src.path == raw_path

    def test_read_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            data = src.read_all()
            assert len(data) == 1024
            assert data[:512] == b"\xAA" * 512

    def test_read_range(self, raw_path):
        with RawDumpSource(raw_path) as src:
            chunk = src.read_range(500, 24)
            assert len(chunk) == 24

    def test_find_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            offsets = src.find_all(b"\xAA\xAA\xAA\xAA")
            assert len(offsets) > 0
            assert offsets[0] == 0

    def test_iter_ranges(self, raw_path):
        with RawDumpSource(raw_path) as src:
            ranges = list(src.iter_ranges())
            assert len(ranges) == 1
            vaddr, length, data = ranges[0]
            assert vaddr == 0
            assert length == 1024

    def test_metadata(self, raw_path):
        src = RawDumpSource(raw_path)
        meta = src.metadata()
        assert meta["format"] == "raw"

    def test_size(self, raw_path):
        with RawDumpSource(raw_path) as src:
            assert src.size == 1024


class TestMslDumpSource:
    def test_format_name(self, msl_path):
        src = MslDumpSource(msl_path)
        assert src.format_name == "msl"

    def test_read_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            data = src.read_all()
            assert len(data) > 0

    def test_iter_ranges(self, msl_path):
        with MslDumpSource(msl_path) as src:
            ranges = list(src.iter_ranges())
            assert len(ranges) >= 1
            vaddr, length, data = ranges[0]
            assert vaddr == 0x7FFF00000000
            assert length == 4096

    def test_metadata(self, msl_path):
        with MslDumpSource(msl_path) as src:
            meta = src.metadata()
            assert meta["format"] == "msl"
            assert meta["pid"] == 1234

    def test_find_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            # Page data starts with b"\xAA" * 32
            offsets = src.find_all(b"\xAA\xAA\xAA\xAA")
            assert len(offsets) > 0


class TestOpenDump:
    def test_auto_detect_raw(self, raw_path):
        src = open_dump(raw_path)
        assert isinstance(src, RawDumpSource)

    def test_auto_detect_msl(self, msl_path):
        src = open_dump(msl_path)
        assert isinstance(src, MslDumpSource)


class TestMslViewModes:
    """Regression tests for the raw-vs-VAS view split.

    Before Phase 25, the hex viewer always read through the VAS
    projection and offset 0 of a .msl file showed the first captured
    page's bytes (often an ELF header from a module) instead of the
    MSL container's ``MEMSLICE`` magic. These tests pin both views.
    """

    def test_raw_view_starts_with_msl_magic(self, msl_path):
        from msl.enums import FILE_MAGIC
        with MslDumpSource(msl_path) as src:
            head = src.read_range(0, len(FILE_MAGIC), view="raw")
            assert head == FILE_MAGIC

    def test_vas_view_matches_captured_page(self, msl_path):
        with MslDumpSource(msl_path) as src:
            # The generate_msl_file fixture pads captured pages with
            # 0xAA, so the VAS projection at offset 0 must start that
            # way — not with the MSL magic.
            head = src.read_range(0, 4, view="vas")
            assert head == b"\xAA\xAA\xAA\xAA"

    def test_size_for_raw_and_vas_differ(self, msl_path):
        with MslDumpSource(msl_path) as src:
            raw = src.size_for("raw")
            vas = src.size_for("vas")
            assert raw == msl_path.stat().st_size
            # Header + block headers + hash chain wrap the payload, so
            # the container is strictly larger than the flat projection.
            assert raw > vas > 0

    def test_default_size_stays_vas_for_scanners(self, msl_path):
        """The bare ``.size`` property must keep its historical VAS
        semantics — lots of scanner code reads it directly."""
        with MslDumpSource(msl_path) as src:
            assert src.size == src.size_for("vas")

    def test_unknown_view_raises(self, msl_path):
        with MslDumpSource(msl_path) as src:
            with pytest.raises(ValueError):
                src.read_range(0, 4, view="garbage")

    def test_va_to_vas_offset_first_region(self, msl_path):
        with MslDumpSource(msl_path) as src:
            regions = src.get_reader().collect_regions()
            assert regions, "fixture must have at least one region"
            first = regions[0]
            assert src.va_to_vas_offset(first.base_addr) == 0

    def test_va_to_vas_offset_out_of_range(self, msl_path):
        with MslDumpSource(msl_path) as src:
            assert src.va_to_vas_offset(0xDEADBEEF00000000) is None

    def test_va_to_file_offset_points_to_block_header(self, msl_path):
        """A module's VA should translate to the file offset of a real
        block header — the first 4 bytes there must be the MSLC block
        magic."""
        from msl.enums import BLOCK_MAGIC
        with MslDumpSource(msl_path) as src:
            regions = src.get_reader().collect_regions()
            assert regions
            va = regions[0].base_addr
            file_off = src.va_to_file_offset(va)
            assert file_off is not None
            head = src.read_range(file_off, 4, view="raw")
            assert head == BLOCK_MAGIC
