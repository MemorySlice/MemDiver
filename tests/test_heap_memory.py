"""Tests for heap/memory.py: VA reads over every dump source + strip_tag."""

import struct
from pathlib import Path

import pytest

from memdiver.core.dump_source import MslDumpSource, RawDumpSource
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
from memdiver.heap.memory import VaMemory, strip_tag
from memdiver.heap.platform import ASSUMED_PLATFORM, TargetPlatform
from tests.fixtures import synth_elf_core, synth_raw_regions
from tests.fixtures.generate_msl_fixtures import write_aslr_fixture

ANDROID_MSL = Path(__file__).parent / "fixtures" / "android" / "memslicer_android.msl"
ARM64 = TargetPlatform("android", "arm64", 8, "little", "test")
BIG32 = TargetPlatform("unknown", "arm32", 4, "big", "test")


@pytest.fixture
def gdb_raw(tmp_path):
    run = synth_raw_regions.build(tmp_path)
    with GdbRawDumpSource(run / "gdb_raw.bin", run / "gdb_raw.maps") as src:
        yield src


@pytest.fixture
def gcore(tmp_path):
    run = synth_elf_core.build(tmp_path)
    with GCoreDumpSource(run / "gcore.core") as src:
        yield src


@pytest.fixture
def raw(tmp_path):
    path = tmp_path / "flat.dump"
    path.write_bytes(bytes(range(256)))
    with RawDumpSource(path) as src:
        yield src


# -- strip_tag ------------------------------------------------------------------


def test_strip_tag_arm64_clears_top_byte():
    assert strip_tag(0xB400007A12345678, ARM64) == 0x0000007A12345678


def test_strip_tag_other_arch_untouched():
    assert strip_tag(0xB400007A12345678, ASSUMED_PLATFORM) == 0xB400007A12345678
    assert strip_tag(0x1234, None) == 0x1234


# -- MSL (sparse "va" view) -----------------------------------------------------


def test_msl_read_matches_vas_bytes():
    with MslDumpSource(ANDROID_MSL) as src:
        mem = VaMemory(src)
        va = 0x7A00000000  # [anon:scudo:primary]
        vas = src.va_to_vas_offset(va)
        assert mem.read(va, 64) == src.read_range(vas, 64, view="vas")
        assert mem.va_to_view_offset(va) == vas
        assert mem.view_offset_to_va(vas) == va
        assert mem.u64(va) == struct.unpack("<Q", src.read_range(vas, 8))[0]


def test_msl_read_uncaptured_returns_none():
    with MslDumpSource(ANDROID_MSL) as src:
        mem = VaMemory(src)
        end = 0x7A00000000 + 4096
        assert mem.read(end - 4, 4) is not None
        assert mem.read(end - 4, 8) is None       # tail runs into a gap
        assert mem.read(end + 0x100, 1) is None   # inside the gap
        assert mem.read(0x10, 8) is None          # below the span
        assert mem.ptr(end) is None


def test_msl_va_view_translation():
    with MslDumpSource(ANDROID_MSL) as src:
        mem = VaMemory(src)
        start = src.va_span_start()
        assert mem.va_to_view_offset(start + 0x10, "va") == 0x10
        assert mem.view_offset_to_va(0x10, "va") == start + 0x10
        assert mem.view_offset_to_va(src.size_for("va"), "va") is None
        assert mem.va_to_view_offset(0x7A00000000, "raw") is None


def test_msl_region_filter_hides_excluded_regions():
    with MslDumpSource(ANDROID_MSL, region_filter="stack") as src:
        mem = VaMemory(src)
        assert mem.read(0x7A00000000, 8) is None   # scudo heap filtered out


def test_msl_regions_property():
    with MslDumpSource(ANDROID_MSL) as src:
        mem = VaMemory(src)
        assert mem.platform.arch == "arm64"
        assert len(mem.regions) == 13


def test_msl_linux_fixture_planted_key(tmp_path):
    key = bytes(range(32))
    path = write_aslr_fixture(tmp_path / "k.msl", region_base=0x7F0000000000,
                              key_bytes=key)
    with MslDumpSource(path) as src:
        assert VaMemory(src).read(0x7F0000000200, 32) == key


# -- regioned raw / gcore (dense "vas" view) ---------------------------------------


def test_regioned_read_and_gaps(gdb_raw):
    mem = VaMemory(gdb_raw)
    heap_va = 0x450000
    assert mem.read(heap_va, 16) == bytes([0xA5]) * 16      # region 5 marker
    assert mem.read(heap_va + 0x2000 - 8, 8) is not None
    assert mem.read(heap_va + 0x2000 - 8, 16) is None       # runs into the gap
    assert mem.read(0x3FFFFF, 1) is None


def test_regioned_translation_roundtrip(gdb_raw):
    mem = VaMemory(gdb_raw)
    va = 0x450010
    off = mem.va_to_view_offset(va)
    assert off == gdb_raw.va_to_vas_offset(va)
    assert mem.view_offset_to_va(off) == va
    assert mem.va_to_view_offset(va, "raw") == gdb_raw.va_to_file_offset(va)
    assert mem.view_offset_to_va(gdb_raw.size_for("vas")) is None
    assert mem.view_offset_to_va(-1) is None


def test_gcore_read_matches_segment_body(gcore):
    mem = VaMemory(gcore)
    va = 0x400000
    assert mem.read(va, 16) == synth_elf_core._load_body(0)[:16]
    assert mem.read(va + synth_elf_core._BODY_SIZE - 4, 8) is None
    assert mem.view_offset_to_va(mem.va_to_view_offset(va + 5)) == va + 5
    assert mem.va_to_view_offset(va, "raw") == gcore.va_to_file_offset(va)


# -- flat / raw --------------------------------------------------------------------


def test_raw_defaults_to_base_zero(raw):
    mem = VaMemory(raw)
    assert mem.base_va == 0
    assert mem.read(0x10, 4) == bytes([0x10, 0x11, 0x12, 0x13])
    assert mem.regions == []


def test_raw_with_base_va(raw):
    base = 0x7F00_0000_0000
    mem = VaMemory(raw, base_va=base)
    assert mem.read(base, 2) == b"\x00\x01"
    assert mem.u16(base + 2) == 0x0302
    assert mem.u32(base + 4) == 0x07060504
    assert mem.u64(base + 8) == 0x0F0E0D0C0B0A0908
    assert mem.ptr(base + 8) == mem.u64(base + 8)
    assert mem.read(base - 1, 2) is None
    assert mem.read(base + 250, 8) is None                  # past EOF
    assert mem.va_to_view_offset(base + 0x20) == 0x20
    assert mem.va_to_view_offset(base - 1) is None
    assert mem.view_offset_to_va(0x20) == base + 0x20


def test_big_endian_32bit_pointer(raw):
    mem = VaMemory(raw, BIG32, base_va=0x1000)
    assert mem.u16(0x1002) == 0x0203
    assert mem.u32(0x1004) == 0x04050607
    assert mem.ptr(0x1004) == 0x04050607


def test_read_edge_lengths(raw):
    mem = VaMemory(raw)
    assert mem.read(0, 0) == b""
    assert mem.read(0, -1) is None
    assert mem.read(-8, 4) is None
