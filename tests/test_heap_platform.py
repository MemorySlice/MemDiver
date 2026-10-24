"""Tests for heap/platform.py: platform discovery and the unified memory map."""

from pathlib import Path

import pytest

from memdiver.core.dump_source import MslDumpSource, RawDumpSource
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
from memdiver.heap.platform import (ASSUMED_PLATFORM, TargetPlatform,
                                    memory_map_of, module_paths, platform_of)
from tests.fixtures import synth_elf_core, synth_raw_regions
from tests.fixtures.android.generate_app_process_bin import (
    maps_entry_names, write_app_process_bin)
from tests.fixtures.generate_msl_fixtures import write_aslr_fixture

ANDROID_MSL = Path(__file__).parent / "fixtures" / "android" / "memslicer_android.msl"


@pytest.fixture
def android_msl():
    with MslDumpSource(ANDROID_MSL) as src:
        yield src


@pytest.fixture
def gdb_raw(tmp_path):
    run = synth_raw_regions.build(tmp_path)
    with GdbRawDumpSource(run / "gdb_raw.bin", run / "gdb_raw.maps") as src:
        yield src


@pytest.fixture
def android_regioned(tmp_path):
    bin_path = write_app_process_bin(tmp_path / "app.bin")
    with GdbRawDumpSource(bin_path, bin_path.with_suffix(".maps")) as src:
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


# -- platform_of ------------------------------------------------------------------


def test_platform_msl_header_android_arm64(android_msl):
    assert platform_of(android_msl) == TargetPlatform(
        "android", "arm64", 8, "little", "msl_header")


def test_platform_msl_linux_x86_64(tmp_path):
    path = write_aslr_fixture(tmp_path / "a.msl", region_base=0x7F0000000000)
    with MslDumpSource(path) as src:
        plat = platform_of(src)
    assert (plat.os, plat.arch, plat.pointer_size, plat.endianness) == (
        "linux", "x86_64", 8, "little")


def test_platform_gcore_from_elf_machine(gcore):
    assert platform_of(gcore) == TargetPlatform(
        "linux", "x86_64", 8, "little", "elf_header")


def test_platform_regioned_linux(gdb_raw):
    plat = platform_of(gdb_raw)
    assert (plat.os, plat.arch, plat.source) == ("linux", "x86_64", "mapping_names")


def test_platform_regioned_android_is_arm64(android_regioned):
    plat = platform_of(android_regioned)
    assert (plat.os, plat.arch, plat.pointer_size) == ("android", "arm64", 8)
    assert plat.is_android


def test_platform_raw_and_unknown_fall_back(raw):
    assert platform_of(raw) == ASSUMED_PLATFORM
    assert platform_of(object()) == ASSUMED_PLATFORM
    assert platform_of(None) == ASSUMED_PLATFORM


def test_platform_unopened_msl_falls_back():
    assert platform_of(MslDumpSource(ANDROID_MSL)) == ASSUMED_PLATFORM


# -- memory_map_of / module_paths ----------------------------------------------


def test_memory_map_msl(android_msl):
    regions = memory_map_of(android_msl)
    assert len(regions) == 13
    assert [r.va for r in regions] == sorted(r.va for r in regions)
    by_name = {r.name: r for r in regions}
    scudo = by_name["[anon:scudo:primary]"]
    assert (scudo.va, scudo.size, scudo.perms, scudo.captured) == (
        0x7A00000000, 4096, "rw-", True)


def test_memory_map_msl_segment_vas_map_wins(tmp_path):
    """The effective (last) VAS map names regions: a segment map naming
    ``[heap]`` supersedes a capture map naming something else (spec 5.8)."""
    from tests.fixtures.vas_segment_msl import vas_entry, write_vas_msl

    path = write_vas_msl(tmp_path / "seg.msl", [[vas_entry("[anon:old]")]],
                         [[vas_entry("[heap]")]])
    with MslDumpSource(path) as src:
        (region,) = memory_map_of(src)
    assert region.name == "[heap]"


def test_memory_map_regioned(gdb_raw):
    regions = memory_map_of(gdb_raw)
    assert len(regions) == len(synth_raw_regions._REGION_SPECS)
    heap = next(r for r in regions if r.name == "[heap]")
    assert (heap.va, heap.size, heap.perms, heap.module_path, heap.captured) == (
        0x450000, 0x2000, "rw-", None, True)
    libc = regions[0]
    assert libc.module_path == "/usr/lib/x86_64-linux-gnu/libc.so.6"
    assert libc.perms == "r-x"


def test_memory_map_android_regioned_names(android_regioned):
    names = [r.name for r in memory_map_of(android_regioned)]
    assert sorted(names) == sorted(maps_entry_names())
    assert "[anon:scudo:primary]" in names


def test_memory_map_gcore_pt_load_with_nt_file(gcore):
    regions = memory_map_of(gcore)
    assert len(regions) == synth_elf_core._NUM_LOAD
    first = regions[0]
    assert first.va == 0x400000
    assert first.module_path == "/usr/bin/gocryptfs"
    assert first.captured


def test_memory_map_raw_and_unknown_are_empty(raw):
    assert memory_map_of(raw) == []
    assert memory_map_of(object()) == []
    assert module_paths(object()) == []


def test_module_paths(android_msl, gdb_raw):
    msl_paths = module_paths(android_msl)
    assert "/apex/com.android.runtime/lib64/bionic/libc.so" in msl_paths
    assert len(msl_paths) == len(set(msl_paths))
    assert module_paths(gdb_raw)[:2] == [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3"]
