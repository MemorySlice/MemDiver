"""Tests for :mod:`core.proc_maps_parser`."""

from pathlib import Path

import pytest

from core.proc_maps_parser import (
    MapRegion,
    classify_region,
    parse_maps_file,
    parse_maps_text,
)
from msl.enums import RegionType


_REAL_MAPS = Path(
    "/Users/danielbaier/research/projects/github/issues/"
    "2024 fritap issues/2026_success/mempdumps/dataset_memory_slice/"
    "gocryptfs/dataset_gocryptfs/run_0001/gdb_raw.maps"
)


def test_parse_basic_line() -> None:
    text = "1a2ee000-1a30f000 rw-p 00000000 00:00 0                                  [heap]\n"
    regions = parse_maps_text(text)
    assert len(regions) == 1
    r: MapRegion = regions[0]
    assert r.start == 0x1A2EE000
    assert r.end == 0x1A30F000
    assert r.perm == "rw-p"
    assert r.file_offset == 0
    assert r.dev == "00:00"
    assert r.inode == 0
    assert r.path == "[heap]"
    assert r.is_anon is True
    assert r.region_type == int(RegionType.HEAP)
    assert r.size == 0x21000


def test_parse_anonymous_line_has_empty_path() -> None:
    text = "00837000-0089d000 rw-p 00000000 00:00 0 \n"
    regions = parse_maps_text(text)
    assert len(regions) == 1
    assert regions[0].path == ""
    assert regions[0].is_anon is True
    assert regions[0].region_type == int(RegionType.ANONYMOUS)


def test_parse_file_backed_image() -> None:
    text = (
        "00400000-00402000 r--p 00000000 103:02 37488101"
        "                          /usr/bin/gocryptfs\n"
    )
    regions = parse_maps_text(text)
    assert regions[0].path == "/usr/bin/gocryptfs"
    assert regions[0].region_type == int(RegionType.IMAGE)
    assert regions[0].is_anon is False


def test_classify_variants() -> None:
    assert classify_region("[heap]") == int(RegionType.HEAP)
    assert classify_region("[heap:1]") == int(RegionType.HEAP)
    assert classify_region("[stack]") == int(RegionType.STACK)
    assert classify_region("[stack:1234]") == int(RegionType.STACK)
    assert classify_region("") == int(RegionType.ANONYMOUS)
    assert classify_region("/usr/lib/libc.so.6") == int(RegionType.IMAGE)
    assert classify_region("/opt/app/plugin.so") == int(RegionType.IMAGE)
    assert classify_region("/lib/x86_64-linux-gnu/libssl.so.1.1") == int(RegionType.IMAGE)
    assert classify_region("/home/user/data.bin") == int(RegionType.MAPPED_FILE)
    assert classify_region("[vdso]") == int(RegionType.OTHER)
    assert classify_region("[vvar]") == int(RegionType.OTHER)
    assert classify_region("[vsyscall]") == int(RegionType.OTHER)
    assert classify_region("[anon_shmem:tag]") == int(RegionType.SHARED_MEM)


def test_parse_ignores_blank_lines() -> None:
    text = "\n\n"
    assert parse_maps_text(text) == []


@pytest.mark.skipif(not _REAL_MAPS.exists(), reason="private dataset missing")
def test_parse_real_file() -> None:
    regions = parse_maps_file(_REAL_MAPS)
    assert len(regions) > 10
    assert any(r.region_type == int(RegionType.HEAP) for r in regions)
    assert any(r.region_type == int(RegionType.IMAGE) for r in regions)
    # Sanity: ranges are non-empty and monotonically ordered within a map.
    for r in regions:
        assert r.end > r.start
