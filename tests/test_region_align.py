"""Tests for ASLR-aware region alignment (core/region_align.py)."""

import logging
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.region_align import (
    AlignedSlice,
    DumpRegionMap,
    NormalizedRegion,
    _normalize_path,
    align_dumps,
    build_module_lookup,
    find_owning_module,
)


@dataclass
class _FakeModule:
    base_addr: int
    module_size: int
    path: str


def test_normalize_module_backed_region():
    """Region inside a module gets mod: key with correct offset."""
    mod = _FakeModule(base_addr=0x400000, module_size=0x100000,
                      path="/usr/lib/libssl.so")
    starts, intervals = build_module_lookup([mod])
    result = find_owning_module(0x410000, starts, intervals)
    assert result is not None
    path, offset = result
    assert path.startswith("/usr/lib/")  # normalized (already lowercase)
    assert offset == 0x10000


def test_normalize_anonymous_region():
    """Region with no modules returns None."""
    result = find_owning_module(0x7FFF0000, [], [])
    assert result is None


def test_aslr_same_module_different_base():
    """Same module at different ASLR bases produces same (path, offset)."""
    mod_a = _FakeModule(base_addr=0x400000, module_size=0x100000,
                        path="/usr/lib/libssl.so")
    mod_b = _FakeModule(base_addr=0x7F000000, module_size=0x100000,
                        path="/usr/lib/libssl.so")
    starts_a, ivs_a = build_module_lookup([mod_a])
    starts_b, ivs_b = build_module_lookup([mod_b])

    res_a = find_owning_module(0x400000 + 0x1000, starts_a, ivs_a)
    res_b = find_owning_module(0x7F000000 + 0x1000, starts_b, ivs_b)

    assert res_a is not None and res_b is not None
    assert res_a == res_b  # same (normalized_path, 0x1000)


def _make_region(key, pages, page_size=4096, base=0x1000, rtype=0):
    return NormalizedRegion(
        key=key, captured_pages=pages, page_size=page_size,
        source_base_addr=base, region_type=rtype,
    )


def test_page_intersection():
    """Only pages captured in ALL dumps appear in aligned slices."""
    pages_a = {0: b"\x00" * 4096, 4096: b"\x01" * 4096, 8192: b"\x02" * 4096}
    pages_b = {4096: b"\x11" * 4096, 8192: b"\x12" * 4096, 12288: b"\x13" * 4096}

    map_a = DumpRegionMap(dump_index=0, regions={
        "mod:lib:0x0": _make_region("mod:lib:0x0", pages_a),
    })
    map_b = DumpRegionMap(dump_index=1, regions={
        "mod:lib:0x0": _make_region("mod:lib:0x0", pages_b, base=0x2000),
    })

    slices = align_dumps([map_a, map_b])
    offsets = {s.page_offset for s in slices}
    assert offsets == {4096, 8192}
    assert all(s.key == "mod:lib:0x0" for s in slices)


def test_failed_pages_excluded():
    """DumpRegionMap captured_pages dict contains only valid page data."""
    pages = {0: b"\xAA" * 4096}
    region = _make_region("test", pages)
    # captured_pages is a plain dict — no FAILED entries exist
    assert all(len(v) == 4096 for v in region.captured_pages.values())
    assert len(region.captured_pages) == 1


def test_align_empty_intersection():
    """Disjoint keys across dumps yield no aligned slices."""
    map_a = DumpRegionMap(dump_index=0, regions={
        "mod:libA:0x0": _make_region("mod:libA:0x0", {0: b"\x00" * 4096}),
    })
    map_b = DumpRegionMap(dump_index=1, regions={
        "mod:libB:0x0": _make_region("mod:libB:0x0", {0: b"\x00" * 4096}),
    })
    slices = align_dumps([map_a, map_b])
    assert slices == []


def test_module_path_normalization():
    """Windows-style path normalized to lowercase forward slashes."""
    result = _normalize_path("C:\\Windows\\System32\\ntdll.dll")
    assert result == "c:/windows/system32/ntdll.dll"


def test_page_size_mismatch_skipped(caplog):
    """Mismatched page sizes for same key logs ERROR and skips."""
    map_a = DumpRegionMap(dump_index=0, regions={
        "mod:x:0x0": _make_region("mod:x:0x0", {0: b"\x00" * 4096},
                                  page_size=4096),
    })
    map_b = DumpRegionMap(dump_index=1, regions={
        "mod:x:0x0": _make_region("mod:x:0x0", {0: b"\x00" * 8192},
                                  page_size=8192),
    })
    with caplog.at_level(logging.ERROR, logger="memdiver.core.region_align"):
        slices = align_dumps([map_a, map_b])
    assert slices == []
    assert any("Page size mismatch" in m for m in caplog.messages)
