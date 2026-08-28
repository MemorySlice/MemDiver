"""Tests for ASLR-aware region alignment (core/region_align.py)."""

import logging
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.region_align import (
    VA_PAGE_SIZE,
    AlignedSlice,
    AlignmentCoverage,
    DumpRegionMap,
    NormalizedRegion,
    _normalize_path,
    align_dumps,
    build_module_lookup,
    build_va_page_index,
    captured_byte_count,
    find_owning_module,
    read_va_slab,
    va_page_key,
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


# ---------------------------------------------------------------------------
# Coverage — what the alignment compared vs what it was offered
# ---------------------------------------------------------------------------


def test_coverage_from_sizes_reconciles():
    """compared * n + discarded == everything offered."""
    coverage = AlignmentCoverage.from_sizes([100, 130, 180], 100)
    assert coverage.n_sources == 3
    assert coverage.bytes_discarded == 110
    assert coverage.sizes_differed is True
    assert (coverage.bytes_compared * coverage.n_sources
            + coverage.bytes_discarded) == 410


def test_coverage_from_equal_sizes_discards_nothing():
    coverage = AlignmentCoverage.from_sizes([64, 64], 64)
    assert coverage.bytes_discarded == 0
    assert coverage.sizes_differed is False
    assert coverage.discarded_fraction == 0.0


def test_coverage_from_alignment_counts_dropped_pages():
    """A page captured in one dump but not the other is discarded, not compared."""
    pages_a = {0: b"\x00" * 4096, 4096: b"\x01" * 4096}
    pages_b = {0: b"\x10" * 4096}
    map_a = DumpRegionMap(dump_index=0, regions={
        "mod:lib:0x0": _make_region("mod:lib:0x0", pages_a),
    })
    map_b = DumpRegionMap(dump_index=1, regions={
        "mod:lib:0x0": _make_region("mod:lib:0x0", pages_b),
    })
    slices = align_dumps([map_a, map_b])
    coverage = AlignmentCoverage.from_alignment([map_a, map_b], slices)
    assert coverage.bytes_compared == 4096
    assert coverage.bytes_available == (8192, 4096)
    assert coverage.bytes_discarded == 4096
    assert coverage.discarded_fraction == pytest.approx(4096 / 12288)


def test_captured_byte_count_reads_metadata_only_maps():
    """Page bytes may be absent; the count comes from page count * page size."""
    rmap = DumpRegionMap(dump_index=0, regions={
        "k": _make_region("k", {0: b"", 4096: b""}),
    })
    assert captured_byte_count(rmap) == 8192


# ---------------------------------------------------------------------------
# VA page indexing
# ---------------------------------------------------------------------------


class _FakeVaSource:
    """Minimal VA-mapped source: ranges plus a flat raw stream."""

    def __init__(self, ranges, raw):
        self._ranges = ranges
        self._raw = raw

    def iter_ranges(self, view="vas"):
        return iter(self._ranges)

    def read_range(self, offset, length, view="raw"):
        assert view == "raw", "the VA slab must be read from the raw stream"
        return self._raw[offset:offset + length]


def test_va_page_key_sorts_numerically():
    """Zero padding is what makes lexicographic key order VA order."""
    assert sorted([va_page_key(0x10000), va_page_key(0x800)]) == [
        va_page_key(0x800), va_page_key(0x10000),
    ]


def test_build_va_page_index_splits_on_absolute_page_boundaries():
    src = _FakeVaSource([(0x400000, 0x400000 + VA_PAGE_SIZE + 10, 0)],
                        b"\x00" * (VA_PAGE_SIZE + 10))
    index = build_va_page_index(0, src)
    assert sorted(index.region_map.regions) == [
        va_page_key(0x400000), va_page_key(0x400000 + VA_PAGE_SIZE),
    ]
    sizes = {k: r.page_size for k, r in index.region_map.regions.items()}
    assert sizes[va_page_key(0x400000)] == VA_PAGE_SIZE
    assert sizes[va_page_key(0x400000 + VA_PAGE_SIZE)] == 10


def test_build_va_page_index_records_raw_offsets():
    """A range starting at file offset 64 keeps that offset in the index."""
    src = _FakeVaSource([(0x1000, 0x1000 + 32, 64)], b"\xFF" * 96)
    index = build_va_page_index(0, src)
    assert index.file_offsets == {va_page_key(0x1000): 64}
    assert index.region_map.regions[va_page_key(0x1000)].source_base_addr == 0x1000


def test_build_va_page_index_cuts_a_range_that_starts_mid_page():
    """The leading short page keeps every page after it in correspondence."""
    start = 0x1000 + 100
    src = _FakeVaSource([(start, 0x1000 + VA_PAGE_SIZE + 8, 0)],
                        b"\x00" * VA_PAGE_SIZE)
    index = build_va_page_index(0, src)
    sizes = {k: r.page_size for k, r in index.region_map.regions.items()}
    assert sizes[va_page_key(start)] == VA_PAGE_SIZE - 100
    assert sizes[va_page_key(0x1000 + VA_PAGE_SIZE)] == 8


def test_read_va_slab_returns_the_aligned_bytes_in_slice_order():
    raw_a = b"aaaabbbb"
    raw_b = b"XXXXaaaacccc"
    src_a = _FakeVaSource([(0x2000, 0x2004, 0), (0x1000, 0x1004, 4)], raw_a)
    src_b = _FakeVaSource([(0x1000, 0x1004, 4), (0x2000, 0x2004, 8)], raw_b)
    idx_a = build_va_page_index(0, src_a)
    idx_b = build_va_page_index(1, src_b)

    slices = align_dumps([idx_a.region_map, idx_b.region_map])
    # Ascending VA, whatever order the ranges were declared in.
    assert [s.source_vaddrs[0] for s in slices] == [0x1000, 0x2000]
    assert read_va_slab(src_a, idx_a, slices) == b"bbbbaaaa"
    assert read_va_slab(src_b, idx_b, slices) == b"aaaacccc"


def test_read_va_slab_rejects_a_slice_the_dump_never_indexed():
    src = _FakeVaSource([(0x1000, 0x1004, 0)], b"aaaa")
    index = build_va_page_index(0, src)
    foreign = AlignedSlice(key=va_page_key(0x9000), page_offset=0, page_size=4,
                           source_vaddrs=[0x9000], data=[b""])
    with pytest.raises(KeyError):
        read_va_slab(src, index, [foreign])
