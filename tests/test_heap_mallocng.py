"""Tests for heap/allocators/mallocng.py against the synth_heap oracle."""

import struct

import pytest

from memdiver.heap.allocators import mallocng as ng
from memdiver.heap.model import AllocatorKind, ChunkState, HeapRole
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh


@pytest.fixture
def opened(tmp_path):
    sources = []

    def _open(*heaps, stem="synth"):
        path = sh.as_regioned_raw(tmp_path, list(heaps), stem=stem)
        source = sh.open_regioned(path)
        sources.append(source)
        return DetectContext(source)

    yield _open
    for source in sources:
        source.close()


def _parse(ctx, **kwargs):
    return ng.parse_mallocng(ctx.memory, ctx, ParseOptions(**kwargs))


def _slots(layout):
    return [c for c in layout.chunks if not c.extra.get("meta")]


# -- tables -----------------------------------------------------------------------


def test_size_classes_match_upstream_table():
    assert len(ng.SIZE_CLASSES) == 48
    assert ng.SIZE_CLASSES[:16] == sh.MALLOCNG_SIZE_CLASSES
    assert ng.SIZE_CLASSES[-1] * ng.UNIT - ng.IB == 131052   # MMAP_THRESHOLD


def test_struct_sizes():
    assert ng.meta_size(8) == sh.MALLOCNG_META_SIZE and ng.meta_size(4) == 24
    assert ng.meta_area_header_size(8) == sh.MALLOCNG_META_AREA_HDR
    assert ng.meta_area_header_size(4) == 16


# -- parse ------------------------------------------------------------------------


@pytest.mark.parametrize("sizeclass,nslots",
                         [(3, 8), (2, 8), (7, 30), (15, 6), (0, 3), (1, 4), (3, 1)])
def test_parse_recovers_exact_slots(opened, sizeclass, nslots):
    heap = sh.mallocng_group(sizeclass=sizeclass, nslots=nslots)
    layout = _parse(opened(heap))
    got = [(c.va, c.size, c.state, c.header_len, c.user_len, c.bin)
           for c in _slots(layout)]
    want = [(c.va, c.size, c.state, c.header_len, c.user_len, c.bin)
            for c in heap.chunks]
    assert got == want
    assert layout.allocator is AllocatorKind.MALLOCNG
    assert layout.confidence == 1.0 and layout.coverage["groups"] == 1


def test_slot_extra_and_header_confirmation(opened):
    heap = sh.mallocng_group()
    layout = _parse(opened(heap))
    meta_va = heap.regions[0][0] + sh.MALLOCNG_META_AREA_HDR
    for idx, chunk in enumerate(_slots(layout)):
        assert chunk.extra["slot_idx"] == idx
        assert chunk.extra["sizeclass"] == 3
        assert chunk.extra["meta_va"] == meta_va
        if chunk.state is ChunkState.IN_USE:
            assert chunk.extra["header_ok"] is True


def test_meta_chunks_are_allocator_meta(opened):
    heap = sh.mallocng_group()
    layout = _parse(opened(heap))
    meta_va, group_va = heap.regions[0][0], heap.regions[1][0]
    metas = {c.bin: c for c in layout.chunks if c.extra.get("meta")}
    assert set(metas) == {"meta_area", "meta", "group"}
    assert metas["meta_area"].va == meta_va
    assert metas["meta_area"].extra["check"] == 0x1122_3344_5566_7788
    assert metas["meta"].va == meta_va + sh.MALLOCNG_META_AREA_HDR
    assert metas["meta"].size == sh.MALLOCNG_META_SIZE
    assert metas["group"].va == group_va and metas["group"].size == ng.UNIT
    counts = layout.role_counts(meta_va, meta_va + 0x100)
    assert counts == {"allocator_meta": sh.MALLOCNG_META_AREA_HDR
                      + sh.MALLOCNG_META_SIZE}
    assert layout.role_counts(group_va, group_va + 16) == {"allocator_meta": 16}


def test_roles_of_slots(opened):
    heap = sh.mallocng_group()
    layout = _parse(opened(heap))
    in_use = next(c for c in _slots(layout) if c.state is ChunkState.IN_USE)
    roles = {role for _va, _n, role in layout.role_runs(in_use.va, in_use.end)}
    assert roles == {HeapRole.USER_DATA, HeapRole.SLACK, HeapRole.CHUNK_HEADER}
    freed = next(c for c in _slots(layout) if c.bin == "freed")
    first = next(layout.role_runs(freed.va, freed.end))
    assert first[2] == HeapRole.FREE_DATA and first[1] == freed.size - ng.IB


def test_regions_reported(opened):
    heap = sh.mallocng_group()
    layout = _parse(opened(heap))
    kinds = {r.kind: r for r in layout.regions}
    assert kinds["mallocng_group"].va == heap.regions[1][0]
    assert kinds["mallocng_meta_area"].va == heap.regions[0][0]


def test_max_chunks_truncates(opened):
    layout = _parse(opened(sh.mallocng_group()), max_chunks=5)
    assert len(layout.chunks) == 5 and layout.coverage["truncated"]
    assert any("max_chunks" in d for d in layout.diagnostics)


def test_region_filter_excludes_group(opened):
    layout = _parse(opened(sh.mallocng_group()), regions=("[heap]",))
    assert layout.chunks == () and layout.confidence == 0.0


def test_corrupt_back_pointer_rejects_group(tmp_path):
    heap = sh.mallocng_group()
    data = bytearray(heap.data)
    struct.pack_into("<Q", data, sh.MALLOCNG_META_AREA_HDR + 16, 0xDEAD_0000)
    heap.data = bytes(data)
    path = sh.as_regioned_raw(tmp_path, [heap])
    source = sh.open_regioned(path)
    try:
        ctx = DetectContext(source)
        assert _parse(ctx).chunks == ()
        assert ng.probe_mallocng(ctx).score == 0.0
    finally:
        source.close()


def test_two_groups_in_two_meta_areas(opened):
    first = sh.mallocng_group()
    second = sh.mallocng_group(meta_va=0x7F00_0050_0000,
                               group_va=0x7F00_0051_0000, sizeclass=5)
    layout = _parse(opened(first, second))
    assert layout.coverage["groups"] == 2
    assert len(_slots(layout)) == len(first.chunks) + len(second.chunks)


# -- probe ------------------------------------------------------------------------


def test_probe_high_on_group(opened):
    result = ng.probe_mallocng(opened(sh.mallocng_group()))
    assert result.score >= 0.6
    assert result.evidence and result.evidence[0].source == "content"


@pytest.mark.parametrize("seed", range(10))
def test_probe_low_on_random_region(opened, seed):
    ctx = opened(sh.random_region(seed), stem=f"rand{seed}")
    assert ng.probe_mallocng(ctx).score == 0.0
    assert _parse(ctx).chunks == ()


def test_probe_low_on_other_allocators(opened):
    ctx = opened(sh.glibc_heap(), sh.scudo_primary(), sh.jemalloc_slab())
    assert ng.probe_mallocng(ctx).score == 0.0


def test_descriptor_overrides():
    probe, parse = ng.DESCRIPTOR_OVERRIDES[AllocatorKind.MALLOCNG]
    assert probe is ng.probe_mallocng and parse is ng.parse_mallocng


def test_cycled_offset_slot_follows_to_user_pointer(tmp_path):
    heap = sh.mallocng_group(sizeclass=7, nslots=8)
    stride, idx = 128, 1
    page = bytearray(heap.region_bytes(1))
    start = ng.UNIT + idx * stride                    # slot offset in the group
    struct.pack_into("<BBH", page, start - 4, 0, 0xE0, 1)   # off = 1 UNIT
    p = start + ng.UNIT
    struct.pack_into("<BBH", page, p - 4, 0, idx | 4 << 5, (p - ng.UNIT) // ng.UNIT)
    heap.data = heap.region_bytes(0) + bytes(page)
    source = sh.open_regioned(sh.as_regioned_raw(tmp_path, [heap]))
    try:
        layout = _parse(DetectContext(source))
    finally:
        source.close()
    chunk = layout.chunk_at(heap.regions[1][0] + start)
    assert chunk.extra["header_ok"] and chunk.header_len == ng.UNIT
    assert chunk.user_va == heap.regions[1][0] + p
    assert chunk.user_len == stride - ng.IB - ng.UNIT - 4
