"""Self-consistency of the synthetic heap fixtures (tests/fixtures/synth_heap.py).

The fixtures are the oracle for the heap parsers, so these tests decode the
bytes independently and check they agree with the declared ExpectedChunks.
"""
from __future__ import annotations

import struct

import pytest

from memdiver.heap.model import ChunkState
from tests.fixtures import synth_heap as sh

BUILDERS = {
    "glibc64": lambda: sh.glibc_heap(),
    "glibc64_plain": lambda: sh.glibc_heap(safe_linking=False),
    "glibc32": lambda: sh.glibc_heap(pointer_size=4),
    "dlmalloc64": lambda: sh.dlmalloc_heap(),
    "dlmalloc32": lambda: sh.dlmalloc_heap(pointer_size=4),
    "scudo": lambda: sh.scudo_primary(),
    "mallocng": lambda: sh.mallocng_group(),
    "jemalloc": lambda: sh.jemalloc_slab(),
}


def _word(heap: sh.SynthHeap, va: int) -> int:
    fmt = "<Q" if heap.pointer_size == 8 else "<I"
    return struct.unpack(fmt, heap.read(va, heap.pointer_size))[0]


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_chunks_tile_span_exactly(name):
    heap = BUILDERS[name]()
    lo, hi = heap.tiled_span
    assert heap.chunks and lo < hi
    cursor = lo
    for chunk in heap.chunks:
        assert chunk.va == cursor
        assert chunk.size > 0 and chunk.header_len + chunk.user_len <= chunk.size
        cursor += chunk.size
    assert cursor == hi
    assert len(heap.data) == sum(size for _va, size, _n in heap.regions)


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_builders_are_deterministic(name):
    assert BUILDERS[name]().data == BUILDERS[name]().data


@pytest.mark.parametrize("name", ["glibc64", "glibc32", "glibc64_plain"])
def test_glibc_headers_and_tcache(name):
    heap = BUILDERS[name]()
    ps = heap.pointer_size
    first = heap.chunks[0]
    assert first.size == (0x290 if ps == 8 else 0x188)
    for chunk in heap.chunks:
        size_field = _word(heap, chunk.va + ps)
        assert size_field & ~0x7 == chunk.size
        assert size_field & sh.PREV_INUSE
    assert heap.chunks[-1].bin == "top"
    assert heap.chunks[-1].va + heap.chunks[-1].size == heap.base_va + 0x1000
    _assert_tcache_chains(heap, safe=name != "glibc64_plain")


def _assert_tcache_chains(heap: sh.SynthHeap, safe: bool) -> None:
    ps = heap.pointer_size
    tcache_mem = heap.base_va + 2 * ps
    cached = {c.va + c.header_len: c for c in heap.chunks
              if c.state is ChunkState.CACHED}
    walked = set()
    for idx in range(sh.TCACHE_BINS):
        count = struct.unpack("<H", heap.read(tcache_mem + 2 * idx, 2))[0]
        entry = _word(heap, tcache_mem + 2 * sh.TCACHE_BINS + ps * idx)
        seen = 0
        while entry:
            assert cached[entry].bin == f"tcache[{idx}]"
            assert _word(heap, entry + ps) == tcache_mem          # key
            walked.add(entry)
            stored = _word(heap, entry)
            entry = (entry >> 12) ^ stored if safe else stored
            seen += 1
        assert seen == count
    assert walked == set(cached)


@pytest.mark.parametrize("name", ["dlmalloc64", "dlmalloc32"])
def test_dlmalloc_boundary_tags(name):
    heap = BUILDERS[name]()
    ps = heap.pointer_size
    prev = None
    for chunk in heap.chunks:
        head = _word(heap, chunk.va + ps)
        assert head & ~0x7 == chunk.size
        if chunk.bin == "top":
            assert head & sh.DL_CINUSE == 0
        else:
            assert bool(head & sh.DL_CINUSE) == (chunk.state is ChunkState.IN_USE)
        prev_free = prev is not None and prev.state is ChunkState.FREE
        assert bool(head & sh.PREV_INUSE) == (not prev_free)
        if prev_free:
            assert _word(heap, chunk.va) == prev.size              # prev_foot
        prev = chunk
    free = [c for c in heap.chunks if c.bin == "smallbin"]
    assert len(free) == 1
    fd = _word(heap, free[0].va + 2 * ps)
    bk = _word(heap, free[0].va + 3 * ps)
    assert fd == bk and not heap.base_va <= fd < heap.base_va + 0x1000


def test_scudo_headers_decode():
    heap = sh.scudo_primary()
    states = {0: ChunkState.FREE, 1: ChunkState.IN_USE, 2: ChunkState.QUARANTINED}
    for chunk in heap.chunks:
        fields = sh.scudo_unpack_header(_word(heap, chunk.va))
        assert fields["class_id"] == 10
        assert states[fields["state"]] is chunk.state
        assert fields["size"] == chunk.user_len and fields["offset"] == 0
    found = {c.state for c in heap.chunks}
    assert {ChunkState.IN_USE, ChunkState.FREE, ChunkState.QUARANTINED} <= found
    assert heap.regions[0][2] == "[anon:scudo:primary]"


def test_scudo_pack_round_trip():
    word = sh.scudo_pack_header(0xAB, 2, 0xFFFFF, origin=3, offset=0x1234,
                                checksum=0xCAFE)
    assert sh.scudo_unpack_header(word) == {
        "class_id": 0xAB, "state": 2, "origin": 3, "size": 0xFFFFF,
        "offset": 0x1234, "checksum": 0xCAFE}


def test_mallocng_meta_and_inband_headers():
    heap = sh.mallocng_group()
    meta_va, group_va = heap.regions[0][0], heap.regions[1][0]
    meta_slot = meta_va + sh.MALLOCNG_META_AREA_HDR
    prev, nxt, mem, avail, freed, bits = struct.unpack(
        "<QQQIIQ", heap.read(meta_slot, sh.MALLOCNG_META_SIZE))
    assert prev == nxt == meta_slot and mem == group_va
    assert _word(heap, group_va) == meta_slot
    last_idx, sizeclass = bits & 31, (bits >> 6) & 63
    stride = sh.MALLOCNG_SIZE_CLASSES[sizeclass] * sh.MALLOCNG_UNIT
    assert last_idx + 1 == len(heap.chunks)
    storage = group_va + sh.MALLOCNG_UNIT
    for idx, chunk in enumerate(heap.chunks):
        assert chunk.va == storage + idx * stride and chunk.size == stride
        hdr_byte, offset = struct.unpack("<BH", heap.read(chunk.va - 3, 3))
        if chunk.state is ChunkState.IN_USE:
            assert hdr_byte & 31 == idx and offset * 16 == chunk.va - storage
            assert not (avail | freed) >> idx & 1
            end = chunk.va + stride - sh.MALLOCNG_IB
            reserved = struct.unpack("<I", heap.read(end - 4, 4))[0]
            assert stride - sh.MALLOCNG_IB - reserved == chunk.user_len
        elif chunk.bin == "freed":
            assert (hdr_byte, offset) == (0xFF, 0) and freed >> idx & 1
        else:
            assert avail >> idx & 1


def test_jemalloc_slab_has_no_headers():
    heap = sh.jemalloc_slab()
    assert all(c.state is ChunkState.UNKNOWN and c.header_len == 0
               for c in heap.chunks)
    assert heap.regions[0][2] == "[anon:jemalloc]"


def test_random_region_is_negative_control():
    heap = sh.random_region(7)
    assert heap.chunks == [] and len(heap.data) == 0x1000
    assert heap.data == sh.random_region(7).data != sh.random_region(8).data


def test_round_trip_through_regioned_raw(tmp_path):
    heaps = [builder() for builder in BUILDERS.values()
             if builder is not BUILDERS["glibc32"]
             and builder is not BUILDERS["dlmalloc32"]
             and builder is not BUILDERS["glibc64_plain"]]
    heaps.append(sh.random_region(3))
    modules = [(0x7F00_1000_0000, 0x2000, "/usr/lib/x86_64-linux-gnu/libc.so.6")]
    path = sh.as_regioned_raw(tmp_path, heaps, modules)
    assert path.name.endswith(".gdb_raw.bin") and path.with_suffix(".maps").exists()
    source = sh.open_regioned(path)
    try:
        assert source.format_name == "gdb_raw"
        ranges = {start: (end, off) for start, end, off in source.iter_ranges()}
        for heap in heaps:
            for idx, (va, size, _name) in enumerate(heap.regions):
                end, file_off = ranges[va]
                assert end - va == size
                assert source.read_range(file_off, size) == heap.region_bytes(idx)
        assert ranges[modules[0][0]][0] - modules[0][0] == 0x2000
    finally:
        source.close()


def test_as_regioned_raw_rejects_overlap(tmp_path):
    with pytest.raises(ValueError):
        sh.as_regioned_raw(tmp_path, [sh.jemalloc_slab(), sh.jemalloc_slab()])
