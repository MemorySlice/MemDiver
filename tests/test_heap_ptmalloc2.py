"""Tests for heap/allocators/ptmalloc2.py against the synthetic heap oracle."""

import dataclasses
import struct

import pytest

from memdiver.heap.allocators.ptmalloc2 import (DESCRIPTOR_OVERRIDES, parse_dlmalloc,
                                                parse_ptmalloc2, probe_dlmalloc,
                                                probe_ptmalloc2)
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import AllocatorKind, ChunkState, HeapRole
from memdiver.heap.platform import TargetPlatform
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh

LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
LIBC_VA = 0x7FFF_F7E0_0000


def _platform(pointer_size):
    arch = "x86_64" if pointer_size == 8 else "x86"
    return TargetPlatform("linux", arch, pointer_size, "little", "test")


@pytest.fixture
def load(tmp_path):
    """Open synthetic heaps as a regioned raw dump -> (memory, ctx)."""
    opened = []

    def _load(*heaps, pointer_size=8):
        source = sh.open_regioned(sh.as_regioned_raw(tmp_path / str(len(opened)), heaps))
        opened.append(source)
        platform = _platform(pointer_size)
        return VaMemory(source, platform), DetectContext(source, platform=platform)

    yield _load
    for source in opened:
        source.close()


def _observed(layout):
    return [(c.va, c.size, c.state, c.header_len, c.user_len, c.bin) for c in layout.chunks]


def _expected(heap):
    return [(c.va, c.size, c.state, c.header_len, c.user_len, c.bin) for c in heap.chunks]


def _put(buf, offset, value, pointer_size=8):
    struct.pack_into("<Q" if pointer_size == 8 else "<I", buf, offset, value)


def _with_data(heap, buf):
    return dataclasses.replace(heap, data=bytes(buf))


# -- exact layouts ------------------------------------------------------------------


@pytest.mark.parametrize("pointer_size", [8, 4])
@pytest.mark.parametrize("safe_linking", [True, False])
def test_glibc_chunks_match_fixture(load, pointer_size, safe_linking):
    heap = sh.glibc_heap(pointer_size=pointer_size, safe_linking=safe_linking)
    memory, ctx = load(heap, pointer_size=pointer_size)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.allocator is AllocatorKind.PTMALLOC2
    assert _observed(layout) == _expected(heap)
    assert layout.coverage["safe_linking"] is safe_linking
    assert layout.version_hint == ("glibc>=2.32" if safe_linking else "glibc 2.30-2.31")
    assert layout.confidence == 1.0
    assert layout.chunks[0].extra["meta"] is True


@pytest.mark.parametrize("safe_linking", [True, False])
def test_tcache_free_lists_are_decoded(load, safe_linking):
    heap = sh.glibc_heap(safe_linking=safe_linking)
    memory, ctx = load(heap)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    tcache = {f.index: f for f in layout.free_lists if f.kind == "tcache"}
    cached = [c for c in heap.chunks if c.state is ChunkState.CACHED]
    by_bin = {}
    for chunk in cached:
        by_bin.setdefault(int(chunk.bin[7:-1]), []).append(chunk.va)
    assert set(tcache) == set(by_bin)
    for idx, vas in by_bin.items():
        assert tcache[idx].chunk_vas == tuple(reversed(vas))  # LIFO
        assert tcache[idx].decoded is safe_linking
        assert not tcache[idx].cycle


@pytest.mark.parametrize("pointer_size", [8, 4])
def test_dlmalloc_chunks_match_fixture(load, pointer_size):
    heap = sh.dlmalloc_heap(pointer_size=pointer_size)
    memory, ctx = load(heap, pointer_size=pointer_size)
    layout = parse_dlmalloc(memory, ctx, ParseOptions())
    assert layout.allocator is AllocatorKind.DLMALLOC
    assert _observed(layout) == _expected(heap)
    assert layout.free_lists == ()


def test_role_runs_mark_links_meta_and_top(load):
    heap = sh.glibc_heap()
    memory, ctx = load(heap)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    cached = next(c for c in heap.chunks if c.state is ChunkState.CACHED)
    user = cached.va + cached.header_len
    runs = list(layout.role_runs(cached.va, cached.va + cached.size))
    assert runs[0] == (cached.va, 16, HeapRole.CHUNK_HEADER)
    assert runs[1] == (user, 16, HeapRole.FREE_LINK)
    assert runs[2][2] is HeapRole.FREE_DATA
    first, top = heap.chunks[0], heap.chunks[-1]
    assert layout.role_counts(first.va, first.va + first.size) == {
        "allocator_meta": first.size}
    assert layout.role_counts(top.va, top.va + top.size) == {"top": top.size}


# -- probes -------------------------------------------------------------------------


def _renamed(heap, name):
    va, size, _name = heap.regions[0]
    return dataclasses.replace(heap, regions=[(va, size, name)])


def test_probe_scores_glibc_high_and_random_low(load):
    _memory, ctx = load(sh.glibc_heap())
    assert probe_ptmalloc2(ctx).score >= 0.9
    assert probe_dlmalloc(ctx).score < 0.2
    _memory, ctx = load(sh.random_region())
    assert probe_ptmalloc2(ctx).score < 0.2
    _memory, ctx = load(_renamed(sh.random_region(), "[heap]"))
    assert probe_ptmalloc2(ctx).score < 0.2
    assert probe_dlmalloc(ctx).score < 0.2


def test_probe_separates_dlmalloc_from_ptmalloc2(load):
    _memory, ctx = load(sh.dlmalloc_heap())
    assert probe_dlmalloc(ctx).score >= 0.9
    _memory, ctx = load(_renamed(sh.dlmalloc_heap(), "[heap]"))
    assert probe_ptmalloc2(ctx).score < 0.2


# -- robustness ---------------------------------------------------------------------


def test_corrupt_size_field_resyncs(load):
    heap = sh.glibc_heap()
    victim = heap.chunks[4]             # head of tcache[1]: that bin breaks
    buf = bytearray(heap.data)
    _put(buf, victim.va - heap.base_va + 8, 0xDEAD_BEEF_0000_0003)
    memory, ctx = load(_with_data(heap, buf))
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    vas = [c.va for c in layout.chunks]
    assert victim.va not in vas
    assert any(f"{victim.va:#x}" in d for d in layout.diagnostics)
    tail = [c for c in heap.chunks if c.va > victim.va]
    assert _observed(layout)[-len(tail):] == [
        (c.va, c.size, c.state, c.header_len, c.user_len, c.bin) for c in tail]
    assert layout.chunk_at(heap.chunks[3].va).state is ChunkState.UNKNOWN
    assert layout.coverage["bytes_skipped"] == victim.size


def test_max_chunks_caps_walk(load):
    memory, ctx = load(sh.glibc_heap())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions(max_chunks=3))
    assert len(layout.chunks) == 3
    assert layout.coverage["truncated"] is True
    assert any("max_chunks" in d for d in layout.diagnostics)


class _HoleMemory:
    """VaMemory stand-in whose first page was never captured."""

    def __init__(self, inner, hole):
        self._inner, self._hole = inner, hole
        self.platform = inner.platform

    def read(self, va, n):
        lo, hi = self._hole
        return None if va < hi and va + n > lo else self._inner.read(va, n)


def test_uncaptured_page_is_skipped_and_counted(load):
    heap = sh.glibc_heap(region_size=0x2000)
    memory, ctx = load(heap)
    hole = (heap.base_va, heap.base_va + sh.PAGE)
    layout = parse_ptmalloc2(_HoleMemory(memory, hole), ctx, ParseOptions())
    assert layout.coverage["bytes_uncaptured"] == sh.PAGE
    assert all(c.va >= hole[1] for c in layout.chunks)


def test_no_heap_region_yields_diagnostic(load):
    memory, ctx = load(sh.random_region())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.chunks == () and layout.diagnostics


# -- main_arena -----------------------------------------------------------------------


def _arena_fixture():
    """glibc heap with one fastbin and one smallbin chunk + libc main_arena."""
    heap = sh.glibc_heap()
    fast, small, after_small = heap.chunks[1], heap.chunks[3], heap.chunks[4]
    top_slot = LIBC_VA + 0x100 + 16 + 10 * 8          # &main_arena.top
    small_header = top_slot + 2 * (small.size // 16 - 1) * 8
    buf = bytearray(heap.data)
    off = heap.base_va
    _put(buf, fast.va - off + 16, (fast.va + 16) >> 12)   # PROTECT_PTR(&fd, NULL)
    _put(buf, small.va - off + 16, small_header)
    _put(buf, small.va - off + 24, small_header)
    _put(buf, after_small.va - off, small.size)
    _put(buf, after_small.va - off + 8, after_small.size)  # PREV_INUSE cleared
    libc = bytearray(sh.PAGE)
    _put(libc, top_slot - LIBC_VA - 10 * 8 + 8, fast.va)  # fastbinsY[1]
    _put(libc, top_slot - LIBC_VA, heap.chunks[-1].va)
    for pair in range(127):
        header = top_slot + 2 * pair * 8
        link = small.va if header == small_header else header
        _put(libc, top_slot - LIBC_VA + 16 + 16 * pair, link)
        _put(libc, top_slot - LIBC_VA + 24 + 16 * pair, link)
    libc_heap = sh.SynthHeap(bytes(libc), LIBC_VA, "libc", 8,
                             [(LIBC_VA, sh.PAGE, LIBC_PATH)], [], perms=["rw-p"])
    return _with_data(heap, buf), libc_heap, top_slot


def test_main_arena_bins_are_decoded(load):
    heap, libc, top_slot = _arena_fixture()
    memory, ctx = load(heap, libc)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.coverage["main_arena_top_va"] == top_slot
    fast = layout.chunk_at(heap.chunks[1].va)
    assert (fast.state, fast.bin) == (ChunkState.CACHED, "fastbin[1]")
    small = layout.chunk_at(heap.chunks[3].va)
    assert (small.state, small.bin) == (ChunkState.FREE, "smallbin[5]")
    kinds = {(f.kind, f.index): f.chunk_vas for f in layout.free_lists}
    assert kinds[("fastbin", 1)] == (heap.chunks[1].va,)
    assert kinds[("smallbin", 5)] == (heap.chunks[3].va,)
    assert not any("main_arena not found" in d for d in layout.diagnostics)


def test_missing_main_arena_is_reported(load):
    memory, ctx = load(sh.glibc_heap())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.coverage["main_arena_top_va"] is None
    assert any("main_arena not found" in d for d in layout.diagnostics)


def test_descriptor_overrides_wire_both_kinds():
    assert DESCRIPTOR_OVERRIDES[AllocatorKind.PTMALLOC2] == (probe_ptmalloc2,
                                                             parse_ptmalloc2)
    assert DESCRIPTOR_OVERRIDES[AllocatorKind.DLMALLOC] == (probe_dlmalloc,
                                                            parse_dlmalloc)


def test_chunks_carry_raw_header_and_link_words(load):
    heap = sh.glibc_heap()
    memory, ctx = load(heap)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    for chunk in layout.chunks:
        assert chunk.extra["prev_size"] == memory.u64(chunk.va)
        assert chunk.extra["size_word"] & ~0x7 == chunk.size
        linked = chunk.state in (ChunkState.FREE, ChunkState.CACHED) and chunk.bin != "top"
        assert ("fd" in chunk.extra) is linked
        if linked:
            assert chunk.extra["fd"] == memory.u64(chunk.user_va)
            assert chunk.extra["bk"] == memory.u64(chunk.user_va + 8)
    assert layout.chunks[0].extra["counts_width"]  # overlay extras still win/merge
