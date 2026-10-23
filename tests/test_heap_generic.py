"""Tests for heap/allocators/generic.py: boundary-tag chain heuristic."""
from __future__ import annotations

import pytest

from memdiver.heap.allocators import generic as gen
from memdiver.heap.model import AllocatorKind, ChunkState
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh


@pytest.fixture
def open_heaps(tmp_path):
    """Open regioned-raw sources built from fixtures; close them afterwards."""
    opened = []

    def _open(heaps):
        source = sh.open_regioned(sh.as_regioned_raw(tmp_path, heaps))
        opened.append(source)
        ctx = DetectContext(source)
        return ctx, ctx.memory

    yield _open
    for source in opened:
        source.close()


def _shape(chunks):
    return [(c.va, c.size, c.header_len) for c in chunks]


def test_finds_glibc_chain(open_heaps):
    heap = sh.glibc_heap()
    ctx, mem = open_heaps([heap])
    layout = gen.parse_generic(mem, ctx, ParseOptions())
    assert layout.allocator is AllocatorKind.GENERIC
    assert _shape(layout.chunks) == _shape(heap.chunks)
    assert all(c.state is ChunkState.UNKNOWN for c in layout.chunks)
    assert all(0 < c.confidence <= gen.MAX_CONFIDENCE for c in layout.chunks)
    assert layout.confidence <= 0.3
    assert layout.diagnostics[0].startswith("heuristic")
    assert layout.coverage["heuristic"] is True


def test_finds_dlmalloc_chain(open_heaps):
    heap = sh.dlmalloc_heap()
    ctx, mem = open_heaps([heap])
    layout = gen.parse_generic(mem, ctx, ParseOptions())
    assert _shape(layout.chunks) == _shape(heap.chunks)


def test_random_region_yields_nothing(open_heaps):
    ctx, mem = open_heaps([sh.random_region(5)])
    layout = gen.parse_generic(mem, ctx, ParseOptions())
    assert layout.chunks == () and layout.regions == ()
    assert gen.probe_generic(ctx).score == 0.0


def test_jemalloc_slab_has_no_chain(open_heaps):
    ctx, mem = open_heaps([sh.jemalloc_slab()])
    assert gen.parse_generic(mem, ctx, ParseOptions()).chunks == ()


def test_probe_capped(open_heaps):
    ctx, _mem = open_heaps([sh.glibc_heap()])
    result = gen.probe_generic(ctx)
    assert 0 < result.score <= gen.MAX_CONFIDENCE


def test_region_filter_and_max_chunks(open_heaps):
    ctx, mem = open_heaps([sh.glibc_heap()])
    none = gen.parse_generic(mem, ctx, ParseOptions(regions=("[anon:x]",)))
    assert none.chunks == ()
    capped = gen.parse_generic(mem, ctx, ParseOptions(max_chunks=5))
    assert len(capped.chunks) == 5


def test_chain_confidence_rewards_tiling():
    short = gen.SizeChain((32,) * 4, 0, 8, tiles_region=False)
    tiled = gen.SizeChain((32,) * 4, 0, 8, tiles_region=True)
    assert gen.chain_confidence(short) < gen.chain_confidence(tiled) <= 0.3


def test_descriptor_overrides_shape():
    probe, parse = gen.DESCRIPTOR_OVERRIDES[AllocatorKind.GENERIC]
    assert parse is gen.parse_generic and probe is gen.probe_generic
