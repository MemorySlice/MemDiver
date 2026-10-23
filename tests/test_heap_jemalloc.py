"""Tests for heap/allocators/jemalloc.py: partial region + stride parser."""
from __future__ import annotations

import pytest

from memdiver.heap.allocators import jemalloc as je
from memdiver.heap.model import AllocatorKind, ChunkState
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh

JEMALLOC_MODULE = (0x7F00_1000_0000, 0x2000, "/usr/lib/libjemalloc.so.2")


@pytest.fixture
def open_heaps(tmp_path):
    """Open regioned-raw sources built from fixtures; close them afterwards."""
    opened = []

    def _open(heaps, modules=()):
        source = sh.open_regioned(sh.as_regioned_raw(tmp_path, heaps, modules))
        opened.append(source)
        ctx = DetectContext(source)
        return ctx, ctx.memory

    yield _open
    for source in opened:
        source.close()


def test_size_class_table_is_jemalloc5_small_classes():
    classes = je.SMALL_SIZE_CLASSES
    assert len(classes) == 36 and classes[0] == 8 and classes[-1] == 14336
    assert list(classes) == sorted(set(classes))


@pytest.mark.parametrize("reg_size", [0x40, 0x80, 0x200, 0x400])
def test_infer_stride_recovers_slab_reg_size(reg_size):
    heap = sh.jemalloc_slab(reg_size=reg_size)
    guess = je.infer_stride(heap.data)
    assert guess is not None and guess.stride == reg_size


def test_infer_stride_rejects_random_bytes():
    assert je.infer_stride(sh.random_region(1).data) is None


def test_parse_slab_matches_expected_slots(open_heaps):
    heap = sh.jemalloc_slab()
    ctx, mem = open_heaps([heap])
    layout = je.parse_jemalloc(mem, ctx, ParseOptions())
    assert layout.allocator is AllocatorKind.JEMALLOC
    got = [(c.va, c.size, c.header_len, c.user_len, c.bin) for c in layout.chunks]
    want = [(c.va, c.size, c.header_len, c.user_len, c.bin) for c in heap.chunks]
    assert got == want
    assert all(c.state is ChunkState.UNKNOWN for c in layout.chunks)
    assert all(0 < c.confidence <= 0.6 for c in layout.chunks)
    assert 0 < layout.confidence <= 0.6


def test_layout_is_flagged_partial(open_heaps):
    ctx, mem = open_heaps([sh.jemalloc_slab()])
    layout = je.parse_jemalloc(mem, ctx, ParseOptions())
    assert je.PARTIAL_DIAGNOSTIC in layout.diagnostics
    assert "rtree" in layout.diagnostics[0]
    assert layout.coverage["partial"] is True
    assert layout.regions[0].kind == "jemalloc_extent"


def test_max_chunks_caps_slots(open_heaps):
    ctx, mem = open_heaps([sh.jemalloc_slab()])
    layout = je.parse_jemalloc(mem, ctx, ParseOptions(max_chunks=3))
    assert len(layout.chunks) == 3


def test_random_region_yields_region_only(open_heaps):
    heap = sh.random_region(2)
    ctx, mem = open_heaps([heap], [JEMALLOC_MODULE])
    layout = je.parse_jemalloc(mem, ctx, ParseOptions())
    assert [r.va for r in layout.regions] == [heap.base_va]
    assert layout.chunks == ()
    assert any("no slot stride" in d for d in layout.diagnostics)
    assert je.probe_jemalloc(ctx).score == 0.0


def test_unnamed_regions_ignored_without_jemalloc_module(open_heaps):
    ctx, mem = open_heaps([sh.random_region(2)])
    assert je.owned_regions(ctx) == []
    layout = je.parse_jemalloc(mem, ctx, ParseOptions())
    assert layout.regions == () and layout.chunks == ()


def test_probe_scores_slab_low_but_positive(open_heaps):
    ctx, _mem = open_heaps([sh.jemalloc_slab()])
    result = je.probe_jemalloc(ctx)
    assert 0 < result.score <= 0.3
    assert result.evidence[0].source == "content"


def test_region_kind_from_name():
    from memdiver.heap.platform import MappedRegion
    arena = MappedRegion(0, 0x1000, "rw-p", "[anon:jemalloc_arena]", None, True)
    extent = MappedRegion(0, 0x1000, "rw-p", "[anon:jemalloc]", None, True)
    assert je.region_kind(arena) == "jemalloc_arena"
    assert je.region_kind(extent) == "jemalloc_extent"


def test_descriptor_overrides_shape():
    probe, parse = je.DESCRIPTOR_OVERRIDES[AllocatorKind.JEMALLOC]
    assert parse is je.parse_jemalloc and probe is je.probe_jemalloc
