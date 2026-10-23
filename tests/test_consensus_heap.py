"""Heap-role annotation of a consensus slab (engine.consensus_heap).

Three synthetic glibc heaps share one layout and differ only in user-data
bytes; they are written as native ``.msl`` (module+offset aligned path) and
as regioned raw ``.bin`` + ``.maps`` (VA path). The annotation must agree
across dumps, carry the expected roles, and leave the consensus itself
byte-identical to an ``allocator="off"`` build.
"""

import struct

import numpy as np
import pytest

from memdiver.engine import consensus_heap as ch
from memdiver.engine.consensus_heap import (
    ConsensusHeap,
    HeapChunkIndex,
    HeapRoleRuns,
    merge_role_pieces,
)
from memdiver.engine.consensus_service import build_consensus
from memdiver.heap import analyze as heap_analyze
from memdiver.heap.model import ChunkState, HeapRole
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_heap as sh

_RW = 0x03
N_DUMPS = 3


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


def _variant(seed: int, *, jitter: bool = False) -> sh.SynthHeap:
    """glibc heap whose first in-use chunk's payload depends on *seed*.

    *jitter* grows that chunk's size field 0x30 -> 0x60 so it swallows the
    next (tcache'd) chunk: a layout shift confined to that chunk pair.
    """
    heap = sh.glibc_heap()
    data = bytearray(heap.data)
    chunk = heap.chunks[1]
    user = chunk.va - heap.base_va + chunk.header_len
    data[user:user + 16] = bytes([0x10 + seed]) * 16
    if jitter:
        struct.pack_into("<Q", data, chunk.va - heap.base_va + 8, 0x60 | 1)
    heap.data = bytes(data)
    return heap


def _write_msl(path, heap):
    writer = MslWriter(path, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       imported=False)
    writer.add_memory_region(heap.base_va, heap.data, protection=_RW)
    writer.add_vas_map([MslVasEntry(heap.base_va, len(heap.data), _RW, 0,
                                    "[heap]")])
    writer.write()
    return path


def _msl_dumps(tmp_path, heaps):
    return [_write_msl(tmp_path / f"d{i}.msl", h) for i, h in enumerate(heaps)]


def _regioned_dumps(tmp_path, heaps):
    return [sh.as_regioned_raw(tmp_path / f"r{i}", [h], stem=f"d{i}")
            for i, h in enumerate(heaps)]


def _raw_dumps(tmp_path, heaps):
    paths = []
    for i, heap in enumerate(heaps):
        path = tmp_path / f"flat{i}.dump"
        path.write_bytes(heap.data)
        paths.append(path)
    return paths


_WRITERS = {"msl": _msl_dumps, "regioned": _regioned_dumps}


def _same_layout():
    return [_variant(i) for i in range(N_DUMPS)]


def _slab_of(cm, va):
    """Slab offset of the anchor dump's *va* (aligned builds)."""
    for slab, page, vas in cm.msl_layout:
        if vas[0] <= va < vas[0] + page:
            return slab + va - vas[0]
    raise AssertionError(f"{va:#x} not in slab")


# -- aligned / VA paths -----------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_WRITERS))
def test_runs_agree_across_identical_layouts(tmp_path, kind):
    cm = build_consensus(_WRITERS[kind](tmp_path, _same_layout()))
    heap = cm.heap
    assert heap.status == ch.STATUS_OK
    assert heap.report["dumps_projected"] == N_DUMPS
    assert heap.report["mixed_bytes"] == 0
    assert set(heap.runs.agree.tolist()) == {N_DUMPS}
    assert [d["allocator"] for d in heap.per_dump] == ["ptmalloc2"] * N_DUMPS


@pytest.mark.parametrize("kind", sorted(_WRITERS))
def test_roles_match_expected_chunks(tmp_path, kind):
    heaps = _same_layout()
    cm = build_consensus(_WRITERS[kind](tmp_path, heaps))
    runs, expected = cm.heap.runs, heaps[0].chunks
    for chunk in expected[1:-1]:
        slab = _slab_of(cm, chunk.va)
        assert runs.role_at(slab) == HeapRole.CHUNK_HEADER
        if chunk.state is ChunkState.CACHED:
            user = slab + chunk.header_len
            assert runs.role_at(user) == HeapRole.FREE_LINK
    tcache = expected[0]
    assert runs.role_at(_slab_of(cm, tcache.va)) == HeapRole.ALLOCATOR_META


@pytest.mark.parametrize("kind", sorted(_WRITERS))
def test_chunk_index_projects_anchor(tmp_path, kind):
    heaps = _same_layout()
    cm = build_consensus(_WRITERS[kind](tmp_path, heaps))
    chunks = cm.heap.chunks
    assert len(chunks) == len(heaps[0].chunks)
    target = heaps[0].chunks[2]
    hit = chunks.chunk_at(_slab_of(cm, target.va) + 5)
    assert hit["size"] == target.size
    assert hit["state"] == target.state.value
    assert hit["offset_in_chunk"] == 5
    assert hit["agree"] == N_DUMPS


@pytest.mark.parametrize("kind", sorted(_WRITERS))
def test_consensus_byte_identical_with_and_without_heap(tmp_path, kind):
    paths = _WRITERS[kind](tmp_path, _same_layout())
    on = build_consensus(paths)
    off = build_consensus(paths, allocator="off")
    assert off.heap is None and on.heap is not None
    assert np.asarray(on.variance).tobytes() == np.asarray(off.variance).tobytes()
    assert (np.asarray(on.classifications).tobytes()
            == np.asarray(off.classifications).tobytes())
    assert on.reference_bytes == off.reference_bytes
    assert on.msl_layout == off.msl_layout


@pytest.mark.parametrize("kind", sorted(_WRITERS))
def test_jittered_layout_is_mixed_only_where_it_differs(tmp_path, kind):
    heaps = [_variant(0), _variant(1), _variant(2, jitter=True)]
    cm = build_consensus(_WRITERS[kind](tmp_path, heaps))
    runs = cm.heap.runs
    swallowed = heaps[0].chunks[2]          # the tcache'd chunk dump 2 absorbs
    start = _slab_of(cm, swallowed.va)
    window = runs.window(start, swallowed.size)
    assert (window == HeapRole.MIXED).any()
    mixed = runs.mask({HeapRole.MIXED}, cm.size)
    assert mixed[start:start + swallowed.size].sum() == int(mixed.sum())
    assert int(runs.agree.min()) == N_DUMPS - 1
    assert cm.heap.chunks.chunk_at(start)["agree"] == N_DUMPS - 1
    first = heaps[0].chunks[1]
    assert cm.heap.chunks.chunk_at(_slab_of(cm, first.va))["agree"] == N_DUMPS - 1


# -- coordinate-less and failure paths --------------------------------------------


def test_pure_raw_reports_no_va_coordinate(tmp_path):
    cm = build_consensus(_raw_dumps(tmp_path, _same_layout()))
    assert cm.size > 0
    assert cm.heap.status == ch.STATUS_NO_VA
    assert len(cm.heap.runs) == 0
    assert cm.heap.runs.fill == HeapRole.UNCOVERED
    assert cm.heap.runs.role_at(0) == HeapRole.UNCOVERED


def test_mixed_flat_projects_va_capable_dumps_by_view_offset(tmp_path):
    heaps = _same_layout()
    paths = [sh.as_regioned_raw(tmp_path / "r0", [heaps[0]], stem="d0"),
             _raw_dumps(tmp_path, heaps[1:2])[0]]
    cm = build_consensus(paths)
    assert cm.msl_layout is None
    heap = cm.heap
    assert heap.status == ch.STATUS_OK
    assert heap.report["coordinate"] == ch.COORDINATE_FLAT_VIEW
    assert [d["projected"] for d in heap.per_dump] == [True, False]
    tcache_len = heaps[0].chunks[0].size
    assert heap.runs.role_at(tcache_len) == HeapRole.CHUNK_HEADER


def test_analysis_error_is_isolated(tmp_path, monkeypatch):
    paths = _msl_dumps(tmp_path, _same_layout())
    baseline = build_consensus(paths, allocator="off")

    def boom(*_args, **_kwargs):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(heap_analyze, "analyze_heap", boom)
    cm = build_consensus(paths)
    assert cm.heap.status == ch.STATUS_ERROR
    assert "parser exploded" in cm.heap.report["error"]
    assert len(cm.heap.runs) == 0
    assert np.asarray(cm.variance).tobytes() == np.asarray(baseline.variance).tobytes()


def test_unknown_allocator_name_rejected_up_front(tmp_path):
    with pytest.raises(ValueError, match="unknown allocator"):
        build_consensus(_raw_dumps(tmp_path, _same_layout()), allocator="nope")


def test_explicit_allocator_hint_forwarded(tmp_path):
    cm = build_consensus(_msl_dumps(tmp_path, _same_layout()),
                         allocator="ptmalloc2")
    assert cm.heap.report["allocator"] == "ptmalloc2"
    assert cm.heap.status == ch.STATUS_OK


# -- HeapRoleRuns unit behaviour --------------------------------------------------


def _runs():
    return HeapRoleRuns(
        np.array([0, 10, 20], dtype=np.int64), np.array([4, 6, 5], dtype=np.int64),
        np.array([HeapRole.CHUNK_HEADER, HeapRole.USER_DATA, HeapRole.MIXED],
                 dtype=np.uint8),
        np.array([3, 3, 2], dtype=np.uint16))


def test_window_mask_and_role_at():
    runs = _runs()
    window = runs.window(2, 10)
    assert window.tolist() == [1, 1, 0, 0, 0, 0, 0, 0, 2, 2]
    assert runs.role_at(21) == HeapRole.MIXED
    assert runs.role_at(5) == HeapRole.NONE
    mask = runs.mask({HeapRole.CHUNK_HEADER, HeapRole.MIXED}, 30)
    assert np.flatnonzero(mask).tolist() == [0, 1, 2, 3, 20, 21, 22, 23, 24]
    inverse = runs.mask({HeapRole.NONE}, 12)
    assert np.flatnonzero(inverse).tolist() == [4, 5, 6, 7, 8, 9]
    assert list(runs.runs_in(12, 10)) == [(12, 4, HeapRole.USER_DATA, 3),
                                          (20, 2, HeapRole.MIXED, 2)]


def test_npz_round_trip(tmp_path):
    runs = _runs()
    path = tmp_path / "heap_roles.npz"
    runs.to_npz(path)
    back = HeapRoleRuns.from_npz(path)
    for name in ("starts", "lengths", "roles", "agree"):
        assert np.array_equal(getattr(back, name), getattr(runs, name))
        assert getattr(back, name).dtype == getattr(runs, name).dtype
    assert back.fill == runs.fill
    assert back.to_dict() == runs.to_dict()


def test_merge_rule_ignores_uncovering_dumps_and_counts_agreement():
    header, user = int(HeapRole.CHUNK_HEADER), int(HeapRole.USER_DATA)
    piece = lambda s, n, r: (np.array(s, dtype=np.int64),  # noqa: E731
                             np.array(n, dtype=np.int64),
                             np.array(r, dtype=np.uint8))
    merged = merge_role_pieces([
        piece([0, 8], [8, 8], [header, user]),
        piece([0], [8], [header]),               # does not cover 8..16
        piece([0, 4], [4, 12], [header, user]),  # disagrees on 4..8
    ])
    triples = list(zip(merged.starts.tolist(), merged.lengths.tolist(),
                       merged.roles.tolist(), merged.agree.tolist()))
    assert triples == [(0, 4, header, 3), (4, 4, int(HeapRole.MIXED), 2),
                       (8, 8, user, 2)]


def test_empty_results_serialize():
    heap = ConsensusHeap.unavailable(ch.STATUS_NO_VA)
    summary = heap.to_dict()
    assert summary["report"]["status"] == ch.STATUS_NO_VA
    assert summary["runs"]["run_count"] == 0
    assert HeapChunkIndex.empty().chunk_at(0) is None
