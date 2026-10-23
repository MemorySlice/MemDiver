"""Heap-aware search-space reduction (``reduce_search_space(heap_policy=...)``).

Corpus: four synthetic glibc heaps sharing one layout, written as native
``.msl``. Three planted high-variance spans (bytes alternate between ``r`` and
``r ^ 0x80`` across dumps, so every byte's variance is exactly 4096):

* ``KEY``      — 64 bytes of live user data (in-use chunk, ``USER_DATA``);
* ``WILD``     — 256 bytes inside the top chunk (``TOP``): a metadata false
  positive the ``mask`` policy must drop;
* ``STALE``    — 32 bytes of a tcache'd chunk's stale payload (``FREE_DATA``):
  kept by every policy but flagged ``residual`` by ``annotate``.

Golden invariant: ``off``, ``annotate`` and no heap input at all produce the
SAME candidate set, stages and scores.
"""

import random

import numpy as np
import pytest

from memdiver.engine import candidate_heap
from memdiver.engine.candidate_pipeline import (
    HEAP_POLICIES,
    reduce_search_space,
)
from memdiver.engine.consensus_heap import HeapChunkIndex, HeapRoleRuns
from memdiver.engine.consensus_service import build_consensus
from memdiver.heap import analyze as heap_analyze
from memdiver.heap.model import ChunkState, HeapRole
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_heap as sh

N_DUMPS = 4
_RW = 0x03
KEY_LEN, WILD_LEN, STALE_LEN = 64, 256, 32


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


# -- corpus -----------------------------------------------------------------------


def _spans(heap):
    """VA of each planted span, from the fixture's expected chunks."""
    in_use = next(c for c in heap.chunks if c.size == 0x100)
    top = heap.chunks[-1]
    stale = next(c for c in heap.chunks
                 if c.state is ChunkState.CACHED and c.size == 0x40)
    return {
        "key": (in_use.va + in_use.header_len + 32, KEY_LEN),
        "wild": (top.va + top.header_len + 64, WILD_LEN),
        # Skip the 16-byte tcache next/key (FREE_LINK) at the user pointer.
        "stale": (stale.va + stale.header_len + 16, STALE_LEN),
    }


def _planted_heap(dump_index: int):
    heap = sh.glibc_heap()
    data = bytearray(heap.data)
    flip = 0x80 if dump_index % 2 else 0x00
    for name, (va, length) in _spans(heap).items():
        base = random.Random(name).randbytes(length)
        off = va - heap.base_va
        data[off:off + length] = bytes(b ^ flip for b in base)
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


def write_corpus(tmp_path):
    """Write the four planted ``.msl`` dumps; return ``(paths, anchor_heap)``."""
    heaps = [_planted_heap(i) for i in range(N_DUMPS)]
    paths = [_write_msl(tmp_path / f"d{i}.msl", h) for i, h in enumerate(heaps)]
    return [str(p) for p in paths], heaps[0]


def slab_of(cm, va):
    for slab, page, vas in cm.msl_layout:
        if vas[0] <= va < vas[0] + page:
            return slab + va - vas[0]
    raise AssertionError(f"{va:#x} not in slab")


@pytest.fixture
def corpus(tmp_path):
    paths, heap = write_corpus(tmp_path)
    cm = build_consensus(paths)
    assert cm.heap is not None and cm.heap.status == "ok"
    spans = {name: (slab_of(cm, va), n) for name, (va, n) in _spans(heap).items()}
    return cm, spans


def _reduce(cm, policy=None, **kwargs):
    heap_kwargs = {} if policy is None else {
        "heap_runs": cm.heap.runs, "heap_chunks": cm.heap.chunks,
        "heap_policy": policy}
    return reduce_search_space(cm.variance, cm.reference_bytes, cm.num_dumps,
                               **heap_kwargs, **kwargs)


def _covering(result, span):
    start, length = span
    return [r for r in result.regions
            if r.offset <= start and start + length <= r.offset + r.length]


def _without_heap(payload):
    regions = [{k: v for k, v in r.items() if k != "heap"}
               for r in payload["regions"]]
    thresholds = {k: v for k, v in payload["thresholds"].items()
                  if k != "heap_policy"}
    return {**payload, "regions": regions, "thresholds": thresholds}


# -- golden: off / annotate change nothing ----------------------------------------


def test_corpus_plants_survive_without_heap(corpus):
    cm, spans = corpus
    result = _reduce(cm)
    for name in ("key", "wild", "stale"):
        assert _covering(result, spans[name]), f"{name} not a candidate"


@pytest.mark.parametrize("order", ["offset", "rank"])
def test_golden_off_and_annotate_identical_to_no_heap(corpus, order):
    cm, _spans_ = corpus
    baseline = _reduce(cm, order=order).to_dict()
    off = _reduce(cm, "off", order=order).to_dict()
    annotate = _reduce(cm, "annotate", order=order).to_dict()
    assert off == baseline                       # byte-identical, no heap keys
    assert _without_heap(annotate) == baseline   # same set, stages, scores
    assert all("heap" in r for r in annotate["regions"])
    assert "heap_masked" not in annotate["stages"]
    assert all("heap" not in r["score_components"] for r in annotate["regions"])


@pytest.mark.parametrize("policy", HEAP_POLICIES)
def test_no_heap_runs_is_identical_under_every_policy(corpus, policy):
    cm, _spans_ = corpus
    baseline = _reduce(cm).to_dict()
    result = reduce_search_space(cm.variance, cm.reference_bytes, cm.num_dumps,
                                 heap_policy=policy)
    assert result.to_dict() == baseline


def test_golden_on_random_arrays():
    rng = np.random.default_rng(7)
    size = 4096
    variance = rng.uniform(0, 6000, size).astype(np.float32)
    reference = rng.integers(0, 256, size, dtype=np.uint8).tobytes()
    runs = HeapRoleRuns(
        np.array([0, 512, 1024], dtype=np.int64),
        np.array([256, 256, 2048], dtype=np.int64),
        np.array([HeapRole.ALLOCATOR_META, HeapRole.USER_DATA, HeapRole.TOP],
                 dtype=np.uint8),
        np.array([3, 3, 3], dtype=np.uint16))
    kwargs = dict(min_variance=0.0, density_threshold=0.1)
    base = reduce_search_space(variance, reference, 4, **kwargs).to_dict()
    for policy in ("off", "annotate"):
        got = reduce_search_space(variance, reference, 4, heap_runs=runs,
                                  heap_policy=policy, **kwargs).to_dict()
        assert _without_heap(got) == base


def test_unknown_policy_rejected():
    with pytest.raises(ValueError, match="heap_policy"):
        reduce_search_space(np.zeros(64, dtype=np.float32), bytes(64), 4,
                            heap_policy="nope")


# -- annotate ---------------------------------------------------------------------


def test_annotate_flags_stale_key_as_residual(corpus):
    cm, spans = corpus
    result = _reduce(cm, "annotate")
    (stale,) = _covering(result, spans["stale"])
    assert stale.heap["residual"] is True
    assert stale.heap["chunk"]["state"] == ChunkState.CACHED.value
    assert stale.heap["role_counts"].get("free_data", 0) >= STALE_LEN
    (key,) = _covering(result, spans["key"])
    assert key.heap["residual"] is False
    assert key.heap["chunk"]["state"] == ChunkState.IN_USE.value
    assert key.heap["chunk"]["offset_in_chunk"] == key.offset - key.heap["chunk"]["start"]
    assert key.heap["agreement"] == N_DUMPS


def test_annotation_shape():
    runs = HeapRoleRuns(
        np.array([10], dtype=np.int64), np.array([10], dtype=np.int64),
        np.array([HeapRole.USER_DATA], dtype=np.uint8),
        np.array([2], dtype=np.uint16))
    chunks = HeapChunkIndex(np.array([0], dtype=np.int64),
                            np.array([32], dtype=np.int64),
                            np.array([0], dtype=np.uint8),
                            np.array([2], dtype=np.uint16))
    ann = candidate_heap.region_heap_annotation(runs, chunks, 5, 20)
    assert ann["role_counts"] == {"user_data": 10, "none": 10}
    assert ann["chunk"] == {"start": 0, "size": 32, "state": "in_use",
                            "offset_in_chunk": 5, "agree": 2}
    assert ann["residual"] is False and ann["agreement"] == 2
    outside = candidate_heap.region_heap_annotation(runs, chunks, 100, 4)
    assert outside["chunk"] is None and outside["agreement"] is None


def test_score_adjustment_rules():
    meta = {"role_counts": {"user_data": 8, "chunk_header": 8}}
    user = {"role_counts": {"user_data": 16}}
    other = {"role_counts": {"user_data": 8, "free_data": 8}}
    assert candidate_heap.heap_score_adjustment(meta, 16) == -0.5
    assert candidate_heap.heap_score_adjustment(user, 16) == 0.1
    assert candidate_heap.heap_score_adjustment(other, 16) == 0.0


# -- mask -------------------------------------------------------------------------


def test_mask_drops_top_false_positive_and_keeps_key(corpus):
    cm, spans = corpus
    result = _reduce(cm, "mask")
    assert not _covering(result, spans["wild"])
    (key,) = _covering(result, spans["key"])
    assert _covering(result, spans["stale"])
    assert result.stages.heap_masked >= WILD_LEN
    assert result.to_dict()["stages"]["heap_masked"] == result.stages.heap_masked
    assert result.thresholds["heap_policy"] == "mask"
    metadata = candidate_heap.metadata_mask(cm.heap.runs, cm.size)
    for region in result.regions:
        assert not metadata[region.offset:region.offset + region.length].any()


def test_mask_scores_include_heap_component(corpus):
    cm, spans = corpus
    result = _reduce(cm, "mask")
    (key,) = _covering(result, spans["key"])
    assert key.score_components.heap == pytest.approx(0.1)
    weighted = key.score_components.total - key.score_components.heap
    assert key.score == pytest.approx(weighted + 0.1)
    assert key.to_dict()["score_components"]["heap"] == pytest.approx(0.1)
    annotate = _covering(_reduce(cm, "annotate"), spans["key"])[0]
    assert key.score == pytest.approx(annotate.score + 0.1)
