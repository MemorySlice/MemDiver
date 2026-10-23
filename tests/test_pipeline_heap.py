"""Heap roles through the app producers: consensus artifact round trip,
``search_reduce`` / ``analyze_candidates`` ``heap_policy``, aligned window.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from memdiver.app import tools_pipeline as tp
from memdiver.app.tools_consensus import aligned_window_from_vector
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.consensus_heap import load_heap_npz
from memdiver.engine.consensus_service import build_consensus
from memdiver.heap import analyze as heap_analyze
from memdiver.heap.model import HeapRole
from tests.test_candidate_pipeline_heap import (
    _spans,
    _without_heap,
    slab_of,
    write_corpus,
)


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


@pytest.fixture
def staged(tmp_path):
    paths, heap = write_corpus(tmp_path / "dumps")
    out = tmp_path / "consensus"
    meta = tp.consensus(dump_paths=paths, output_dir=str(out))
    return paths, heap, out, meta


def _covers(rows, span):
    start, length = span
    return any(r["offset"] <= start and start + length <= r["offset"] + r["length"]
               for r in rows)


def _search(meta, out_dir, policy, **kwargs):
    return tp.search_reduce(
        variance_path=meta["variance_path"],
        reference_path=meta["reference_path"],
        num_dumps=meta["num_dumps"], output_dir=str(out_dir),
        heap_policy=policy, max_returned=0, **kwargs)


# -- consensus stage artifact -----------------------------------------------------


def test_consensus_writes_heap_npz_and_json_block(staged):
    paths, _heap, out, meta = staged
    block = json.loads((out / "consensus.json").read_text())["heap"]
    assert block == meta["heap"]
    assert block["status"] == "ok"
    assert block["report"]["dumps_projected"] == len(paths)
    assert len(block["per_dump"]) == len(paths)
    assert Path(block["heap_roles_path"]) == out / "heap_roles.npz"
    runs, chunks = load_heap_npz(block["heap_roles_path"])
    cm = build_consensus(paths)
    for name in ("starts", "lengths", "roles", "agree"):
        assert np.array_equal(getattr(runs, name), getattr(cm.heap.runs, name))
    for name in ("slab_starts", "sizes", "states", "agree"):
        assert np.array_equal(getattr(chunks, name), getattr(cm.heap.chunks, name))


def test_consensus_allocator_off_has_no_heap_and_drops_stale_npz(staged):
    paths, _heap, out, _meta = staged
    assert (out / "heap_roles.npz").is_file()
    meta = tp.consensus(dump_paths=paths, output_dir=str(out), allocator="off")
    assert "heap" not in meta
    assert "heap" not in json.loads((out / "consensus.json").read_text())
    assert not (out / "heap_roles.npz").exists()


def test_consensus_unknown_allocator_is_invalid_input(staged):
    paths, _heap, out, _meta = staged
    with pytest.raises(CapabilityError) as exc:
        tp.consensus(dump_paths=paths, output_dir=str(out), allocator="nope")
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# -- search_reduce ----------------------------------------------------------------


def test_search_reduce_golden_annotate_vs_off(staged, tmp_path):
    _paths, _heap, _out, meta = staged
    off = _search(meta, tmp_path / "off", "off")
    annotate = _search(meta, tmp_path / "ann", "annotate")
    assert off["stages"] == annotate["stages"]
    assert _without_heap({"regions": annotate["regions"], "thresholds": {}}) == {
        "regions": off["regions"], "thresholds": {}}
    off_file = json.loads(Path(off["candidates_path"]).read_text())
    ann_file = json.loads(Path(annotate["candidates_path"]).read_text())
    assert _without_heap(ann_file) == off_file


def test_search_reduce_mask_matches_engine(staged, tmp_path):
    paths, heap, _out, meta = staged
    masked = _search(meta, tmp_path / "mask", "mask")
    assert masked["stages"]["heap_masked"] > 0
    cm = build_consensus(paths)
    spans = {k: (slab_of(cm, va), n) for k, (va, n) in _spans(heap).items()}
    assert not _covers(masked["regions"], spans["wild"])
    assert _covers(masked["regions"], spans["key"])
    off = _search(meta, tmp_path / "off", "off")
    assert _covers(off["regions"], spans["wild"])


def test_search_reduce_without_npz(staged, tmp_path):
    _paths, _heap, out, meta = staged
    (out / "heap_roles.npz").unlink()
    annotate = _search(meta, tmp_path / "ann", "annotate")
    assert all("heap" not in r for r in annotate["regions"])
    with pytest.raises(CapabilityError) as exc:
        _search(meta, tmp_path / "mask", "mask")
    assert exc.value.category == ErrorCategory.PRECONDITION
    assert "heap_roles.npz" in str(exc.value)


def test_search_reduce_rejects_unknown_policy(staged, tmp_path):
    _paths, _heap, _out, meta = staged
    with pytest.raises(CapabilityError) as exc:
        _search(meta, tmp_path / "x", "bogus")
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# -- analyze_candidates -----------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_project_db(monkeypatch):
    """Keep analyze_candidates' best-effort persistence off the real DB."""
    from memdiver.app import composition

    monkeypatch.setattr(composition, "resolve_project_db", lambda *a, **k: None)


def _candidates(paths, **kwargs):
    return tp.analyze_candidates(dump_paths=paths, max_returned=0, **kwargs)


def test_analyze_candidates_golden_and_status(staged):
    paths = staged[0]
    off = _candidates(paths, heap_policy="off")
    annotate = _candidates(paths)
    assert "heap_status" not in off
    assert annotate["heap_status"] == "ok"
    assert annotate["stages"] == off["stages"]
    assert [{k: v for k, v in r.items() if k != "heap"}
            for r in annotate["regions"]] == off["regions"]
    assert all("heap" in r for r in annotate["regions"])


def test_analyze_candidates_mask_needs_heap(staged):
    paths = staged[0]
    masked = _candidates(paths, heap_policy="mask")
    assert masked["stages"]["heap_masked"] > 0
    with pytest.raises(CapabilityError) as exc:
        _candidates(paths, heap_policy="mask", allocator="off")
    assert exc.value.category == ErrorCategory.PRECONDITION


# -- aligned window ---------------------------------------------------------------


def test_aligned_window_heap_roles_parallel_to_classes(staged):
    paths, heap, _out, _meta = staged
    cm = build_consensus(paths)
    key_va, key_len = _spans(heap)["key"]
    start = slab_of(cm, key_va) - 32
    window = aligned_window_from_vector(cm, slab_offset=start, length=128,
                                        include_bytes=False)
    assert window["heap_status"] == "ok"
    roles = window["heap_roles"]
    assert len(roles) == len(window["classes"]) == window["length"]
    assert roles == cm.heap.runs.window(start, window["length"]).tolist()
    assert roles[32:32 + key_len] == [int(HeapRole.USER_DATA)] * key_len
    names = window["heap_role_names"]
    assert names[str(int(HeapRole.USER_DATA))] == "user_data"
    assert names[str(int(HeapRole.UNCOVERED))] == "uncovered"


def test_aligned_window_without_heap_has_no_heap_keys(staged):
    paths = staged[0]
    cm = build_consensus(paths, allocator="off")
    window = aligned_window_from_vector(cm, slab_offset=0, length=64,
                                        include_bytes=False)
    assert not {"heap_roles", "heap_role_names", "heap_status"} & set(window)
