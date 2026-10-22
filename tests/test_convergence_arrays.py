"""Array-backed convergence sweep == the former set-of-offsets implementation.

The reference functions below are verbatim copies of ``engine/convergence.py``
before the numpy rewrite (set of every high-entropy byte offset, one-shot
consensus per N). Every public output -- dataclasses and the serialised JSON --
must be identical.
"""

import json
import random
import tracemalloc
from pathlib import Path
from typing import Set

import numpy as np
import pytest

from memdiver.core.alignment_filter import alignment_filter
from memdiver.core.entropy import compute_entropy_profile
from memdiver.core.variance import ByteClass
from memdiver.engine import convergence as conv
from memdiver.engine.consensus import ConsensusVector
from memdiver.engine.convergence import (
    ConvergencePoint,
    ConvergenceSweepResult,
    DEFAULT_N_VALUES,
    DetectionMetrics,
    MAX_N,
    run_convergence_sweep,
)
from memdiver.engine.serializer import serialize_convergence_result


# ---------------------------------------------------------------------------
# Reference implementation (copied from the pre-rewrite engine/convergence.py)
# ---------------------------------------------------------------------------


def _ref_compute_metrics(candidates: Set[int], truth: Set[int]) -> DetectionMetrics:
    tp = len(candidates & truth)
    fp = len(candidates - truth)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / len(truth) if truth else 0.0
    return DetectionMetrics(
        tp=tp, fp=fp, precision=precision, recall=recall,
        candidates=len(candidates),
    )


def _ref_entropy_candidates(dump_data: bytes, threshold: float = 4.5,
                            window: int = 32) -> Set[int]:
    profile = compute_entropy_profile(dump_data, window=window, step=1)
    candidates: Set[int] = set()
    for offset, entropy in profile:
        if entropy >= threshold:
            for b in range(offset, min(offset + window, len(dump_data))):
                candidates.add(b)
    return candidates


def _ref_variance_candidates(cm: ConsensusVector) -> Set[int]:
    return {i for i, c in enumerate(cm.classifications)
            if c == ByteClass.KEY_CANDIDATE}


def _ref_run_convergence_sweep(
    dump_paths, ground_truth=None, n_values=None, entropy_threshold=4.5,
    alignment_params=None, verifier_fn=None, recall_threshold=0.875, max_fp=0,
):
    if n_values is None:
        n_values = [n for n in DEFAULT_N_VALUES if n <= MAX_N]
    total = len(dump_paths)
    n_values = [n for n in n_values if n <= min(total, MAX_N)]
    if not n_values or total < 2:
        return ConvergenceSweepResult(total_dumps=total, max_fp=max_fp)
    align_params = alignment_params or {
        "block_size": 32, "alignment": 16, "density_threshold": 0.75,
    }
    first_data = dump_paths[0].read_bytes()
    ent_cands = _ref_entropy_candidates(first_data, entropy_threshold)
    result = ConvergenceSweepResult(total_dumps=total, max_fp=max_fp)
    for n in n_values:
        cm = ConsensusVector()
        cm.build(dump_paths[:n])
        var_cands = _ref_variance_candidates(cm)
        var_m = _ref_compute_metrics(var_cands, ground_truth) if ground_truth else None
        combined = ent_cands & var_cands
        com_m = _ref_compute_metrics(combined, ground_truth) if ground_truth else None
        aligned = alignment_filter(combined, **align_params)
        ali_m = _ref_compute_metrics(aligned, ground_truth) if ground_truth else None
        dec = None
        if verifier_fn is not None:
            dec = verifier_fn(first_data, aligned)
        result.points.append(ConvergencePoint(
            n=n,
            variance=var_m or DetectionMetrics(0, 0, 0.0, 0.0, len(var_cands)),
            combined=com_m, aligned=ali_m, decryption_verified=dec,
        ))
        if ground_truth:
            if result.first_detection_n is None and var_m and var_m.recall >= recall_threshold:
                result.first_detection_n = n
            if result.first_fp_target_n is None and ali_m and ali_m.fp <= max_fp and ali_m.recall >= recall_threshold:
                result.first_fp_target_n = n
        if result.first_decryption_n is None and dec is True:
            result.first_decryption_n = n
    return result


# ---------------------------------------------------------------------------
# Synthetic dumps: structured/low-entropy background, random noise regions,
# planted keys (some aligned, some not), and unequal sizes.
# ---------------------------------------------------------------------------


def _make_dumps(tmp: Path, num: int, size: int = 64 * 1024, seed: int = 7):
    rng = random.Random(seed)
    base = bytearray((i * 13 + 5) % 251 for i in range(size))
    base[1000:3000] = rng.randbytes(2000)            # static high-entropy
    for start in range(8192, size, 9001):             # sparse zero runs
        base[start:start + 200] = bytes(200)
    keys = [(4096, 32), (12_345, 32), (20_480, 48), (size - 40, 32)]
    truth = set()
    for off, length in keys:
        truth.update(range(off, off + length))
    paths = []
    for run in range(num):
        data = bytearray(base)
        for off, length in keys:
            data[off:off + length] = rng.randbytes(length)
        data[30_000:30_300] = rng.randbytes(300)       # varying noise
        if run % 3 == 2:
            data = data[:size - 17]                    # unequal sizes
        p = tmp / f"dump_{run}.dump"
        p.write_bytes(bytes(data))
        paths.append(p)
    return paths, truth


def _assert_identical(new, ref):
    assert new == ref
    assert json.dumps(serialize_convergence_result(new), sort_keys=True) == \
        json.dumps(serialize_convergence_result(ref), sort_keys=True)


@pytest.mark.parametrize("n_values", [None, [2], [2, 3, 5], [3, 7, 9]])
def test_sweep_matches_reference(tmp_path, n_values):
    paths, truth = _make_dumps(tmp_path, 9)
    kwargs = dict(ground_truth=truth, n_values=n_values)
    _assert_identical(run_convergence_sweep(paths, **kwargs),
                      _ref_run_convergence_sweep(paths, **kwargs))


def test_sweep_matches_reference_without_truth(tmp_path):
    paths, _ = _make_dumps(tmp_path, 5)
    _assert_identical(run_convergence_sweep(paths, n_values=[2, 4, 5]),
                      _ref_run_convergence_sweep(paths, n_values=[2, 4, 5]))


@pytest.mark.parametrize("threshold,align", [
    (3.0, None),
    (4.5, {"block_size": 16, "alignment": 8, "density_threshold": 0.5}),
    (4.0, {"block_size": 48, "alignment": 16, "density_threshold": 0.9}),
    (4.5, {"block_size": 32, "alignment": 16, "density_threshold": 0.0}),
])
def test_sweep_matches_reference_params(tmp_path, threshold, align):
    paths, truth = _make_dumps(tmp_path, 6, seed=11)
    kwargs = dict(ground_truth=truth, n_values=[2, 3, 6],
                  entropy_threshold=threshold, alignment_params=align,
                  max_fp=3)
    _assert_identical(run_convergence_sweep(paths, **kwargs),
                      _ref_run_convergence_sweep(paths, **kwargs))


def test_verifier_receives_identical_aligned_set(tmp_path):
    paths, truth = _make_dumps(tmp_path, 5)
    seen_new, seen_ref = [], []

    def verifier(log):
        def fn(data, aligned):
            assert isinstance(aligned, set)
            log.append((len(data), sorted(aligned)))
            return len(aligned) >= 32
        return fn

    new = run_convergence_sweep(paths, ground_truth=truth,
                                n_values=[2, 3, 5], verifier_fn=verifier(seen_new))
    ref = _ref_run_convergence_sweep(paths, ground_truth=truth,
                                     n_values=[2, 3, 5], verifier_fn=verifier(seen_ref))
    _assert_identical(new, ref)
    assert seen_new == seen_ref


def test_truth_outside_dump_range(tmp_path):
    paths, truth = _make_dumps(tmp_path, 4)
    truth = truth | {-5, 10 ** 9}
    kwargs = dict(ground_truth=truth, n_values=[2, 4])
    _assert_identical(run_convergence_sweep(paths, **kwargs),
                      _ref_run_convergence_sweep(paths, **kwargs))


# ---------------------------------------------------------------------------
# Helper-level equivalence (incl. slab boundaries of the entropy scan)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("slab", [1, 7, 64, 1 << 20])
@pytest.mark.parametrize("size", [0, 31, 32, 33, 500, 3000])
def test_entropy_mask_matches_set(monkeypatch, slab, size):
    monkeypatch.setattr(conv, "ENTROPY_SLAB_POSITIONS", slab)
    rng = random.Random(size)
    data = bytearray(rng.randbytes(size))
    for start in range(0, size, 400):
        data[start:start + 150] = bytes(150)
    data = bytes(data)
    for threshold in (0.0, 3.5, 4.5, 9.0):
        mask = conv._entropy_mask(data, threshold)
        assert set(np.flatnonzero(mask).tolist()) == \
            _ref_entropy_candidates(data, threshold)


def test_aligned_positions_matches_alignment_filter():
    rng = random.Random(3)
    for _ in range(200):
        cands = {rng.randrange(0, 2000) for _ in range(rng.randrange(0, 600))}
        params = {"block_size": rng.choice([0, 8, 16, 32, 33]),
                  "alignment": rng.choice([0, 1, 4, 16]),
                  "density_threshold": rng.choice([0.0, 0.25, 0.75, 1.0])}
        pos = np.array(sorted(cands), dtype=np.int64)
        got = conv._aligned_positions(pos, **params)
        assert set(got.tolist()) == alignment_filter(cands, **params)


def test_metrics_helpers_match_set_metrics():
    rng = random.Random(5)
    for _ in range(100):
        size = rng.randrange(1, 500)
        cands = {rng.randrange(0, size) for _ in range(rng.randrange(0, size))}
        truth = {rng.randrange(-10, size + 10) for _ in range(rng.randrange(1, 50))}
        mask = np.zeros(size, dtype=bool)
        mask[list(cands)] = True
        truth_arr = conv._truth_array(truth)
        ref = _ref_compute_metrics(cands, truth)
        assert conv._metrics_from_mask(mask, truth_arr) == ref
        pos = np.array(sorted(cands), dtype=np.int64)
        assert conv._metrics_from_positions(pos, truth_arr) == ref


# ---------------------------------------------------------------------------
# Budget pass-through and memory
# ---------------------------------------------------------------------------


def test_upfront_budget_check_refuses_and_force_proceeds(tmp_path):
    from memdiver.core.memory_budget import CapabilityError  # noqa: F401
    paths, truth = _make_dumps(tmp_path, 4)
    with pytest.raises(Exception) as exc:
        run_convergence_sweep(paths, ground_truth=truth, n_values=[2, 4],
                              budget=1024)
    assert "memory_budget_exceeded" in repr(exc.value) or \
        getattr(exc.value, "code", None) == "memory_budget_exceeded"
    forced = run_convergence_sweep(paths, ground_truth=truth, n_values=[2, 4],
                                   budget=1024, force=True)
    _assert_identical(forced, _ref_run_convergence_sweep(
        paths, ground_truth=truth, n_values=[2, 4]))


def _write_random_dumps(tmp: Path, num: int, size: int):
    rng = np.random.default_rng(0)
    base = rng.integers(0, 256, size, dtype=np.uint8)
    paths, truth = [], set(range(1 << 20, (1 << 20) + 32))
    for run in range(num):
        data = base.copy()
        data[1 << 20:(1 << 20) + 32] = rng.integers(0, 256, 32, dtype=np.uint8)
        p = tmp / f"big_{run}.dump"
        p.write_bytes(data.tobytes())
        paths.append(p)
    return paths, truth


def test_peak_memory_16mib_x4(tmp_path):
    size = 16 << 20
    paths, truth = _write_random_dumps(tmp_path, 4, size)
    tracemalloc.start()
    try:
        result = run_convergence_sweep(paths, ground_truth=truth,
                                       n_values=[2, 3, 4], force=True)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.points[-1].variance.tp > 0
    # Former implementation: >256 MiB step-1 profile plus a set of ~16 M
    # Python ints (GBs). Now: a few bytes per position plus bounded slabs.
    assert peak < 12 * size, f"peak {peak / 2**20:.1f} MiB"
