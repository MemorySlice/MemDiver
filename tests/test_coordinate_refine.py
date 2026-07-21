"""Tests for engine.coordinate_refine (correspondence / alignment-quality)."""
from __future__ import annotations

import numpy as np

from memdiver.engine.coordinate_refine import correspondence_score


def test_aligned_stack_scores_high():
    rng = np.random.default_rng(0)
    base = rng.integers(0, 256, 256, dtype=np.uint8)
    stack = np.tile(base, (6, 1))               # identical content every run
    res = correspondence_score(stack, window=32, max_lag=64)
    assert res.score > 0.9
    assert res.lag_consistency == 1.0
    assert res.peak_ncc > 0.9


def test_jittered_stack_scores_lower_than_aligned():
    rng = np.random.default_rng(1)
    base = rng.integers(0, 256, 256, dtype=np.uint8)
    stack = np.zeros((6, 256), dtype=np.uint8)
    stack[0] = base
    for r in range(1, 6):
        shift = int(rng.integers(-20, 21))
        stack[r] = np.roll(base, shift)          # same content, different offset
    res = correspondence_score(stack, window=32, max_lag=64)
    aligned = correspondence_score(np.tile(base, (6, 1)), window=32, max_lag=64)
    # content still matches (high NCC) but the lag wanders → lower stability
    assert res.score < aligned.score


def test_noise_stack_scores_low():
    rng = np.random.default_rng(2)
    stack = rng.integers(0, 256, (6, 256), dtype=np.uint8)  # independent per run
    res = correspondence_score(stack, window=32, max_lag=64)
    assert res.score < 0.5


def test_single_run_is_degenerate():
    stack = np.zeros((1, 256), dtype=np.uint8)
    res = correspondence_score(stack)
    assert res.score == 0.0
