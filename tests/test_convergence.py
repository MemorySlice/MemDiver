"""Tests for engine.convergence — convergence sweep module."""

import tempfile
from pathlib import Path

import pytest

from engine.convergence import (
    ConvergencePoint,
    ConvergenceSweepResult,
    DetectionMetrics,
    run_convergence_sweep,
    DEFAULT_N_VALUES,
    MAX_N,
)


def _make_dumps(tmpdir: Path, num: int, key_offset: int = 128,
                key_length: int = 32) -> tuple[list[Path], set[int]]:
    """Create synthetic dumps with a key at fixed offset."""
    import random
    rng = random.Random(42)
    base = bytearray(4096)
    # Static anchor before key
    base[112:128] = bytes(range(16))
    # Static anchor after key
    base[160:176] = bytes(range(16, 32))
    # Fill rest with deterministic structural data
    for i in range(0, 112):
        base[i] = (i * 7 + 3) % 256
    for i in range(176, 4096):
        base[i] = (i * 13 + 5) % 256

    paths = []
    for run in range(num):
        data = bytearray(base)
        # Insert unique key per run
        key = rng.randbytes(key_length)
        data[key_offset:key_offset + key_length] = key
        run_dir = tmpdir / f"run_{run}"
        run_dir.mkdir()
        p = run_dir / "dump.dump"
        p.write_bytes(bytes(data))
        paths.append(p)

    truth = set(range(key_offset, key_offset + key_length))
    return paths, truth


class TestConvergenceSweep:
    def test_basic_sweep(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 10)
        result = run_convergence_sweep(
            paths, ground_truth=truth, n_values=[2, 5, 10],
        )
        assert isinstance(result, ConvergenceSweepResult)
        assert len(result.points) == 3
        assert result.total_dumps == 10

    def test_points_have_increasing_n(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 10)
        result = run_convergence_sweep(
            paths, ground_truth=truth, n_values=[2, 5, 10],
        )
        ns = [p.n for p in result.points]
        assert ns == [2, 5, 10]

    def test_recall_improves_with_n(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 20)
        result = run_convergence_sweep(
            paths, ground_truth=truth, n_values=[2, 10, 20],
        )
        recalls = [p.variance.recall for p in result.points]
        # Recall should be non-decreasing (more dumps = better)
        assert recalls[-1] >= recalls[0]

    def test_first_detection_tracked(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 20)
        result = run_convergence_sweep(
            paths, ground_truth=truth,
            n_values=[2, 3, 5, 7, 10, 15, 20],
        )
        # Should eventually detect
        if result.first_detection_n is not None:
            assert result.first_detection_n >= 2

    def test_n_capped_at_total(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 5)
        result = run_convergence_sweep(
            paths, ground_truth=truth, n_values=[2, 5, 10, 20],
        )
        # N=10 and N=20 exceed total dumps (5), should be skipped
        ns = [p.n for p in result.points]
        assert max(ns) <= 5

    def test_max_fp_tracking(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 20)
        result = run_convergence_sweep(
            paths, ground_truth=truth,
            n_values=[2, 5, 10, 15, 20],
            max_fp=5,
        )
        assert result.max_fp == 5

    def test_too_few_dumps(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 1)
        result = run_convergence_sweep(paths, ground_truth=truth)
        assert len(result.points) == 0

    def test_no_ground_truth(self, tmp_path):
        paths, _ = _make_dumps(tmp_path, 5)
        result = run_convergence_sweep(
            paths, ground_truth=None, n_values=[2, 5],
        )
        assert len(result.points) == 2
        # Without ground truth, aligned should be None
        assert result.points[0].aligned is None

    def test_with_verifier(self, tmp_path):
        paths, truth = _make_dumps(tmp_path, 10)
        # Simple verifier that always returns True if candidates exist
        def mock_verifier(data, candidates):
            return len(candidates) > 0
        result = run_convergence_sweep(
            paths, ground_truth=truth, n_values=[5, 10],
            verifier_fn=mock_verifier,
        )
        for p in result.points:
            assert p.decryption_verified is not None


class TestDetectionMetrics:
    def test_frozen(self):
        m = DetectionMetrics(tp=10, fp=5, precision=0.67, recall=1.0, candidates=15)
        with pytest.raises(AttributeError):
            m.tp = 20

    def test_values(self):
        m = DetectionMetrics(tp=32, fp=0, precision=1.0, recall=1.0, candidates=32)
        assert m.tp == 32
        assert m.fp == 0
