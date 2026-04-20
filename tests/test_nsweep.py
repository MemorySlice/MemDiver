"""Tests for engine.nsweep — N-scaling harness and report emission."""

import json

import numpy as np

from engine.nsweep import (
    NSweepResult,
    run_nsweep,
    write_nsweep_artifacts,
)


class _FakeSource:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read_all(self) -> bytes:
        return self._data


def _synth_dumps(num: int = 20, size: int = 1024, seed: int = 21):
    rng = np.random.default_rng(seed)
    base = rng.integers(0, 256, size, dtype=np.uint8)
    sources = []
    for _ in range(num):
        d = base.copy()
        d[256:288] = rng.integers(0, 256, 32, dtype=np.uint8)
        sources.append(_FakeSource(d.tobytes()))
    return sources


def _target_from(sources) -> bytes:
    return sources[0].read_all()[256:288]


def test_returns_empty_result_for_no_sources():
    result = run_nsweep(
        sources=[], n_values=[1, 3],
        reduce_kwargs={}, oracle=lambda c: False,
    )
    assert isinstance(result, NSweepResult)
    assert result.points == []
    assert result.first_hit_n is None


def test_finds_hit_and_builds_headline():
    sources = _synth_dumps(num=20)
    target = _target_from(sources)

    def oracle(c):
        return c == target

    result = run_nsweep(
        sources, n_values=[1, 5, 10, 20],
        reduce_kwargs=dict(
            alignment=8, density_threshold=0.5,
            entropy_window=32, entropy_threshold=4.0,
            min_variance=500.0, min_region=16,
        ),
        oracle=oracle, key_sizes=(32,), stride=8,
    )
    assert result.first_hit_n is not None
    assert result.first_hit_offset == 256
    assert "decrypted" in result.headline()


def test_no_hit_headline_mentions_exhaustion():
    sources = _synth_dumps(num=10)

    def always_false(_):
        return False

    result = run_nsweep(
        sources, n_values=[3, 5, 10],
        reduce_kwargs=dict(
            alignment=8, density_threshold=0.5,
            entropy_window=32, entropy_threshold=4.0,
            min_variance=500.0, min_region=16,
        ),
        oracle=always_false, key_sizes=(32,), stride=8,
    )
    assert result.first_hit_n is None
    assert "without a hit" in result.headline()


def test_write_artifacts_creates_all_three(tmp_path):
    sources = _synth_dumps(num=10)
    target = _target_from(sources)

    def oracle(c):
        return c == target

    result = run_nsweep(
        sources, n_values=[1, 5, 10],
        reduce_kwargs=dict(
            alignment=8, density_threshold=0.5,
            entropy_window=32, entropy_threshold=4.0,
            min_variance=500.0, min_region=16,
        ),
        oracle=oracle,
    )
    paths = write_nsweep_artifacts(result, tmp_path / "out")
    for key in ("json", "md", "html"):
        assert paths[key].exists()
        assert paths[key].stat().st_size > 0

    rep = json.loads(paths["json"].read_text())
    assert rep["total_dumps"] == 10
    assert rep["headline"] == result.headline()

    md = paths["md"].read_text()
    assert "N-sweep report" in md
    assert "| N |" in md

    html = paths["html"].read_text()
    assert "plotly" in html.lower()
    assert "Survivors vs N" in html


def test_timing_fields_populated():
    sources = _synth_dumps(num=5)
    target = _target_from(sources)
    result = run_nsweep(
        sources, n_values=[3, 5],
        reduce_kwargs=dict(
            alignment=8, density_threshold=0.5,
            entropy_window=32, entropy_threshold=4.0,
            min_variance=500.0, min_region=16,
        ),
        oracle=lambda c: c == target,
    )
    for p in result.points:
        assert p.timing.consensus_ms >= 0.0
        assert p.timing.reduce_ms >= 0.0
        assert p.timing.brute_force_ms >= 0.0
