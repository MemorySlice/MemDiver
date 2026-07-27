"""Tests for engine.nsweep — N-scaling harness and report emission."""

import json

import numpy as np

from memdiver.app.reports import write_nsweep_artifacts
from memdiver.core.variance import WelfordVariance
from memdiver.engine.nsweep import (
    NSweepResult,
    _fold_until,
    _probe_min_size,
    run_nsweep,
)
from memdiver.presentation.reports import nsweep_headline


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
    assert "decrypted" in nsweep_headline(result)


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
    assert "without a hit" in nsweep_headline(result)


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
    assert rep["headline"] == nsweep_headline(result)

    md = paths["md"].read_text()
    assert "N-sweep report" in md
    assert "| N |" in md

    html = paths["html"].read_text()
    assert "plotly" in html.lower()
    assert "Survivors vs N" in html


def _diluted_dumps(num: int = 4, size: int = 1024, seed: int = 7):
    """Dumps whose key window sits in the diluted band (< default floor 3000).

    Dump 0 carries the target; dumps 1..N-1 share a constant ``target - 113``
    key window, so per-byte population variance there is 3*113**2/16 ~= 2394
    at N=4 (below 3000). Everything else is identical across dumps (variance 0),
    so a reduce at min_variance=3000 yields no candidates and no hit.
    """
    rng = np.random.default_rng(seed)
    base = rng.integers(0, 256, size, dtype=np.uint8)
    p0 = np.arange(150, 182, dtype=np.uint8)              # distinct -> high entropy
    p1 = (p0.astype(np.int16) - 113).astype(np.uint8)     # constant delta, no wrap
    sources = []
    for i in range(num):
        d = base.copy()
        d[256:288] = p0 if i == 0 else p1
        sources.append(_FakeSource(d.tobytes()))
    return sources


_DILUTED_REDUCE = dict(
    alignment=8, density_threshold=0.5, entropy_window=32,
    entropy_threshold=4.0, min_variance=3000.0, min_region=16,
)


def test_escalate_false_leaves_result_unchanged():
    sources = _diluted_dumps()
    result = run_nsweep(
        sources, n_values=[3, 4], reduce_kwargs=dict(_DILUTED_REDUCE),
        oracle=lambda c: c == sources[0].read_all()[256:288], key_sizes=(32,), stride=8,
    )
    # No checkpoint hit and escalation not requested -> no escalation field.
    assert result.first_hit_n is None
    assert result.escalation is None
    assert "escalation" not in result.to_dict()


def test_escalate_recovers_diluted_key_at_terminal_n():
    sources = _diluted_dumps()
    target = sources[0].read_all()[256:288]
    result = run_nsweep(
        sources, n_values=[3, 4], reduce_kwargs=dict(_DILUTED_REDUCE),
        oracle=lambda c: c == target, key_sizes=(32,), stride=8,
        escalate=True,
    )
    # Default floor found nothing at any checkpoint; escalation recovered it.
    assert result.first_hit_n is None
    assert result.escalation is not None
    assert result.escalation["verdict"] == "FLOOR_WAS_TOO_HIGH"
    assert result.escalation["hit_tier"] == "phi0"
    assert result.escalation["offset"] == 256
    assert result.to_dict()["escalation"]["hit_tier"] == "phi0"


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


class _SizeDivergentSource:
    """A source whose advertised ``.size`` exceeds its real ``read_all()`` length.

    Mirrors the reachable ``MslDumpSource`` edge case: ``.size`` (=
    ``size_for("vas")``) SUMS each captured run's *claimed* length
    (``iv.count * page_size``) without reading the payload, while
    ``read_all()`` materialises the *actual* captured bytes. For a truncated /
    short .msl container ``core.msl_helpers.get_region_page_data`` →
    ``MslReader.read_bytes`` clamps to the buffer end, so the real bytes are
    fewer than ``.size`` claims. ``_probe_min_size`` MUST fold on the real
    ``read_all()`` length, never on ``.size`` — otherwise the fold guard at
    ``nsweep._fold_until`` (``len(data) < welford.size``) would spuriously
    raise. This test locks that in so a ``len(src.read_all())`` → ``src.size``
    optimization cannot be introduced silently.
    """

    def __init__(self, data: bytes, claimed_size: int) -> None:
        self._data = data
        self.size = claimed_size

    def read_all(self) -> bytes:
        return self._data


def test_probe_min_size_uses_read_all_length_across_multiple_sources():
    sources = [
        _FakeSource(b"\x00" * 1024),
        _FakeSource(b"\x01" * 768),   # the true minimum
        _FakeSource(b"\x02" * 900),
    ]
    assert _probe_min_size(sources) == 768


def test_probe_min_size_ignores_inflated_size_attribute():
    # The short source advertises a LARGER .size than it can actually deliver
    # (truncated-MSL analogue). _probe_min_size must return the real read_all
    # length (400), NOT the inflated .size (2048).
    sources = [
        _SizeDivergentSource(b"\xaa" * 400, claimed_size=2048),
        _SizeDivergentSource(b"\xbb" * 1024, claimed_size=1024),
    ]
    assert _probe_min_size(sources) == 400

    # And the probed width must fold cleanly over every source — swapping in
    # the inflated .size (2048) would make _fold_until raise on the 400-byte
    # source (400 < 2048).
    size = _probe_min_size(sources)
    welford = WelfordVariance(size)
    welford.add_dump(sources[0].read_all()[:size])
    folded = _fold_until(welford, sources, 1, len(sources))
    assert folded == len(sources)
