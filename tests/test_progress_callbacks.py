"""Tests that engine long-running functions emit progress and respect cancel.

Covers B1 of the Phase 25 web-UI integration plan: reduce_search_space,
brute_force_with_oracle, run_nsweep, and emit_plugin_for_hit all accept an
optional ``progress_callback`` kwarg (default ``noop_progress``) and the
brute-force / n-sweep loops accept an optional ``cancel_event`` that
interrupts execution within a bounded number of candidates.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import numpy as np
import pytest

from engine.brute_force import brute_force_with_oracle
from engine.candidate_pipeline import reduce_search_space
from engine.nsweep import run_nsweep
from engine.progress import (
    Cancelled,
    CancelEvent,
    ProgressEvent,
    check_cancel,
    noop_progress,
    safe_emit,
)
from engine.vol3_emit import emit_plugin_for_hit


class _Collector:
    """Accumulates ProgressEvents for assertion."""

    def __init__(self) -> None:
        self.events: List[ProgressEvent] = []

    def __call__(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def stages(self) -> List[str]:
        return [e.stage for e in self.events]


# --------------------------------------------------------------------------
# ProgressEvent / CancelEvent primitives
# --------------------------------------------------------------------------


def test_noop_progress_drops_events():
    # Must not raise, must return None.
    assert noop_progress(ProgressEvent(stage="x")) is None


def test_safe_emit_swallows_callback_errors():
    def boom(_: ProgressEvent) -> None:
        raise RuntimeError("kaboom")

    # Must not propagate even though the callback raises.
    safe_emit(boom, ProgressEvent(stage="x"))


def test_safe_emit_passes_none_callback():
    safe_emit(None, ProgressEvent(stage="x"))


def test_cancel_event_flow():
    ev = CancelEvent()
    assert not ev.is_set()
    check_cancel(ev)  # does not raise
    ev.set()
    assert ev.is_set()
    with pytest.raises(Cancelled):
        check_cancel(ev)
    ev.clear()
    assert not ev.is_set()


def test_check_cancel_accepts_none():
    check_cancel(None)  # no-op


# --------------------------------------------------------------------------
# reduce_search_space
# --------------------------------------------------------------------------


def _make_reduction_inputs(total: int = 1024, hot_offset: int = 256,
                           hot_size: int = 32):
    """A synthetic (variance, reference) pair with one obvious hot region."""
    rng = np.random.default_rng(7)
    variance = np.full(total, 100.0, dtype=np.float64)
    variance[hot_offset:hot_offset + hot_size] = 20000.0
    reference = bytearray(rng.integers(0, 256, total, dtype=np.uint8).tobytes())
    # Pack the hot window with a permutation so entropy easily exceeds 4.5.
    reference[hot_offset:hot_offset + hot_size] = bytes(range(hot_size))
    return variance, bytes(reference)


def test_reduce_search_space_emits_four_stages():
    variance, reference = _make_reduction_inputs()
    collector = _Collector()
    reduce_search_space(
        variance, reference, num_dumps=5,
        progress_callback=collector,
    )
    stages = collector.stages()
    assert "search_reduce:start" in stages
    assert "search_reduce:variance" in stages
    assert "search_reduce:aligned" in stages
    assert "search_reduce:entropy" in stages
    assert "search_reduce:regions" in stages
    # pct values are monotonic non-decreasing.
    pcts = [e.pct for e in collector.events]
    assert pcts == sorted(pcts)
    assert pcts[0] == 0.0
    assert pcts[-1] == 1.0


def test_reduce_search_space_default_noop_unchanged():
    variance, reference = _make_reduction_inputs()
    # Must work without passing progress_callback.
    result = reduce_search_space(variance, reference, num_dumps=5)
    assert result.stages.total_bytes == len(variance)


# --------------------------------------------------------------------------
# brute_force_with_oracle
# --------------------------------------------------------------------------


def _make_brute_force_inputs(num_regions: int = 1, region_size: int = 64,
                             target_offset: int = 0):
    """Returns (reference, regions, target_bytes)."""
    total = max(1024, num_regions * 128 + 64)
    ref = bytearray(np.random.RandomState(3).bytes(total))
    target = bytes(range(32))
    ref[target_offset:target_offset + 32] = target
    regions = [
        {"offset": i * 128, "length": region_size, "mean_variance": 20000.0,
         "mean_entropy": 4.8}
        for i in range(num_regions)
    ]
    return bytes(ref), regions, target


def test_brute_force_emits_progress_and_hit():
    reference, regions, target = _make_brute_force_inputs(num_regions=2)

    def oracle(candidate: bytes) -> bool:
        return candidate == target

    collector = _Collector()
    result = brute_force_with_oracle(
        regions, reference, oracle,
        progress_callback=collector,
    )
    assert result.verified_count == 1
    stages = collector.stages()
    assert "brute_force:start" in stages
    assert "brute_force:hit" in stages
    # Extra payload on hit event carries the offset.
    hit_evs = [e for e in collector.events if e.stage == "brute_force:hit"]
    assert hit_evs[0].extra["offset"] == 0


def test_brute_force_cancel_event_interrupts():
    # Build a 2000-candidate region so we have enough work to interleave a cancel.
    reference = bytes(4096)
    regions = [{"offset": 0, "length": 4096, "mean_variance": 20000.0,
                "mean_entropy": 4.8}]

    cancel = CancelEvent()
    call_count = {"n": 0}

    def oracle(candidate: bytes) -> bool:
        call_count["n"] += 1
        if call_count["n"] == 50:
            cancel.set()
        return False

    with pytest.raises(Cancelled):
        brute_force_with_oracle(
            regions, reference, oracle,
            progress_callback=noop_progress,
            cancel_event=cancel,
        )
    # The cancel must kick in well before the full 500+ candidate set.
    assert call_count["n"] < 512


# --------------------------------------------------------------------------
# run_nsweep
# --------------------------------------------------------------------------


class _MemSource:
    """A DumpSource-compatible in-memory source for run_nsweep."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read_all(self) -> bytes:
        return self._data


def _make_nsweep_sources(n: int = 3, total: int = 1024, target_offset: int = 256):
    rng = np.random.default_rng(11)
    target = bytes(range(32))
    sources = []
    for i in range(n):
        buf = bytearray(rng.integers(0, 256, total, dtype=np.uint8).tobytes())
        buf[target_offset:target_offset + 32] = target
        # Introduce variance everywhere else so the welford matrix has signal.
        for j in range(0, total, 37):
            if not (target_offset <= j < target_offset + 32):
                buf[j] = (buf[j] + i * 17) % 256
        sources.append(_MemSource(bytes(buf)))
    return sources, target


def test_run_nsweep_emits_point_events():
    sources, target = _make_nsweep_sources(n=4)

    def oracle(candidate: bytes) -> bool:
        return candidate == target

    collector = _Collector()
    result = run_nsweep(
        sources,
        n_values=[3, 4],
        reduce_kwargs={"min_variance": 100.0, "entropy_threshold": 3.5,
                       "entropy_window": 16, "min_region": 8},
        oracle=oracle,
        progress_callback=collector,
    )
    stages = collector.stages()
    assert "nsweep:start" in stages
    assert "nsweep:n_start" in stages
    assert stages.count("nsweep:point") == 2


def test_run_nsweep_cancel_event_interrupts():
    sources, target = _make_nsweep_sources(n=4)
    cancel = CancelEvent()

    def oracle(candidate: bytes) -> bool:
        return False

    call_count = {"n": 0}

    def progress(event: ProgressEvent) -> None:
        call_count["n"] += 1
        if event.stage == "nsweep:n_start":
            cancel.set()

    with pytest.raises(Cancelled):
        run_nsweep(
            sources,
            n_values=[3, 4],
            reduce_kwargs={"min_variance": 100.0, "entropy_threshold": 3.5,
                           "entropy_window": 16, "min_region": 8},
            oracle=oracle,
            progress_callback=progress,
            cancel_event=cancel,
        )


# --------------------------------------------------------------------------
# emit_plugin_for_hit
# --------------------------------------------------------------------------


def test_emit_plugin_for_hit_emits_three_stages(tmp_path: Path):
    # Build a neighborhood where most bytes have LOW variance (static) and
    # a 32-byte key region has HIGH variance (wildcarded).
    reference = bytearray(b"A" * 256)
    reference[100:132] = bytes(range(32))
    variance = [0.0] * 160
    for i in range(32):
        variance[64 + i] = 10000.0  # key bytes highly variable
    hit = {
        "offset": 100,
        "length": 32,
        "neighborhood_start": 36,
        "neighborhood_variance": variance,
        "region_index": 0,
    }
    collector = _Collector()
    output = tmp_path / "plugin.py"
    emit_plugin_for_hit(
        hit,
        bytes(reference),
        name="test_plugin",
        output_path=output,
        progress_callback=collector,
    )
    stages = collector.stages()
    assert stages == ["emit_plugin:load", "emit_plugin:render", "emit_plugin:write"]
    assert output.is_file()
    assert "test_plugin" in output.read_text()
