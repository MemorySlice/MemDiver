"""Per-algorithm working-set estimates and their use by ``run_file``.

Covers:
* ``BaseAlgorithm.estimate_working_set`` (default 0) and the size-proportional
  implementations (entropy_scan, change_point, structure_scan, pattern_match,
  differential) -- estimates checked against tracemalloc peaks with generous
  bounds (never far below the measurement, at most a few times above it);
* ``read_estimate_sample`` and the analysis-buffer gate (dump copy + largest
  working set, read_all only while both fit);
* ``run_file`` refusing when an algorithm's working set exceeds a tiny budget
  (naming it), passing with ``force_memory``, identical results otherwise.
"""

from __future__ import annotations

import json
import mmap
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.registry import get_registry
from memdiver.algorithms.working_set import (
    conservative_fraction,
    conservative_region_density,
    entropy_profile_bytes,
    entropy_scan_bytes,
    positions,
    region_sample_pieces,
)
from memdiver.app.pipeline.analysis_buffer import (
    STRATEGY_BYTES,
    STRATEGY_MMAP,
    analysis_estimate,
    open_analysis_buffer,
    plan_analysis_buffer,
    read_estimate_sample,
)
from memdiver.app.pipeline.analysis_task_runner import run_file
from memdiver.core.dump_source import open_dump
from memdiver.core.service_errors import CapabilityError

MIB = 1024 * 1024
REGISTRY = get_registry()


@dataclass
class _FakeCtx:
    task_id: str = "test-working-set"
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return False


def _context(**extra: Any) -> AnalysisContext:
    return AnalysisContext(library="x", protocol_version="unknown",
                           phase="file", extra=extra)


def _content(size: int, kind: str, seed: int = 0) -> bytes:
    rng = np.random.default_rng(seed)
    if kind == "random":
        return rng.integers(0, 256, size, dtype=np.uint8).tobytes()
    if kind == "striped":  # 32 random + 32 zero bytes: one region per 64 B
        buf = rng.integers(0, 256, size, dtype=np.uint8).reshape(-1, 64)
        buf[:, 32:] = 0
        return buf.tobytes()
    buf = np.zeros(size, dtype=np.uint8)
    if kind == "mixed":  # 10% of 4 KiB blocks random
        blocks = size // 4096
        for i in rng.choice(blocks, max(blocks // 10, 1), replace=False):
            buf[i * 4096:(i + 1) * 4096] = rng.integers(0, 256, 4096, dtype=np.uint8)
    return buf.tobytes()


def _write(tmp_path: Path, size: int, kind: str) -> Path:
    path = tmp_path / f"{kind}_{size}.dump"
    path.write_bytes(_content(size, kind))
    return path


def _measure(name: str, path: Path, context: AnalysisContext) -> int:
    with open(path, "rb") as fh:
        mapping = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    algorithm = REGISTRY.get(name)
    tracemalloc.start()
    try:
        result = algorithm.run(mapping, context)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        del result
        mapping.close()
    return peak


def _estimate(name: str, path: Path, context: AnalysisContext) -> int:
    with open_dump(path) as source:
        sample = read_estimate_sample(source)
        size = int(source.size)
    return REGISTRY.get(name).estimate_working_set(size, context, sample)


# ---------------------------------------------------------------------------
# hook defaults and formulas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["exact_match", "user_regex",
                                  "constraint_validator", "differential"])
def test_non_proportional_algorithms_estimate_zero(name):
    assert REGISTRY.get(name).estimate_working_set(1 << 30, _context()) == 0


def test_every_algorithm_accepts_size_only_call():
    for algorithm in REGISTRY.list_all():
        assert algorithm.estimate_working_set(4 * MIB) >= 0


def test_differential_estimate_uses_slab_plan(tmp_path):
    paths = [tmp_path / f"d{i}.dump" for i in range(3)]
    for p in paths:
        p.write_bytes(b"\x00" * (256 * 1024))
    est = REGISTRY.get("differential").estimate_working_set(
        256 * 1024, _context(dump_paths=paths))
    assert est > 0


def test_positions_and_profile_formula():
    assert positions(31, 32, 16) == 0
    assert positions(32, 32, 16) == 1
    assert positions(64 * MIB, 32, 16) == (64 * MIB - 32) // 16 + 1
    assert entropy_profile_bytes(10, 32, 16) == 0
    # 16 B/position dominates for large inputs.
    big = entropy_profile_bytes(1 << 30, 32, 16)
    assert 16 * positions(1 << 30, 32, 16) < big < 17 * positions(1 << 30, 32, 16)


def test_structure_scan_estimate_is_size_independent():
    """One view at a time: 1 GiB costs (almost) what 64 MiB does, and far less
    than the former whole-dump step-16 profile (16 B per 16 bytes)."""
    scan = REGISTRY.get("structure_scan")
    small = scan.estimate_working_set(64 * MIB)
    large = scan.estimate_working_set(1024 * MIB)
    assert large == small  # matches capped, regions per view
    assert large < entropy_profile_bytes(1024 * MIB, 32, 16) / 8
    zeros = [bytes(64 * 1024)] * 4
    assert scan.estimate_working_set(1024 * MIB, _context(), zeros) < large / 2


def test_change_point_respects_step_parameter():
    cp = REGISTRY.get("change_point")
    assert cp.estimate_working_set(64 * MIB, _context(step=1)) > \
        cp.estimate_working_set(64 * MIB, _context(step=16))


def test_entropy_scan_without_sample_is_worst_case():
    scan = REGISTRY.get("entropy_scan")
    zeros = [bytes(64 * 1024)] * 4
    worst = scan.estimate_working_set(64 * MIB, _context())
    sampled = scan.estimate_working_set(64 * MIB, _context(), zeros)
    assert worst > 10 * sampled
    assert conservative_fraction(None) == 1.0


def test_entropy_scan_random_estimate_is_slab_bound():
    """Random bytes merge into ONE region: no per-window term any more."""
    scan = REGISTRY.get("entropy_scan")
    sample = [_content(64 * 1024, "random", seed) for seed in range(32)]
    estimate = scan.estimate_working_set(64 * MIB, _context(), sample)
    assert estimate < 100 * MIB
    assert estimate < scan.estimate_working_set(64 * MIB, _context()) / 10


def test_entropy_scan_estimate_grows_with_region_density():
    sparse = entropy_scan_bytes(64 * MIB, [32, 48], 1, region_density=0.0)
    dense = entropy_scan_bytes(64 * MIB, [32, 48], 1, region_density=1 / 64)
    densest = entropy_scan_bytes(64 * MIB, [32, 48], 1)
    assert sparse < dense < densest
    assert conservative_region_density(None, 32) == 1 / 32
    assert conservative_region_density(1.0, 32) == 1 / 32  # capped
    assert conservative_region_density(0.0, 32) > 0  # absolute margin


def test_entropy_scan_non_unit_step_keeps_candidate_estimate():
    scan = REGISTRY.get("entropy_scan")
    zeros = [bytes(64 * 1024)] * 4
    worst = scan.estimate_working_set(4 * MIB, _context(step=2))
    sampled = scan.estimate_working_set(4 * MIB, _context(step=2), zeros)
    assert worst > 10 * sampled
    assert worst == entropy_scan_bytes(4 * MIB, [32, 48], 2)


def test_region_sample_pieces_spread_over_sample():
    assert region_sample_pieces(None, 32) is None
    assert region_sample_pieces([b""], 32) is None
    single = bytes(range(256)) * 4096  # 1 MiB, one block
    pieces = region_sample_pieces([single], 32, pieces=4, piece_bytes=1024)
    stride = (len(single) - 1024) // 3
    assert pieces == [single[i * stride:i * stride + 1024] for i in range(4)]
    many = [bytes([i]) * 4096 for i in range(64)]
    pieces = region_sample_pieces(many, 32, pieces=32, piece_bytes=1024)
    assert pieces == [block[:1024] for block in many[:32]]
    assert region_sample_pieces([b"x" * 10], 512) == [b"x" * 10]


def test_pattern_match_estimate_is_largest_pattern_scan():
    pm = REGISTRY.get("pattern_match")
    scan = REGISTRY.get("entropy_scan")
    size = 16 * MIB
    applicable = pm._filter_patterns(_context())
    expected = max((scan.estimate_working_set(size, pm._entropy_context(_context(), p))
                    for p in applicable), default=0)
    assert pm.estimate_working_set(size, _context()) == expected
    assert pm.estimate_working_set(size) > 0  # no context: all loaded patterns


# ---------------------------------------------------------------------------
# estimates vs tracemalloc (generous bounds, small sizes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,kind,size", [
    ("change_point", "zeros", 1 * MIB),
    ("change_point", "mixed", 4 * MIB),
    # structure_scan streams one bounded overview view at a time (no longer a
    # whole-dump step-16 profile): the mixed case is sparse (zero blocks are
    # skipped), random/striped are the dense worst cases of scratch / regions.
    ("structure_scan", "mixed", 4 * MIB),
    ("structure_scan", "random", 2 * MIB),
    ("structure_scan", "striped", 1 * MIB),
    ("entropy_scan", "zeros", 1 * MIB),
    ("entropy_scan", "mixed", 2 * MIB),
    ("entropy_scan", "random", MIB // 2),
    ("entropy_scan", "random", 2 * MIB),
    ("entropy_scan", "striped", 1 * MIB),
])
def test_estimate_bounds_measured_peak(tmp_path, name, kind, size):
    path = _write(tmp_path, size, kind)
    context = _context()
    measured = _measure(name, path, context)
    estimate = _estimate(name, path, context)
    assert estimate >= 0.9 * measured, (name, kind, estimate, measured)
    assert estimate <= 4 * measured + 8 * MIB, (name, kind, estimate, measured)


# ---------------------------------------------------------------------------
# sample + gate
# ---------------------------------------------------------------------------


def test_read_estimate_sample_small_and_large(tmp_path):
    small = _write(tmp_path, 100 * 1024, "mixed")
    with open_dump(small) as source:
        assert read_estimate_sample(source) == [source.read_all()]
    large = _write(tmp_path, 8 * MIB, "mixed")
    with open_dump(large) as source:
        blocks = read_estimate_sample(source, blocks=4, block_bytes=1024)
        data = source.read_all()
    stride = (8 * MIB - 1024) // 3
    assert blocks == [data[i * stride:i * stride + 1024] for i in range(4)]


def test_plan_prefers_mmap_when_algorithms_need_the_budget(tmp_path):
    path = _write(tmp_path, 64 * 1024, "zeros")
    with open_dump(path) as source:
        budget = 1 * MIB  # the 64 KiB copy fits, copy + 2 MiB does not
        assert plan_analysis_buffer(source, budget=budget).strategy == STRATEGY_BYTES
        plan = plan_analysis_buffer(source, budget=budget,
                                    working_sets={"a": 2 * MIB})
        assert plan.strategy == STRATEGY_MMAP
        est = analysis_estimate(plan, source.name, {"a": 2 * MIB, "b": MIB})
        assert est.peak_bytes == 2 * MIB  # max, not sum; mmap costs no heap
        assert est.breakdown["b"] == MIB


def test_gate_names_heaviest_algorithm(tmp_path):
    path = _write(tmp_path, 64 * 1024, "zeros")
    with open_dump(path) as source:
        with pytest.raises(CapabilityError) as info:
            with open_analysis_buffer(source, budget=MIB,
                                      working_sets={"small": 1, "big": 4 * MIB}):
                pass
        assert info.value.code == "memory_budget_exceeded"
        assert info.value.details["heaviest_algorithm"] == "big"
        assert "deselect" in info.value.message and "big" in info.value.message
        with open_analysis_buffer(source, budget=MIB, force=True,
                                  working_sets={"big": 4 * MIB}) as buf:
            assert buf[:] == source.read_all()


# ---------------------------------------------------------------------------
# run_file end to end
# ---------------------------------------------------------------------------


def _run(dump: Path, out: Path, **extra: Any) -> Dict[str, Any]:
    params = {"artifact_dir": str(out), "dump_path": str(dump), **extra}
    ret = run_file(params, _FakeCtx())
    return json.loads((out / ret["artifacts"][0]["relpath"]).read_text())


def test_run_file_refuses_heavy_algorithm_then_forced(tmp_path, monkeypatch):
    dump = _write(tmp_path, 256 * 1024, "mixed")
    algorithms = ["change_point", "user_regex", "entropy_scan"]
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "100000")
    baseline = _run(dump, tmp_path / "base", algorithms=algorithms)
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "1")  # 1 MiB
    with pytest.raises(CapabilityError) as info:
        _run(dump, tmp_path / "refused", algorithms=algorithms)
    details = info.value.details
    assert info.value.code == "memory_budget_exceeded"
    heaviest = details["heaviest_algorithm"]
    assert heaviest in ("change_point", "entropy_scan")
    assert details["algorithm_working_sets"][heaviest] == max(
        details["algorithm_working_sets"].values())
    assert details["algorithm_working_sets"]["user_regex"] == 0
    forced = _run(dump, tmp_path / "forced", algorithms=algorithms,
                  force_memory=True)
    assert forced == baseline


def test_run_file_zero_cost_algorithms_pass_tiny_budget(tmp_path, monkeypatch):
    dump = _write(tmp_path, 256 * 1024, "mixed")
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "100000")
    baseline = _run(dump, tmp_path / "base", algorithms=["user_regex"],
                    user_regex=r"\x00{4096}")
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "0.001")
    bounded = _run(dump, tmp_path / "bounded", algorithms=["user_regex"],
                   user_regex=r"\x00{4096}")
    assert bounded == baseline


def test_structure_scan_bytes_formula():
    from memdiver.algorithms.working_set import dense_block_fraction, structure_scan_bytes
    args = (32, MIB, 2 * MIB, 1 << 16, 4096)
    assert structure_scan_bytes(16, *args) == 0
    worst = structure_scan_bytes(64 * MIB, *args)
    sparse = structure_scan_bytes(64 * MIB, *args, region_density=0.0, dense_fraction=0.0)
    assert sparse < worst
    assert structure_scan_bytes(1024 * MIB, *args) == worst  # one view at a time
    assert dense_block_fraction(None) is None
    assert dense_block_fraction([bytes(2048), b"\x01" + bytes(1023)]) == 1 / 3
