"""Streaming slab variance (core/slab_variance.py) is bit-identical to the
historical in-RAM ``compute_variance`` path, bounded in memory, and guarded."""

from __future__ import annotations

import os
import tracemalloc
from pathlib import Path

import numpy as np
import pytest

from memdiver.algorithms.unknown_key.differential import DifferentialAlgorithm
from memdiver.core.dump_source import MslDumpSource, RawDumpSource
from memdiver.core.memory_budget import MIB
from memdiver.core.service_errors import CapabilityError
from memdiver.core.slab_variance import (
    allocate_variance_output,
    as_slab_reader,
    plan_slab_variance,
    plan_slabs,
    sliceable_flat_size,
    stream_variance,
)
from memdiver.core.variance import (
    ByteClass,
    classify_variance,
    compute_variance,
    count_classifications,
)
from memdiver.engine.consensus import ConsensusVector
from memdiver.engine.consensus_service import build_consensus
from memdiver.msl.enums import Protection, RegionType
from memdiver.msl.region_select import RegionCategory as C
from memdiver.msl.region_select import RegionSelection
from memdiver.msl.writer import MslWriter

SMALL_CHUNK = 4096
PAGE = 4096
R, W = int(Protection.READ), int(Protection.WRITE)
HEAP_RW = RegionSelection(frozenset({C.HEAP}), writable_only=True)


def _bits_equal(a: np.ndarray, b: np.ndarray) -> bool:
    return (a.dtype == b.dtype and a.shape == b.shape
            and np.array_equal(np.asarray(a).view(np.uint32),
                               np.asarray(b).view(np.uint32)))


def _random_buffers(n: int, size: int, seed: int) -> list:
    rng = np.random.default_rng(seed)
    base = rng.integers(0, 256, size, dtype=np.uint8)
    bufs = []
    for _ in range(n):
        buf = base.copy()
        # Mixed bands: invariant, low-variance, and fully random positions.
        buf[size // 3: size // 2] += rng.integers(0, 4, size // 2 - size // 3, dtype=np.uint8)
        buf[size // 2:] = rng.integers(0, 256, size - size // 2, dtype=np.uint8)
        bufs.append(buf.tobytes() + rng.integers(0, 256, n, dtype=np.uint8).tobytes())
    return bufs


def _write_files(tmp_path: Path, bufs: list) -> list:
    paths = []
    for i, buf in enumerate(bufs):
        p = tmp_path / f"d{i}.dump"
        p.write_bytes(buf)
        paths.append(p)
    return paths


def _old_variance(bufs: list) -> np.ndarray:
    min_size = min(len(b) for b in bufs)
    return compute_variance([b[:min_size] for b in bufs], min_size)


# ---------------------------------------------------------------------------
# Bit-identity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [2, 3, 8, 9])
@pytest.mark.parametrize("size", [1, 2, 4097, 3 * SMALL_CHUNK + 1, 5 * SMALL_CHUNK + 3, 70_001])
def test_buffers_bit_identical_with_tiny_chunks(n, size):
    bufs = _random_buffers(n, size, seed=n * 1000 + size)
    expected = _old_variance(bufs)
    got, ref = stream_variance(bufs, len(expected), chunk_positions=SMALL_CHUNK)
    assert _bits_equal(got, expected)
    assert ref == bufs[0][:len(expected)]


@pytest.mark.parametrize("n", [2, 3, 8, 9])
def test_raw_files_and_sources_bit_identical(tmp_path, n):
    bufs = _random_buffers(n, 11 * SMALL_CHUNK + 5, seed=n)
    paths = _write_files(tmp_path, bufs)
    expected = _old_variance(bufs)
    size = len(expected)
    from_paths, ref_p = stream_variance(paths, size, chunk_positions=SMALL_CHUNK)
    sources = [RawDumpSource(p) for p in paths]
    try:
        from_sources, ref_s = stream_variance(sources, size, chunk_positions=SMALL_CHUNK)
    finally:
        for s in sources:
            s.close()
    assert _bits_equal(from_paths, expected)
    assert _bits_equal(from_sources, expected)
    assert ref_p == ref_s == bufs[0][:size]


def test_width_one_tail_is_merged_unless_legacy_grid_had_one():
    assert plan_slabs(3 * SMALL_CHUNK + 1, SMALL_CHUNK)[-1] == (2 * SMALL_CHUNK, 3 * SMALL_CHUNK + 1)
    legacy = 4 * SMALL_CHUNK
    slabs = plan_slabs(legacy + 1, SMALL_CHUNK, legacy_chunk=legacy)
    assert slabs[-1] == (legacy, legacy + 1)
    assert all(e - s >= 2 for s, e in slabs[:-1])
    # Contiguous cover of [0, size).
    assert slabs[0][0] == 0 and all(a[1] == b[0] for a, b in zip(slabs, slabs[1:]))


def test_legacy_single_position_tail_reproduced():
    """Where compute_variance's own grid ended in a width-1 slab (reduced
    pairwise by numpy), the plan reproduces it bit for bit."""
    legacy = 4 * SMALL_CHUNK
    bufs = _random_buffers(9, legacy + 1, seed=5)
    size = legacy + 1
    expected = compute_variance([b[:size] for b in bufs], size, chunk_bytes=legacy)
    mat = np.stack([np.frombuffer(b, np.uint8, count=size) for b in bufs])
    got = np.empty(size, np.float32)
    for s, e in plan_slabs(size, SMALL_CHUNK, legacy_chunk=legacy):
        got[s:e] = np.var(mat[:, s:e].astype(np.float32), axis=0)
    assert _bits_equal(got, expected)


def test_consensus_build_paths_identical_to_old_and_counts(tmp_path):
    bufs = _random_buffers(3, 50_000, seed=11)
    bufs[1] = bufs[1][:-7]  # unequal sizes -> truncation to min_size
    paths = _write_files(tmp_path, bufs)
    cm = ConsensusVector()
    cm.build(paths)
    expected = _old_variance(bufs)
    assert _bits_equal(np.asarray(cm.variance), expected)
    assert cm.reference_bytes == bufs[0][:len(expected)]
    old_classes = classify_variance(expected)
    assert np.array_equal(np.asarray(cm.classifications), old_classes)
    codes, cnts = np.unique(old_classes, return_counts=True)
    assert count_classifications(np.asarray(cm.classifications)) == {
        ByteClass(int(c)).name.lower(): int(k) for c, k in zip(codes, cnts)}

    flat = build_consensus([str(p) for p in paths])
    assert _bits_equal(np.asarray(flat.variance), expected)
    assert flat.reference_bytes == cm.reference_bytes
    assert flat.classification_counts() == cm.classification_counts()


def test_differential_files_identical_to_buffers(tmp_path):
    bufs = _random_buffers(4, 30_001, seed=3)
    paths = _write_files(tmp_path, bufs)
    from_files = DifferentialAlgorithm._compute_variance(paths)
    from_buffers = DifferentialAlgorithm._variance_from_buffers(bufs)
    assert _bits_equal(np.asarray(from_files), np.asarray(from_buffers))


def test_classify_and_count_unchanged_across_slabs(monkeypatch):
    import memdiver.core.variance as variance_mod
    rng = np.random.default_rng(0)
    var = (rng.random(100_003) * 6000).astype(np.float32)
    var[::7] = 0.0
    whole = classify_variance(var)
    codes, cnts = np.unique(whole, return_counts=True)
    unique_counts = {variance_mod.ByteClass(int(c)).name.lower(): int(n)
                     for c, n in zip(codes, cnts)}
    monkeypatch.setattr(variance_mod, "CHUNK_BYTES", 1000)
    assert np.array_equal(classify_variance(var), whole)
    assert count_classifications(whole) == unique_counts
    assert list(count_classifications(whole)) == list(unique_counts)


# ---------------------------------------------------------------------------
# MSL sources (incl. region view filter)
# ---------------------------------------------------------------------------


def _write_msl(path: Path, seed: int, imported: bool) -> Path:
    rng = np.random.default_rng(seed)
    writer = MslWriter(str(path), pid=7, imported=imported)
    writer.add_memory_region(0x20000000, rng.integers(0, 256, PAGE, dtype=np.uint8).tobytes(),
                             protection=R | W, region_type=int(RegionType.ANONYMOUS))
    writer.add_memory_region(0x30000000, rng.integers(0, 256, 3 * PAGE, dtype=np.uint8).tobytes(),
                             protection=R | W, region_type=int(RegionType.HEAP))
    writer.add_memory_region(0x7FFF0000, rng.integers(0, 256, PAGE, dtype=np.uint8).tobytes(),
                             protection=R | W, region_type=int(RegionType.STACK))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.mark.parametrize("region_filter", [None, HEAP_RW])
def test_msl_sources_bit_identical_and_filter_honoured(tmp_path, region_filter):
    paths = [_write_msl(tmp_path / f"m{i}.msl", i, imported=True) for i in range(3)]
    sources = [MslDumpSource(p, region_filter=region_filter) for p in paths]
    for s in sources:
        s.open()
    try:
        bufs = [s.read_all() for s in sources]
        expected = _old_variance(bufs)
        assert [sliceable_flat_size(s) for s in sources] == [len(b) for b in bufs]
        assert all(type(as_slab_reader(s)).__name__ == "SourceSlabReader" for s in sources)
        got, ref = stream_variance(sources, len(expected), chunk_positions=SMALL_CHUNK)
        assert _bits_equal(got, expected)
        assert ref == bufs[0][:len(expected)]
        cm = ConsensusVector()
        cm.build_from_sources(sources)  # imported .msl -> flat fallback
    finally:
        for s in sources:
            s.close()
    # heap category = HEAP + rw ANONYMOUS regions; the STACK page is dropped.
    expected_len = 4 * PAGE if region_filter is not None else 5 * PAGE
    assert len(expected) == expected_len
    assert _bits_equal(np.asarray(cm.variance), expected)
    assert cm.reference_bytes == bufs[0][:len(expected)]


# ---------------------------------------------------------------------------
# Memory: memmap output, tracemalloc peak, guard
# ---------------------------------------------------------------------------


def test_memmap_output_identical(tmp_path):
    bufs = _random_buffers(3, 40_000, seed=9)
    expected = _old_variance(bufs)
    out = allocate_variance_output(len(expected), in_ram=False, directory=tmp_path)
    assert isinstance(out, np.memmap)
    got, _ = stream_variance(bufs, len(expected), out=out, chunk_positions=SMALL_CHUNK,
                             with_reference=False)
    assert got is out
    assert _bits_equal(np.asarray(got), expected)
    if os.name == "posix":
        assert not list(tmp_path.iterdir())  # unlinked right away


def test_build_places_variance_in_memmap_when_ram_estimate_exceeds_budget(tmp_path):
    size, budget = 2 * MIB, 20 * MIB
    plan = plan_slab_variance(2, size, budget=budget)
    assert not plan.variance_in_ram and plan.estimate.peak_bytes <= budget
    rng = np.random.default_rng(1)
    bufs = [rng.integers(0, 256, size, dtype=np.uint8).tobytes() for _ in range(2)]
    paths = _write_files(tmp_path, bufs)
    cm = ConsensusVector()
    cm.build(paths, budget=budget)
    assert isinstance(cm.variance, np.memmap)
    assert _bits_equal(np.asarray(cm.variance), _old_variance(bufs))


def test_guard_raises_on_tiny_budget_and_force_overrides(tmp_path):
    bufs = _random_buffers(3, 100_000, seed=2)
    paths = _write_files(tmp_path, bufs)
    with pytest.raises(CapabilityError) as info:
        ConsensusVector().build(paths, budget=1024)
    assert info.value.code == "memory_budget_exceeded"
    assert info.value.details["estimate_bytes"] > 1024
    with pytest.raises(CapabilityError):
        build_consensus([str(p) for p in paths], budget=1024)
    with pytest.raises(CapabilityError):
        DifferentialAlgorithm._compute_variance(paths, budget=1024)
    cm = ConsensusVector()
    cm.build(paths, budget=1024, force=True)
    assert _bits_equal(np.asarray(cm.variance), _old_variance(bufs))
    forced = build_consensus([str(p) for p in paths], budget=1024, force=True)
    assert _bits_equal(np.asarray(forced.variance), _old_variance(bufs))


def test_tracemalloc_peak_well_below_input(tmp_path):
    """4 x 32 MiB raw files: the streamed estimator never holds the dumps."""
    n, size = 4, 32 * MIB
    rng = np.random.default_rng(4)
    paths = []
    for i in range(n):
        p = tmp_path / f"big{i}.dump"
        p.write_bytes(rng.integers(0, 256, size, dtype=np.uint8).tobytes())
        paths.append(p)
    out = allocate_variance_output(size, in_ram=False, directory=tmp_path)
    tracemalloc.start()
    try:
        stream_variance(paths, size, out=out, chunk_positions=256 * 1024,
                        with_reference=False)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < (n * size) // 4, f"peak {peak / MIB:.1f} MiB"
    # Spot-check correctness on a window against the in-RAM estimator.
    window = [p.read_bytes()[1000:1000 + 65536] for p in paths]
    assert _bits_equal(np.asarray(out[1000:1000 + 65536]),
                       compute_variance(window, 65536))


# ---------------------------------------------------------------------------
# Incremental path + n-sweep probe
# ---------------------------------------------------------------------------


def test_welford_variance_out_matches_legacy_expression():
    from memdiver.core.variance import WelfordVariance
    bufs = _random_buffers(5, 10_000, seed=21)
    w = WelfordVariance(10_000)
    for b in bufs:
        w.add_dump(b[:10_000])
    mean, m2, n = w.state_arrays()
    legacy = (m2 / n).astype(np.float32)
    assert _bits_equal(w.variance(), legacy)
    out = np.empty(10_000, np.float32)
    assert w.variance(out=out) is out and _bits_equal(out, legacy)
    mean_v, max_v = w.variance_summary()
    assert max_v == float(legacy.max())
    assert mean_v == pytest.approx(float(legacy.mean()), rel=1e-5)
    with pytest.raises(ValueError):
        w.variance(out=np.empty(3, np.float32))


def test_incremental_consensus_unchanged_and_lazy():
    bufs = [b[:4000] for b in _random_buffers(3, 4000, seed=8)]
    cm = ConsensusVector()
    cm.build_incremental(4000)
    assert len(cm.variance) == 0  # no size-wide placeholder any more
    stats = [cm.add_source(b) for b in bufs]
    live = cm.get_live_variance()
    cm.finalize()
    assert [s[0] for s in stats] == [1, 2, 3]
    assert stats[-1][2] == float(live.max())
    assert _bits_equal(np.asarray(cm.variance), live)
    assert cm.reference_bytes == bufs[0]


def test_nsweep_probe_uses_size_not_read_all(tmp_path, monkeypatch):
    from memdiver.engine.nsweep import _probe_min_size
    bufs = _random_buffers(2, 9000, seed=1)
    bufs[1] = bufs[1][:8000]
    sources = [RawDumpSource(p) for p in _write_files(tmp_path, bufs)]

    def _boom(*_a, **_k):
        raise AssertionError("read_all called")

    for s in sources:
        monkeypatch.setattr(s, "read_all", _boom)
    try:
        assert _probe_min_size(sources) == 8000
    finally:
        for s in sources:
            s.close()

    class _Opaque:
        def read_all(self):
            return b"x" * 123

    assert _probe_min_size([_Opaque()]) == 123
