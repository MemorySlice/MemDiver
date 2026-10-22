"""Bit-identity harness for the fast entropy profile / streaming Entropy tab.

``_frozen_*`` below are verbatim copies of ``core/entropy.py`` as it stood
before the sorted-run profile, the pair histogram and the streaming endpoint
(the 256-bin ``bincount`` + gather + pairwise ``sum`` profile and the
whole-buffer ``bincount`` Shannon entropy). Every new path must reproduce
them BIT FOR BIT (compared as ``uint64`` views, not with a tolerance), and
so must every consumer that thresholds or aggregates the values.
"""
import math
import sys
import tracemalloc
from pathlib import Path

import numpy as np
import pytest
from numpy.lib.stride_tricks import sliding_window_view

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.unknown_key import change_point as change_point_module
from memdiver.algorithms.unknown_key import structure_scan as structure_scan_module
from memdiver.app import tools_inspect
from memdiver.app.entropy_payload import profile_regions
from memdiver.app.session import ToolSession
from memdiver.core import entropy as entropy_module
from memdiver.core.entropy import (
    byte_histogram,
    compute_entropy_profile,
    entropy_from_byte_counts,
    find_high_entropy_regions,
    shannon_entropy,
    sorted_path_matches_numpy,
    stream_entropy_profile,
    window_entropies,
)
from memdiver.core.entropy_profile import EntropyProfile


# --- frozen pre-change implementation ------------------------------------

_FROZEN_CHUNK_POSITIONS = 1 << 13


def _frozen_shannon_entropy(data):
    length = len(data)
    if length == 0:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    nonzero = counts[counts > 0].astype(np.float64)
    probabilities = nonzero / length
    return float(-(probabilities * np.log2(probabilities)).sum())


def _frozen_compute_entropy_profile(data, window=32, step=1):
    data_len = len(data)
    if data_len < window:
        return EntropyProfile.empty()
    arr = np.frombuffer(data, dtype=np.uint8)
    offsets = np.arange(0, data_len - window + 1, step, dtype=np.int64)
    num_positions = offsets.shape[0]
    counts_range = np.arange(1, window + 1, dtype=np.float64)
    flut = np.zeros(window + 1, dtype=np.float64)
    flut[1:] = counts_range * np.log2(counts_range)
    windows = sliding_window_view(arr, window)
    log2_window = math.log2(window)
    entropies = np.empty(num_positions, dtype=np.float64)
    row_index = np.arange(_FROZEN_CHUNK_POSITIONS, dtype=np.int64)
    for start in range(0, num_positions, _FROZEN_CHUNK_POSITIONS):
        stop = min(start + _FROZEN_CHUNK_POSITIONS, num_positions)
        rows = windows[offsets[start:stop]]
        slab = stop - start
        composite = (row_index[:slab, None] * 256 + rows).ravel()
        counts = np.bincount(composite, minlength=slab * 256).reshape(slab, 256)
        entropy_sum = flut[counts].sum(axis=1)
        entropies[start:stop] = log2_window - entropy_sum / window
    return EntropyProfile(offsets, entropies)


# --- corpus -----------------------------------------------------------------

def _heap_like(size, seed):
    rng = np.random.default_rng(seed)
    out = np.zeros(size, dtype=np.uint8)
    for i in range(0, size, 512):
        kind = rng.integers(0, 6)
        block = slice(i, min(i + 512, size))
        n = block.stop - block.start
        if kind == 1:
            out[block] = rng.integers(32, 127, n, dtype=np.uint8)
        elif kind == 2:
            out[block] = rng.integers(0, 256, n, dtype=np.uint8)
        elif kind == 3:
            out[block] = rng.integers(0, 6, n, dtype=np.uint8)
        elif kind == 4:
            out[block] = (np.arange(n) * 8).astype(np.uint8)
    return out.tobytes()


def _threshold_crafted():
    """Windows whose entropy is exactly log2(k): 2^k distinct values, evenly."""
    rng = np.random.default_rng(3)
    parts = [np.tile(np.arange(1 << k, dtype=np.uint8), 2048 >> k) for k in range(6)]
    parts.append(rng.permutation(np.repeat(np.arange(256, dtype=np.uint8), 4)))
    parts.append(np.repeat(np.arange(0, 256, 8, dtype=np.uint8), 32))  # one slot only
    return np.concatenate(parts).tobytes()


_RNG = np.random.default_rng(11)
CORPUS = {
    "random": _RNG.integers(0, 256, 40_000, dtype=np.uint8).tobytes(),
    "zeros": bytes(9_000),
    "ascii": _RNG.integers(32, 127, 30_000, dtype=np.uint8).tobytes(),
    "low_alphabet": _RNG.integers(0, 4, 30_000, dtype=np.uint8).tobytes(),
    "high_half": _RNG.integers(128, 256, 20_000, dtype=np.uint8).tobytes(),
    "heap_like": _heap_like(60_000, 5),
    "threshold_crafted": _threshold_crafted(),
    "odd_tail": _RNG.integers(0, 256, 4097, dtype=np.uint8).tobytes(),
    "tiny": b"\x01\x02\x03",
    "empty": b"",
}

# (window, step): default/tab/change_point shapes, both sides of the
# sorted/histogram cutoff, step > window, step 1, degenerate windows.
SHAPES = [(32, 16), (32, 1), (32, 64), (33, 16), (16, 3), (48, 7), (64, 64), (7, 1), (1, 1),
          (2, 1), (256, 256), (300, 50), (512, 97), (513, 97), (1024, 1000)]


def _bits(values):
    return np.asarray(values, dtype=np.float64).view(np.uint64)


def _assert_profiles_identical(got, want):
    assert np.array_equal(got.offsets, want.offsets)
    assert np.array_equal(_bits(got.values), _bits(want.values))


# --- core primitives --------------------------------------------------------

def test_sorted_path_active_on_this_numpy():
    """The fast path mirrors numpy's pairwise layout; it must be enabled here."""
    assert sorted_path_matches_numpy() is True


@pytest.mark.parametrize("name", sorted(CORPUS))
@pytest.mark.parametrize("window,step", SHAPES)
def test_compute_entropy_profile_bit_identical(name, window, step):
    data = CORPUS[name]
    _assert_profiles_identical(compute_entropy_profile(data, window, step),
                               _frozen_compute_entropy_profile(data, window, step))


@pytest.mark.parametrize("window,step", [(32, 16), (16, 1), (300, 50)])
def test_histogram_fallback_bit_identical(monkeypatch, window, step):
    monkeypatch.setattr(entropy_module, "SORTED_PATH_MAX_WINDOW", 0)
    data = CORPUS["heap_like"]
    _assert_profiles_identical(compute_entropy_profile(data, window, step),
                               _frozen_compute_entropy_profile(data, window, step))


def test_window_entropies_arbitrary_offsets():
    data = CORPUS["heap_like"]
    arr = np.frombuffer(data, dtype=np.uint8)
    full = _frozen_compute_entropy_profile(data, 32, 1)
    picks = np.array([0, 5, 17, 4000, 30_001, len(data) - 32], dtype=np.int64)
    assert np.array_equal(_bits(window_entropies(arr, picks, 32)), _bits(full.values[picks]))
    assert window_entropies(arr, picks[:0], 32).shape == (0,)


def test_sorted_path_forced_for_large_windows(monkeypatch):
    """The sorted path is exact for any window, not only the default ones."""
    monkeypatch.setattr(entropy_module, "SORTED_PATH_MAX_WINDOW", 4096)
    data = CORPUS["heap_like"]
    for window, step in ((64, 64), (300, 50), (1024, 1000)):
        _assert_profiles_identical(compute_entropy_profile(data, window, step),
                                   _frozen_compute_entropy_profile(data, window, step))


def test_small_slabs_do_not_change_rows(monkeypatch):
    monkeypatch.setattr(entropy_module, "SORTED_SLAB_WINDOW_BYTES", 100)
    data = CORPUS["random"]
    _assert_profiles_identical(compute_entropy_profile(data, 32, 3),
                               _frozen_compute_entropy_profile(data, 32, 3))


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_byte_histogram_matches_bincount(name):
    data = CORPUS[name]
    expected = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    got = byte_histogram(data)
    assert got.dtype == np.int64 and got.shape == (256,)
    assert np.array_equal(got, expected)


@pytest.mark.parametrize("chunk,block", [(16, 8), (4096, 1024), (1 << 19, 1024), (24, 8)])
def test_byte_histogram_chunking_zero_blocks_and_strided_input(monkeypatch, chunk, block):
    monkeypatch.setattr(entropy_module, "HISTOGRAM_CHUNK_BYTES", chunk)
    monkeypatch.setattr(entropy_module, "ZERO_BLOCK_BYTES", block)
    arr = np.frombuffer(CORPUS["heap_like"] + bytes(5000) + b"\x07" + bytes(3), dtype=np.uint8)
    for view in (arr, arr[1:], arr[::3], arr[:block - 1], arr[-3 * block - 1:]):
        assert np.array_equal(byte_histogram(view), np.bincount(view, minlength=256))


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_shannon_entropy_bit_identical(name):
    data = CORPUS[name]
    want = _frozen_shannon_entropy(data)
    assert _bits(shannon_entropy(data)) == _bits(want)
    assert _bits(entropy_from_byte_counts(byte_histogram(data), len(data))) == _bits(want)


# --- streaming --------------------------------------------------------------

@pytest.mark.parametrize("name", ["random", "heap_like", "threshold_crafted", "odd_tail", "tiny", "zeros"])
@pytest.mark.parametrize("window,step", [(32, 16), (32, 1), (32, 1000), (300, 50), (5, 7)])
@pytest.mark.parametrize("slab", [1, 31, 4096, 1 << 20])
def test_stream_entropy_profile_bit_identical(name, window, step, slab):
    data = CORPUS[name]
    if slab < 31 and len(data) > 10_000:
        pytest.skip("one read per byte: covered on the small inputs")
    reads = []

    def read(offset, length):
        reads.append(length)
        return data[offset:offset + length]

    overall, profile = stream_entropy_profile(read, len(data), window, step, slab)
    assert _bits(overall) == _bits(_frozen_shannon_entropy(data))
    _assert_profiles_identical(profile, _frozen_compute_entropy_profile(data, window, step))
    assert max(reads, default=0) <= slab + window - 1


def test_stream_entropy_profile_empty_and_short_read():
    assert stream_entropy_profile(lambda o, n: b"", 0, 32, 1) == (0.0, EntropyProfile.empty())
    with pytest.raises(ValueError, match="short read"):
        stream_entropy_profile(lambda o, n: b"\x00" * (n - 1), 100, 32, 1, 64)


# --- consumers --------------------------------------------------------------

def _context():
    return AnalysisContext(library="test", protocol_version="13", phase="pre_abort")


@pytest.mark.parametrize("name", ["random", "heap_like", "threshold_crafted", "ascii"])
def test_change_point_and_structure_scan_outputs_identical(monkeypatch, name):
    """change_point under the fast vs the frozen profile; structure_scan no
    longer reads ``compute_entropy_profile`` (its regions come from the
    step-1 ``stream_entropy_overview``, checked against the frozen profile in
    ``test_entropy_overview``), so it is only required to be unaffected by the
    swap -- same output under both."""
    data = CORPUS[name] * 2
    results = {}
    for label, impl in (("new", compute_entropy_profile), ("frozen", _frozen_compute_entropy_profile)):
        monkeypatch.setattr(change_point_module, "compute_entropy_profile", impl)
        monkeypatch.setattr(entropy_module, "compute_entropy_profile", impl)
        cp = change_point_module.ChangePointAlgorithm().run(data, _context())
        ss = structure_scan_module.StructureScanAlgorithm().run(data, _context())
        results[label] = (repr(cp), repr(ss))
    assert results["new"] == results["frozen"]


@pytest.mark.parametrize("name", sorted(CORPUS))
@pytest.mark.parametrize("threshold", [1.0, 2.0, 4.0, 4.5, 5.0])
def test_high_entropy_regions_identical(name, threshold):
    data = CORPUS[name]
    new = find_high_entropy_regions(compute_entropy_profile(data, 32, 16), threshold, 32)
    old = find_high_entropy_regions(_frozen_compute_entropy_profile(data, 32, 16), threshold, 32)
    assert new == old


# --- the Entropy tab endpoint ----------------------------------------------

def _frozen_endpoint_payload(data, window, step, threshold, max_positions,
                             regions_of=None):
    """The pre-streaming ``entropy_result`` payload computed from *data*.

    *regions_of(profile, threshold, window, step)*: the region rule applied to
    the FROZEN profile. The endpoint now joins byte-overlapping runs and keeps
    regions covering >= 32 bytes (``entropy_payload.profile_regions``) instead
    of a fixed 32-start span; default: the historical rule.
    """
    effective = tools_inspect._bounded_entropy_step(len(data), window, step, max_positions)
    profile = _frozen_compute_entropy_profile(data, window, effective)
    if regions_of is None:
        regions = find_high_entropy_regions(profile, threshold=threshold)
    else:
        regions = regions_of(profile, threshold, window, effective)
    sample = profile
    cap = tools_inspect.MAX_ENTROPY_SAMPLES
    if len(profile) > cap:
        n = len(profile)
        sample = [profile[(i * (n - 1)) // (cap - 1)] for i in range(cap)]
    entropies = [e for _, e in profile] if profile else [0.0]
    return {
        "overall_entropy": round(_frozen_shannon_entropy(data), 4),
        "high_entropy_regions": [
            {"start": s, "end": e, "mean_entropy": round(m, 4)} for s, e, m in regions],
        "profile_sample": [{"offset": o, "entropy": round(e, 4)} for o, e in sample],
        "stats": {"min": round(min(entropies), 4), "max": round(max(entropies), 4),
                  "mean": round(sum(entropies) / len(entropies), 4)},
        "step": effective,
        "window": window,
    }


def _write_msl(path, data, region_bytes):
    sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
    import generate_msl_fixtures as g

    blob = bytearray(g._build_file_header(g._det_uuid(), 1_700_000_000_000_000_000))
    for i in range(0, len(data), region_bytes):
        chunk = data[i:i + region_bytes]
        block, _ = g._build_memory_region(
            base_addr=0x7F0000000000 + i * 2, num_pages=len(chunk) // 4096, page_data=chunk)
        blob += block
    block, _ = g._build_end_of_capture(1_700_000_001_000_000_000)
    blob += block
    path.write_bytes(bytes(blob))


@pytest.fixture
def small_stream_slab(monkeypatch):
    """Stream in 64 KiB slabs so small fixtures cross many slab boundaries."""
    monkeypatch.setattr(entropy_module, "STREAM_SLAB_BYTES", 1 << 16)


@pytest.mark.parametrize("fmt", ["raw", "msl"])
@pytest.mark.parametrize("kwargs", [
    {},  # what the Entropy tab sends (length=0 -> whole flat view)
    {"max_positions": 1000},
    {"window": 16, "step": 3, "threshold": 3.0},
    {"offset": 4096 * 7 + 5, "length": 300_000},  # > slab: streamed range
    {"offset": 100, "length": 256},  # InvestigationPanel's small range
])
def test_entropy_result_matches_frozen(tmp_path, small_stream_slab, fmt, kwargs):
    data = _heap_like(4096 * 160, 9)
    path = tmp_path / ("dump.bin" if fmt == "raw" else "dump.msl")
    if fmt == "raw":
        path.write_bytes(data)
    else:
        _write_msl(path, data, 4096 * 48)
    window = kwargs.get("window", 32)
    step = kwargs.get("step", 16)
    threshold = kwargs.get("threshold", 7.5)
    length = kwargs.get("length", 0)
    offset = kwargs.get("offset", 0)
    expected_bytes = data if length == 0 else data[offset:offset + length]
    # The sampled (bounded-step) path is the one the frozen copy describes;
    # "auto" would profile this small fixture at full resolution.
    result = tools_inspect.entropy_result(
        ToolSession(), str(path), offset, length, window, step, threshold,
        kwargs.get("max_positions"), resolution="sampled")
    payload = {k: v for k, v in result.payload.items() if k != "view"}
    for key in ("status", "key_status", "diagnostics"):
        payload.pop(key, None)
    # `byte_end` is an additive field the frozen payload predates.
    payload["high_entropy_regions"] = [
        {k: v for k, v in region.items() if k != "byte_end"}
        for region in payload["high_entropy_regions"]]
    want = _frozen_endpoint_payload(expected_bytes, window, step, threshold,
                                    kwargs.get("max_positions"),
                                    regions_of=profile_regions)
    assert {k: payload[k] for k in want} == want


def test_entropy_result_heap_is_bounded(tmp_path):
    """The whole-dump request streams: peak heap far below the dump size."""
    size = 48 << 20
    path = tmp_path / "big.bin"
    rng = np.random.default_rng(1)
    with open(path, "wb") as fh:
        for _ in range(size >> 22):
            fh.write(rng.integers(0, 256, 1 << 22, dtype=np.uint8).tobytes())
    tracemalloc.start()
    try:
        tools_inspect.entropy_result(ToolSession(), str(path))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # One 8 MiB slab + per-slab scratch + the 262144-position profile.
    assert peak < 32 << 20, peak


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
