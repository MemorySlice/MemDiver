"""Equivalence of the vectorised entropy_scan against the original loop.

``_scan_entropy_reference`` / ``_merge_overlapping_reference`` /
``_run_reference`` are verbatim copies of the pre-vectorisation
implementation; every comparison below demands exact ``Match`` equality
(offset, length, confidence, label, data bytes, metadata).
"""
import mmap
import os
import random
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.algorithms.base import AnalysisContext, Match
from memdiver.algorithms.unknown_key import entropy_scan as entropy_scan_module
from memdiver.algorithms.unknown_key.entropy_scan import EntropyScanAlgorithm
from memdiver.core.entropy import entropy_from_freq, entropy_from_freq_batch


# --- reference (old) implementation -------------------------------------

def _scan_entropy_reference(data, window_size, threshold, step):
    matches = []
    if len(data) < window_size:
        return matches

    freq = [0] * 256
    for i in range(window_size):
        freq[data[i]] += 1

    for pos in range(0, len(data) - window_size + 1, step):
        if pos > 0:
            freq[data[pos - 1]] -= 1
            freq[data[pos + window_size - 1]] += 1

        entropy = entropy_from_freq(freq, window_size)
        if entropy >= threshold:
            matches.append(Match(
                offset=pos,
                length=window_size,
                confidence=entropy / 8.0,
                label=f"high_entropy_{window_size}B",
                data=data[pos:pos + window_size],
                metadata={"entropy": round(entropy, 4), "window_size": window_size},
            ))

    return matches


def _merge_overlapping_reference(matches):
    if not matches:
        return []
    matches.sort(key=lambda m: (m.offset, -m.length))
    merged = [matches[0]]
    cluster_end = merged[0].offset + merged[0].length
    for m in matches[1:]:
        if m.offset < cluster_end:
            kept = merged[-1]
            if (m.confidence, m.length) > (kept.confidence, kept.length):
                merged[-1] = m
            cluster_end = max(cluster_end, m.offset + m.length)
        else:
            merged.append(m)
            cluster_end = m.offset + m.length
    return merged


def _run_reference(data, window_sizes, threshold, step):
    matches = []
    for window_size in window_sizes:
        matches.extend(_scan_entropy_reference(data, window_size, threshold, step))
    return _merge_overlapping_reference(matches)


# --- inputs ---------------------------------------------------------------

def _structured_dump(seed: int) -> bytes:
    rng = random.Random(seed)
    parts = []
    for _ in range(40):
        kind = rng.randrange(5)
        size = rng.randrange(1, 120)
        if kind == 0:
            parts.append(b"\x00" * size)
        elif kind == 1:
            parts.append(rng.randbytes(size))
        elif kind == 2:
            parts.append(bytes(range(256))[: size])
        elif kind == 3:
            parts.append(bytes(rng.randrange(8) for _ in range(size)))
        else:
            parts.append(b"ABCD" * (size // 4 + 1))
    return b"".join(parts)


def _threshold_boundary_dump() -> bytes:
    """Windows whose entropy is EXACTLY 4.5, 5.0 and 4.0 bits."""
    # 32-byte windows: 16 distinct bytes x 2 -> exactly 4.0 bits;
    # 32 distinct bytes -> exactly 5.0 bits.
    four = bytes(i // 2 for i in range(32))
    five = bytes(range(64, 96))
    return b"\x00" * 40 + four + five + four * 3 + five * 2 + b"\x00" * 40


INPUTS = {
    "empty": b"",
    "one_byte": b"\x7f",
    "shorter_than_window": os.urandom(31),
    "exact_window": os.urandom(32),
    "window_plus_one": os.urandom(33),
    "zeros": b"\x00" * 500,
    "random_small": random.Random(1).randbytes(700),
    "random_medium": random.Random(2).randbytes(20_000),
    "structured_a": _structured_dump(3),
    "structured_b": _structured_dump(4),
    "boundary": _threshold_boundary_dump(),
    "adjacent_keys": b"\x00" * 64 + os.urandom(32) + os.urandom(32) + b"\x00" * 64,
    "overlapping_keys": b"\x00" * 50 + os.urandom(80) + b"\x11" * 10 + os.urandom(48),
}

PARAMS = [
    ([32, 48], 4.5),
    ([32], 4.5),
    ([48, 32], 4.5),
    ([32, 32], 4.5),  # duplicate window sizes: stable-order tie-breaking
    ([16, 32, 64], 3.0),
    ([32], 4.0),      # exact-boundary value 4.0
    ([32], 5.0),      # exact-boundary value 5.0
    ([8], 0.0),       # every window qualifies
    ([32], 8.5),      # nothing qualifies
]


def _ctx(window_sizes, threshold, step=1):
    return AnalysisContext(
        library="t", tls_version="13", phase="p",
        extra={"window_sizes": window_sizes, "entropy_threshold": threshold,
               "step": step},
    )


@pytest.mark.parametrize("name", sorted(INPUTS))
@pytest.mark.parametrize("window_sizes,threshold", PARAMS)
def test_run_matches_reference(name, window_sizes, threshold):
    data = INPUTS[name]
    result = EntropyScanAlgorithm().run(data, _ctx(window_sizes, threshold))
    assert result.matches == _run_reference(data, window_sizes, threshold, 1)


@pytest.mark.parametrize("name", sorted(INPUTS))
@pytest.mark.parametrize("window_size,threshold", [(32, 4.5), (48, 4.5), (8, 2.0)])
def test_scan_entropy_matches_reference(name, window_size, threshold):
    data = INPUTS[name]
    got = EntropyScanAlgorithm()._scan_entropy(data, window_size, threshold, 1)
    assert got == _scan_entropy_reference(data, window_size, threshold, 1)


@pytest.mark.parametrize("step", [2, 3, 16])
def test_non_unit_step_matches_reference(step):
    data = INPUTS["structured_a"]
    result = EntropyScanAlgorithm().run(data, _ctx([32, 48], 4.5, step))
    assert result.matches == _run_reference(data, [32, 48], 4.5, step)


def test_boundary_dump_hits_exact_threshold():
    """The boundary input really contains windows at exactly 4.0 and 5.0."""
    hits = _scan_entropy_reference(INPUTS["boundary"], 32, 4.0, 1)
    values = {m.metadata["entropy"] for m in hits}
    assert 4.0 in values and 5.0 in values


def test_threshold_exactly_4_5_on_constructed_windows():
    """Windows with entropy 4.5: 16 bytes x1 + 8 bytes x2 (=32 bytes)."""
    window = bytes(range(16)) + bytes(16 + i // 2 for i in range(16))
    assert entropy_from_freq(
        [window.count(b) for b in range(256)], 32) == pytest.approx(4.5, abs=1e-12)
    data = b"\x00" * 32 + window + b"\x00" * 32 + window * 2
    for th in (4.5, entropy_from_freq([window.count(b) for b in range(256)], 32)):
        result = EntropyScanAlgorithm().run(data, _ctx([32], th))
        assert result.matches == _run_reference(data, [32], th, 1)


def test_random_fuzz_against_reference():
    rng = random.Random(1234)
    for _ in range(25):
        data = _structured_dump(rng.randrange(10_000))
        sizes = rng.sample([8, 16, 24, 32, 48, 64], rng.randrange(1, 4))
        threshold = rng.choice([2.0, 3.5, 4.0, 4.5, 5.0])
        result = EntropyScanAlgorithm().run(data, _ctx(sizes, threshold))
        assert result.matches == _run_reference(data, sizes, threshold, 1)


def test_mmap_input(tmp_path):
    data = INPUTS["structured_b"]
    path = tmp_path / "dump.bin"
    path.write_bytes(data)
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        result = EntropyScanAlgorithm().run(mm, _ctx([32, 48], 4.5))
        assert result.matches == _run_reference(data, [32, 48], 4.5, 1)
        assert all(isinstance(m.data, bytes) for m in result.matches)


def test_result_metadata_unchanged():
    data = INPUTS["random_small"]
    result = EntropyScanAlgorithm().run(data, _ctx([32, 48], 4.5))
    expected = _run_reference(data, [32, 48], 4.5, 1)
    assert result.metadata == {
        "window_sizes": [32, 48], "threshold": 4.5, "total_candidates": len(expected)}
    assert result.confidence == (min(len(expected) / 10.0, 1.0) if expected else 0.0)


def test_entropy_from_freq_batch_is_bit_identical():
    rng = np.random.default_rng(7)
    for total in (1, 2, 7, 32, 48, 255):
        rows = np.zeros((300, 256), dtype=np.int64)
        for row in rows:
            np.add.at(row, rng.integers(0, rng.integers(1, 257), total), 1)
        batch = entropy_from_freq_batch(rows, total)
        for row, value in zip(rows, batch.tolist()):
            ref = entropy_from_freq(row.tolist(), total)
            assert value == ref and str(value) == str(ref)


# --- streaming merge across slab boundaries --------------------------------

SLAB_SIZES = [1, 2, 3, 7, 16, 33]

BOUNDARY_INPUTS = {
    "random_medium": INPUTS["random_medium"][:3000],
    "structured_a": INPUTS["structured_a"],
    "overlapping_keys": INPUTS["overlapping_keys"],
    "boundary": INPUTS["boundary"],
    # high-entropy runs alternating with zeros so regions open/close often
    "striped": b"".join(random.Random(9).randbytes(n) + b"\x00" * z
                        for n, z in [(40, 3), (70, 31), (33, 1), (90, 50)] * 6),
}


@pytest.mark.parametrize("chunk", SLAB_SIZES)
@pytest.mark.parametrize("name", sorted(BOUNDARY_INPUTS))
@pytest.mark.parametrize("window_sizes,threshold", [
    ([32, 48], 4.5), ([48, 32], 4.5), ([32, 32], 4.5),
    ([16, 32, 64], 3.0), ([8], 0.0), ([8, 24], 2.5),
])
def test_tiny_slabs_match_reference(monkeypatch, chunk, name, window_sizes, threshold):
    """Regions spanning (many) slab boundaries are carried exactly."""
    monkeypatch.setattr(entropy_scan_module, "_SCAN_CHUNK_POSITIONS", chunk)
    monkeypatch.setattr(entropy_scan_module, "_ESTIMATE_CHUNK_POSITIONS", chunk)
    data = BOUNDARY_INPUTS[name]
    result = EntropyScanAlgorithm().run(data, _ctx(window_sizes, threshold))
    assert result.matches == _run_reference(data, window_sizes, threshold, 1)


@pytest.mark.parametrize("chunk", [1, 5, 64])
def test_tiny_slabs_random_fuzz(monkeypatch, chunk):
    """Random data / sizes with slab sizes that split every kind of cluster."""
    monkeypatch.setattr(entropy_scan_module, "_SCAN_CHUNK_POSITIONS", chunk)
    monkeypatch.setattr(entropy_scan_module, "_ESTIMATE_CHUNK_POSITIONS", chunk)
    rng = random.Random(4321 + chunk)
    for _ in range(12):
        if rng.random() < 0.3:
            data = rng.randbytes(rng.randrange(0, 1500))
        else:
            data = _structured_dump(rng.randrange(10_000))
        sizes = [rng.choice([8, 16, 24, 32, 48, 64]) for _ in range(rng.randrange(1, 4))]
        threshold = rng.choice([0.0, 2.0, 3.5, 4.0, 4.5, 5.0])
        result = EntropyScanAlgorithm().run(data, _ctx(sizes, threshold))
        assert result.matches == _run_reference(data, sizes, threshold, 1)


def test_window_sizes_interact_at_slab_boundary(monkeypatch):
    """A 64-byte window opened in one slab absorbs 16-byte windows of the next."""
    monkeypatch.setattr(entropy_scan_module, "_SCAN_CHUNK_POSITIONS", 10)
    monkeypatch.setattr(entropy_scan_module, "_ESTIMATE_CHUNK_POSITIONS", 10)
    data = b"\x00" * 9 + random.Random(5).randbytes(64) + b"\x00" * 40
    for sizes in ([16, 64], [64, 16]):
        result = EntropyScanAlgorithm().run(data, _ctx(sizes, 3.0))
        assert result.matches == _run_reference(data, sizes, 3.0, 1)


def test_streaming_matches_one_shot_merge_on_random(monkeypatch):
    """Default slab size on random data: one region per cluster, same as before."""
    data = random.Random(11).randbytes(50_000)
    algorithm = EntropyScanAlgorithm()
    columns = [algorithm._scan_entropy_arrays(data, w, 4.5, 1) for w in (32, 48)]
    expected = algorithm._merge_overlapping_arrays(columns)
    got = algorithm._scan_and_merge_streaming(data, [32, 48], 4.5)
    for g, e in zip(got, expected):
        assert g.dtype == e.dtype and np.array_equal(g, e)


# --- estimate-first step-1 scan vs the 256-bin streaming scan ---------------

def _assert_same_columns(got, expected):
    for g, e in zip(got, expected):
        assert g.dtype == e.dtype and np.array_equal(g, e)
    assert np.array_equal(np.signbit(got[2]), np.signbit(expected[2]))


def _tie_heavy_dump(seed: int) -> bytes:
    """Uniform blocks (exact 4.0 / log2(23) / 5.0 / 6.0-bit windows), repeats."""
    rng = random.Random(seed)
    parts = []
    for _ in range(30):
        k = rng.choice([16, 23, 24, 32, 48, 64])
        block = bytes(rng.sample(range(256), k))
        parts.append(block * rng.randrange(1, 5))
        parts.append(b"\x00" * rng.randrange(0, 40))
    return b"".join(parts)


ESTIMATE_INPUTS = dict(INPUTS, ties_a=_tie_heavy_dump(1), ties_b=_tie_heavy_dump(2),
                       periodic=random.Random(9).randbytes(32) * 40,
                       ascii=b"the quick brown fox jumps over the lazy dog " * 40)
ESTIMATE_PARAMS = PARAMS + [
    ([1], 0.0), ([2], 1.0), ([255, 256, 300], 7.9), ([300], 8.0),
    ([32, 48], 5.0), ([32], float(np.log2(23))), ([64, 16], 4.0),
    ([32, 48], float("-inf")), ([32, 48], float("nan")),
]


@pytest.mark.parametrize("name", sorted(ESTIMATE_INPUTS))
@pytest.mark.parametrize("window_sizes,threshold", ESTIMATE_PARAMS)
def test_estimated_scan_matches_streaming(name, window_sizes, threshold):
    """Bit-identical regions (offsets, lengths, entropy floats)."""
    data = ESTIMATE_INPUTS[name]
    got = EntropyScanAlgorithm._scan_and_merge_estimated(data, window_sizes, threshold)
    expected = EntropyScanAlgorithm._scan_and_merge_streaming(data, window_sizes, threshold)
    _assert_same_columns(got, expected)


@pytest.mark.parametrize("chunk", [1, 7, 100])
def test_estimated_scan_tiny_slabs_fuzz(monkeypatch, chunk):
    """Slab and exact-batch sizes that split clusters, ties and thresholds."""
    monkeypatch.setattr(entropy_scan_module, "_ESTIMATE_CHUNK_POSITIONS", chunk)
    monkeypatch.setattr(entropy_scan_module, "_EXACT_CHUNK_BYTES", 100)
    rng = random.Random(77 + chunk)
    for _ in range(15):
        data = rng.choice([_tie_heavy_dump, _structured_dump])(rng.randrange(1000))
        sizes = [rng.choice([1, 8, 16, 23, 32, 48, 64]) for _ in range(rng.randrange(1, 4))]
        threshold = rng.choice([0.0, 3.0, 4.0, 4.5, 5.0, float(np.log2(23)), 6.0])
        got = EntropyScanAlgorithm._scan_and_merge_estimated(data, sizes, threshold)
        _assert_same_columns(
            got, EntropyScanAlgorithm._scan_and_merge_streaming(data, sizes, threshold))


def test_step_one_dispatches_to_estimated_scan(monkeypatch):
    calls = []
    original = EntropyScanAlgorithm._scan_and_merge_estimated
    monkeypatch.setattr(EntropyScanAlgorithm, "_scan_and_merge_estimated", staticmethod(
        lambda *args: calls.append(args) or original(*args)))
    data = INPUTS["adjacent_keys"]
    result = EntropyScanAlgorithm().run(data, _ctx([32, 48], 4.5))
    assert calls and result.matches == _run_reference(data, [32, 48], 4.5, 1)


def test_unsupported_window_falls_back_to_streaming(monkeypatch):
    monkeypatch.setattr(entropy_scan_module, "supports_estimate", lambda window: False)
    monkeypatch.setattr(EntropyScanAlgorithm, "_scan_and_merge_estimated", staticmethod(
        lambda *args: pytest.fail("estimate path used")))
    data = INPUTS["structured_a"]
    result = EntropyScanAlgorithm().run(data, _ctx([32], 4.5))
    assert result.matches == _run_reference(data, [32], 4.5, 1)


def test_feed_sorted_with_ends_matches_feed():
    """A stand-in entry carrying a dropped run's end keeps the clustering."""
    offsets = np.array([0, 10, 20, 100], dtype=np.int64)
    lengths = np.array([32, 32, 32, 32], dtype=np.int64)
    entropies = np.array([4.6, 4.9, 4.7, 5.0])
    full = entropy_scan_module._RegionMerger()
    full.feed(offsets, lengths, entropies)
    # drop the (beaten) third window; the head stands in with its cluster end
    compact = entropy_scan_module._RegionMerger()
    compact.feed_sorted(offsets[[0, 1, 3]], lengths[[0, 1, 3]],
                        np.array([-np.inf, 4.9, 5.0]),
                        np.array([52, 52, 132], dtype=np.int64))
    _assert_same_columns(compact.finish(), full.finish())
