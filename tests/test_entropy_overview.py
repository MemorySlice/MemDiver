"""Full-resolution entropy overview (core.entropy_overview) + its endpoint path.

Contract under test:

* regions == ``find_high_entropy_regions(profile_step1, threshold, min_width)``
  with identical starts/ends, where ``profile_step1`` is the FROZEN pre-change
  profile (``tests/test_entropy_fast_profile._frozen_compute_entropy_profile``);
  means within 1e-9;
* every envelope bucket's min/max/mean equals the exact per-window values of
  its window starts within 1e-9 (the estimate's documented tolerance);
* results do not depend on slab size, sub-slab size or worker count.
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app import entropy_payload  # noqa: E402
from memdiver.app import tools_inspect  # noqa: E402
from memdiver.app.session import ToolSession  # noqa: E402
from memdiver.core import entropy_overview as overview_module  # noqa: E402
from memdiver.core.entropy import (  # noqa: E402
    compute_entropy_profile,
    find_high_entropy_regions,
    shannon_entropy,
)
from memdiver.core.entropy_overview import (  # noqa: E402
    MAX_ENVELOPE_BUCKETS,
    clamp_buckets,
    envelope_bucket_edges,
    envelope_from_profile,
    merge_close_runs,
    stream_entropy_overview,
)
from memdiver.core.entropy_profile import EntropyProfile  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from tests.test_entropy_fast_profile import (  # noqa: E402
    _frozen_compute_entropy_profile,
    _heap_like,
)

TOL = 1e-9


_WORDS = [w.encode() for w in (
    "the", "session", "key", "value", "error", "config", "buffer", "socket",
    "handshake", "client", "server", "memory", "python", "object", "string")]


def quiet_heap(size, seed=5):
    """Low-entropy heap-like bytes: zero pages, chunk headers, aligned
    user-space pointers, small integers and English-word text -- the content
    a real heap mostly holds, none of it near 4.5 bits/byte at window 32."""
    rng = np.random.default_rng(seed)
    out = np.zeros(size, dtype=np.uint8)
    for page in range(0, size, 4096):
        if rng.random() < 0.5:
            continue  # zero page
        for chunk in range(page, min(page + 4096, size) - 64, 64):
            kind = rng.integers(0, 4)
            out[chunk] = 0x41  # chunk header: size | flags
            if kind == 0:  # 6 pointers into one arena
                base = 0x7F3A5C000000 + int(rng.integers(0, 1 << 16)) * 16
                for k in range(6):
                    ptr = base + int(rng.integers(0, 64)) * 16
                    out[chunk + 8 + 8 * k:chunk + 16 + 8 * k] = np.frombuffer(
                        ptr.to_bytes(8, "little"), dtype=np.uint8)
            elif kind == 1:  # small ints
                out[chunk + 8:chunk + 56:4] = rng.integers(0, 16, 12)
            elif kind == 2:  # text
                text = b" ".join(_WORDS[i] for i in rng.integers(0, len(_WORDS), 12))[:56]
                out[chunk + 8:chunk + 8 + len(text)] = np.frombuffer(text, dtype=np.uint8)
    return out


def _planted(size, keys, seed=3, filler=None):
    """Heap-like bytes with random keys ``(offset, length)`` planted in it."""
    data = bytearray(_heap_like(size, seed) if filler is None else filler.tobytes())
    rng = np.random.default_rng(seed)
    for offset, length in keys:
        data[offset:offset + length] = rng.integers(0, 256, length, dtype=np.uint8).tobytes()
    return bytes(data)


def _overview(data, window=32, threshold=4.5, min_width=1, **kwargs):
    return stream_entropy_overview(lambda o, n: data[o:o + n], len(data), window,
                                   threshold, min_width, **kwargs)


def _assert_envelope_exact(data, ov, window):
    values = _frozen_compute_entropy_profile(data, window, 1).values
    env = ov.envelope
    assert env.starts[0] == 0 and env.stops[-1] == len(values)
    assert np.array_equal(env.starts[1:], env.stops[:-1])
    for k in range(len(env)):
        segment = values[env.starts[k]:env.stops[k]]
        assert abs(segment.max() - env.maximum[k]) <= TOL
        assert abs(segment.min() - env.minimum[k]) <= TOL
        assert abs(segment.mean() - env.mean[k]) <= TOL


# --- bucket edges -----------------------------------------------------------

@pytest.mark.parametrize("positions,buckets", [
    (1, 1), (1, 1500), (7, 3), (10, 10), (11, 10), (1000, 1500), (123457, 1500)])
def test_bucket_edges_partition_every_position(positions, buckets):
    edges = envelope_bucket_edges(positions, buckets)
    sizes = np.diff(edges)
    assert edges[0] == 0 and edges[-1] == positions
    assert len(sizes) == min(positions, buckets)
    assert sizes.min() >= 1 and sizes.max() - sizes.min() <= 1


@pytest.mark.parametrize("positions,buckets", [(0, 10), (-5, 10), (10, 0)])
def test_bucket_edges_empty(positions, buckets):
    assert envelope_bucket_edges(positions, buckets).tolist() == [0]


def test_clamp_buckets():
    assert clamp_buckets(None) == overview_module.DEFAULT_ENVELOPE_BUCKETS
    assert clamp_buckets(0) == 1 and clamp_buckets(-3) == 1
    assert clamp_buckets(10 ** 9) == MAX_ENVELOPE_BUCKETS


# --- equivalence with the frozen step-1 profile ----------------------------

@pytest.mark.parametrize("window,threshold,min_width", [
    (32, 4.5, 1), (32, 4.5, 32), (32, 3.0, 8), (16, 3.6, 1), (48, 5.0, 4),
    (64, 5.3, 1), (32, 0.0, 1), (32, -1.0, 0), (32, 5.0, 1)])
def test_regions_match_frozen_step1_profile(window, threshold, min_width):
    data = _planted(1 << 18, [(5000, 32), (70000, 64), (150001, 16), (200000, 300)])
    ov = _overview(data, window, threshold, min_width, slab_bytes=50_000,
                   subslab_positions=9_000, workers=3)
    want = find_high_entropy_regions(
        _frozen_compute_entropy_profile(data, window, 1), threshold, min_width)
    assert [(s, e) for s, e, _ in ov.regions] == [(s, e) for s, e, _ in want]
    assert all(abs(a[2] - b[2]) <= TOL for a, b in zip(ov.regions, want))
    _assert_envelope_exact(data, ov, window)


def test_threshold_band_is_decided_exactly():
    """Thresholds AT exact window values hit the estimate's undecided band."""
    data = _planted(1 << 15, [(1000, 32), (9000, 40)])
    values = compute_entropy_profile(data, 32, 1).values
    for threshold in np.unique(values[values > 3.5])[::7].tolist():
        ov = _overview(data, 32, threshold, 1)
        want = find_high_entropy_regions(compute_entropy_profile(data, 32, 1), threshold, 1)
        assert [(s, e) for s, e, _ in ov.regions] == [(s, e) for s, e, _ in want]


@pytest.mark.parametrize("kwargs", [
    {"slab_bytes": 4096, "subslab_positions": 1000, "workers": 1},
    {"slab_bytes": 33, "subslab_positions": 7, "workers": 2},
    {"slab_bytes": 1 << 20, "subslab_positions": 1 << 17, "workers": 4},
])
def test_result_independent_of_slabbing(kwargs):
    data = _planted(40_000, [(100, 32), (39_960, 40), (20_000, 64)])
    base = _overview(data, buckets=97)
    other = _overview(data, buckets=97, **kwargs)
    assert [r[:2] for r in other.regions] == [r[:2] for r in base.regions]
    # Window values are slab-independent (integer fixed-point sums); only the
    # float summation order of a region's mean can differ.
    assert all(abs(a[2] - b[2]) <= TOL for a, b in zip(other.regions, base.regions))
    for name in ("starts", "stops", "minimum", "maximum"):
        assert np.array_equal(getattr(other.envelope, name), getattr(base.envelope, name))
    assert np.allclose(other.envelope.mean, base.envelope.mean, atol=TOL)
    assert other.overall_entropy == base.overall_entropy == shannon_entropy(data)


def test_zero_blocks_are_exact_zero():
    data = bytes(1 << 16) + bytes(range(256)) + bytes(1 << 16)
    ov = _overview(data, buckets=64)
    _assert_envelope_exact(data, ov, 32)
    assert ov.envelope.maximum[0] == 0.0 and ov.envelope.maximum[-1] == 0.0
    assert ov.minimum == 0.0


# --- run merging -----------------------------------------------------------

def _runs(*triples):
    starts, stops, counts = (np.array(c, dtype=np.int64) for c in zip(*triples))
    return starts, stops, counts.astype(np.float64)


def test_merge_close_runs_join_gap_one_keeps_runs():
    starts, stops, counts = _runs((0, 4, 4), (6, 7, 1), (40, 80, 40))
    sums = counts * 2.0
    assert merge_close_runs(starts, stops, sums, counts, 1, 0) == [
        (0, 4, 2.0), (6, 7, 2.0), (40, 80, 2.0)]
    assert merge_close_runs(starts, stops, sums, counts, 1, 2) == [(0, 4, 2.0), (40, 80, 2.0)]


def test_merge_close_runs_joins_then_filters_and_weights_means():
    starts, stops, counts = _runs((0, 4, 4), (6, 7, 1), (40, 80, 40))
    sums = np.array([4 * 5.0, 1 * 4.0, 40 * 3.0])
    merged = merge_close_runs(starts, stops, sums, counts, 31, 5)
    assert merged == [(0, 7, pytest.approx(24.0 / 5)), (40, 80, 3.0)]
    assert merge_close_runs(starts[:0], stops[:0], sums[:0], counts[:0], 31, 0) == []


def test_overview_join_gap_merges_reference_runs():
    data = _planted(1 << 17, [(9000, 700), (30_000, 32), (30_060, 32)])
    ov = _overview(data, 32, 4.5, 1, join_gap=31)
    runs = find_high_entropy_regions(compute_entropy_profile(data, 32, 1), 4.5, 0)
    starts, stops, means = (np.array(c) for c in zip(*runs))
    counts = (stops - starts).astype(np.float64)
    want = merge_close_runs(starts, stops, means * counts, counts, 31, 1)
    assert [r[:2] for r in ov.regions] == [r[:2] for r in want]
    assert all(abs(a[2] - b[2]) <= TOL for a, b in zip(ov.regions, want))


def test_random_buffer_is_one_region_not_shreds():
    rng = np.random.default_rng(2)
    data = bytes(4096) + rng.integers(0, 256, 1 << 20, dtype=np.uint8).tobytes() + bytes(4096)
    unmerged = _overview(data, 32, 4.5, 1)
    merged = _overview(data, 32, 4.5, 1, join_gap=31)
    assert len(unmerged.regions) > 10  # windows dip below 4.5 ~2 in 10^4
    assert len(merged.regions) == 1
    start, stop, _ = merged.regions[0]
    assert 4096 - 31 <= start <= 4096 and 4096 + (1 << 20) - 32 <= stop


# --- tiny inputs ------------------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, 31])
def test_input_shorter_than_window(size):
    data = bytes(range(size))
    ov = _overview(data)
    assert ov.positions == 0 and len(ov.envelope) == 0 and ov.regions == []
    assert ov.overall_entropy == shannon_entropy(data)


@pytest.mark.parametrize("size", [32, 33, 40])
def test_tiny_inputs(size):
    data = bytes(range(size))
    ov = _overview(data, buckets=1500)
    assert ov.positions == size - 31
    assert len(ov.envelope) == size - 31  # one window per bucket
    _assert_envelope_exact(data, ov, 32)
    assert ov.regions == [(0, size - 31, pytest.approx(5.0))]


def test_exact_fallback_when_estimate_unsupported(monkeypatch):
    monkeypatch.setattr(overview_module, "supports_estimate", lambda window: False)
    data = _planted(20_000, [(500, 32)])
    ov = _overview(data, buckets=50)
    want = find_high_entropy_regions(compute_entropy_profile(data, 32, 1), 4.5, 1)
    assert [r[:2] for r in ov.regions] == [r[:2] for r in want]
    assert all(abs(a[2] - b[2]) <= TOL for a, b in zip(ov.regions, want))
    _assert_envelope_exact(data, ov, 32)


# --- the planted-key story --------------------------------------------------

@pytest.mark.parametrize("key_len", [32, 64])
def test_planted_key_is_a_spike_and_a_region(key_len):
    key_at = 300_017
    data = _planted(1 << 20, [(key_at, key_len)], filler=quiet_heap(1 << 20))
    ov = _overview(data, buckets=1500)
    bucket = int(np.searchsorted(ov.envelope.stops, key_at, side="right"))
    assert ov.envelope.maximum[bucket] >= 4.5
    assert [(s <= key_at < e + 31) for s, e, _ in ov.regions] == [True]  # only the key
    # The sampled profile the tab used to plot does not see it.
    step = tools_inspect._bounded_entropy_step(len(data), 32, 16, 1 << 18)
    sampled = compute_entropy_profile(data, 32, step)
    picks = entropy_payload.sample_indices(len(sampled))
    assert max(sampled.values[picks]) < 4.5 or step == 1


def test_samples_are_requested_positions():
    data = _planted(10_000, [(4000, 32)])
    positions = np.array([0, 17, 4000, 9968])
    ov = _overview(data, sample_positions=positions)
    exact = compute_entropy_profile(data, 32, 1).values[positions]
    assert ov.sample_offsets.tolist() == positions.tolist()
    assert np.allclose(ov.sample_values, exact, atol=TOL)


# --- envelope of a sampled profile ------------------------------------------

def test_envelope_from_profile_buckets_points():
    profile = EntropyProfile(np.array([0, 10, 20, 30, 40]), np.array([1.0, 2.0, 3.0, 4.0, 5.0]))
    env = envelope_from_profile(profile, 41, buckets=4)
    assert env.starts.tolist() == [0, 10, 20, 30]
    assert env.maximum.tolist() == [1.0, 2.0, 3.0, 5.0]
    assert env.minimum.tolist() == [1.0, 2.0, 3.0, 4.0]
    assert env.mean.tolist() == [1.0, 2.0, 3.0, 4.5]
    sparse = envelope_from_profile(profile, 41, buckets=41)
    assert sparse.starts.tolist() == [0, 10, 20, 30, 40]  # empty buckets omitted
    empty = envelope_from_profile(EntropyProfile.empty(), 0)
    assert len(empty) == 0


# --- entropy_result ---------------------------------------------------------

@pytest.fixture
def planted_dump(tmp_path):
    data = _planted(1 << 20, [(400_000, 32), (800_000, 64)], filler=quiet_heap(1 << 20))
    path = tmp_path / "planted.bin"
    path.write_bytes(data)
    return str(path), data


def _result(path, **kwargs):
    return tools_inspect.entropy_result(ToolSession(), path, **kwargs).payload


def test_full_resolution_response(planted_dump):
    path, data = planted_dump
    payload = _result(path, resolution="full", buckets=500)
    assert payload["resolution"] == "full" and payload["step"] == 1
    assert payload["full_resolution_available"] is False
    assert payload["threshold"] == 4.5 and payload["threshold_source"] == "default"
    assert payload["max_entropy"] == 5.0 and payload["threshold_reachable"]
    env = payload["envelope"]
    assert len(env["starts"]) == 500 == len(env["max"]) == len(env["min"]) == len(env["mean"])
    want = find_high_entropy_regions(compute_entropy_profile(data, 32, 1), 4.5, 1)
    got = payload["high_entropy_regions"]
    assert [(r["start"], r["end"]) for r in got] == [(s, e) for s, e, _ in want]
    assert all(r["byte_end"] == r["end"] - 1 + 32 for r in got)
    assert payload["region_count"] == len(want) and not payload["regions_truncated"]
    assert any(r["start"] <= 400_000 < r["byte_end"] for r in got)
    assert any(r["start"] <= 800_000 < r["byte_end"] for r in got)
    assert len(payload["profile_sample"]) == 200
    assert payload["overall_entropy"] == round(shannon_entropy(data), 4)


def test_auto_is_full_for_small_and_sampled_for_large(planted_dump, monkeypatch):
    path, _ = planted_dump
    assert _result(path)["resolution"] == "full"
    monkeypatch.setattr(entropy_payload, "FULL_RESOLUTION_AUTO_BYTES", 1 << 16)
    sampled = _result(path)
    assert sampled["resolution"] == "sampled"
    assert sampled["full_resolution_available"] is True
    assert sampled["envelope"]["starts"]  # a (sampled) envelope is still there


def test_sampled_resolution_keeps_historical_fields(planted_dump):
    path, _ = planted_dump
    payload = _result(path, resolution="sampled", step=16)
    assert payload["resolution"] == "sampled" and payload["step"] == 16
    assert {"overall_entropy", "high_entropy_regions", "profile_sample", "stats",
            "step", "window", "view"} <= set(payload)


def test_explicit_unreachable_threshold_is_kept_and_flagged(planted_dump):
    path, _ = planted_dump
    payload = _result(path, threshold=7.5, resolution="full")
    assert payload["threshold"] == 7.5 and payload["threshold_source"] == "explicit"
    assert payload["threshold_reachable"] is False
    assert payload["warnings"] == ["threshold_unreachable"]
    assert payload["high_entropy_regions"] == []


def test_regions_are_capped(planted_dump, monkeypatch):
    path, _ = planted_dump
    monkeypatch.setattr(entropy_payload, "MAX_ENTROPY_REGIONS", 1)
    payload = _result(path, resolution="full")
    assert len(payload["high_entropy_regions"]) == 1
    assert payload["region_count"] >= 2 and payload["regions_truncated"]


def test_invalid_resolution_is_invalid_input(planted_dump):
    path, _ = planted_dump
    with pytest.raises(CapabilityError) as info:
        _result(path, resolution="everything")
    assert info.value.category.name == "INVALID_INPUT"


def test_rest_route_full_resolution(planted_dump):
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    path, _ = planted_dump
    response = TestClient(create_app()).get(
        "/api/inspect/entropy",
        params={"dump_path": path, "resolution": "full", "buckets": 100})
    assert response.status_code == 200
    body = response.json()
    assert body["resolution"] == "full" and len(body["envelope"]["max"]) == 100
    assert body["region_count"] >= 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
