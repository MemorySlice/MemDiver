"""Tests for engine.brute_force — oracle-driven candidate iteration."""

import json
import os
from unittest.mock import patch

import numpy as np
import pytest

from memdiver.engine.brute_force import (
    EXIT_HIT,
    EXIT_NO_HIT,
    _run_parallel,
    brute_force_with_oracle,
    iter_candidate_slices,
    run_brute_force,
    write_result,
)


def _write_oracle(tmp_path, body: str):
    path = tmp_path / "oracle.py"
    path.write_text(body)
    os.chmod(path, 0o644)
    return path


def _synth_setup(tmp_path):
    np.random.seed(77)
    ref = bytearray(np.random.randint(0, 256, 1024, dtype=np.uint8).tobytes())
    target = bytes(range(32))
    ref[256:288] = target
    candidates = {
        "regions": [
            {"offset": 256, "length": 32, "mean_variance": 15000.0, "mean_entropy": 4.8},
            {"offset": 512, "length": 64, "mean_variance": 12000.0, "mean_entropy": 4.7},
        ]
    }
    cand_path = tmp_path / "cands.json"
    cand_path.write_text(json.dumps(candidates))
    return bytes(ref), target, cand_path, candidates["regions"]


def test_iter_slices_respects_region_bounds():
    ref = b"\x00" * 256
    regions = [{"offset": 64, "length": 32}]
    slices = list(iter_candidate_slices(regions, ref, [32], stride=8))
    # Only offset 64 can fit a 32-byte window within a 32-byte region.
    assert len(slices) == 1
    assert slices[0][1] == 64


def test_iter_slices_skips_oversized_keys():
    ref = b"\x00" * 256
    regions = [{"offset": 0, "length": 16}]
    slices = list(iter_candidate_slices(regions, ref, [32], stride=1))
    assert slices == []


def test_iter_slices_invalid_stride_raises():
    with pytest.raises(ValueError):
        list(iter_candidate_slices([], b"", [32], stride=0))


def test_brute_force_with_oracle_serial_hit(tmp_path):
    ref, target, _, regions = _synth_setup(tmp_path)

    def verify(candidate):
        return candidate == target

    result = brute_force_with_oracle(regions, ref, verify, stride=8)
    assert result.exit_code == EXIT_HIT
    assert len(result.hits) == 1
    assert result.hits[0].offset == 256
    assert result.hits[0].length == 32


def test_brute_force_no_hit_emits_top_k(tmp_path):
    ref, _, _, regions = _synth_setup(tmp_path)

    def always_false(_):
        return False

    result = brute_force_with_oracle(regions, ref, always_false, top_k=5)
    assert result.exit_code == EXIT_NO_HIT
    assert len(result.top_k) == 2
    # Ordered by mean_variance descending
    assert result.top_k[0].mean_variance >= result.top_k[1].mean_variance


def test_first_hit_short_circuit():
    ref = b"\x00" * 1024
    regions = [{"offset": 0, "length": 128}]

    def always_true(_):
        return True

    exhaustive = brute_force_with_oracle(regions, ref, always_true, stride=8)
    first_only = brute_force_with_oracle(regions, ref, always_true, stride=8, exhaustive=False)
    assert len(exhaustive.hits) > 1
    assert len(first_only.hits) == 1


def test_run_brute_force_parallel_path(tmp_path):
    ref, target, cand_path, _ = _synth_setup(tmp_path)
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\n"
        "def verify(c): return c == TARGET\n",
    )
    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=ref,
        oracle_path=oracle,
        jobs=2,
        stride=8,
    )
    assert result.exit_code == EXIT_HIT
    assert result.hits[0].offset == 256


def test_parallel_path_validates_oracle_in_parent(tmp_path, monkeypatch):
    """FIX #5: the parallel (jobs>1) branch must validate the oracle ONCE in the
    parent before workers spawn — otherwise --jobs N bypasses the load-time
    sandbox entirely. Spy the parent-side validator and assert it fired."""
    import memdiver.engine.brute_force as bf

    ref, target, cand_path, _ = _synth_setup(tmp_path)
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\n"
        "def verify(c): return c == TARGET\n",
    )
    calls = {"n": 0}
    real = bf.validate_oracle_sandboxed

    def _spy(path, config=None, **kw):
        calls["n"] += 1
        return real(path, config, **kw)

    monkeypatch.setattr(bf, "validate_oracle_sandboxed", _spy)
    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=ref,
        oracle_path=oracle,
        jobs=2,
        stride=8,
    )
    assert result.exit_code == EXIT_HIT
    # Exactly one parent-side validation for the whole parallel run.
    assert calls["n"] == 1


def test_parallel_path_rejects_hanging_oracle_before_workers(tmp_path, monkeypatch):
    """FIX #5: a hanging oracle is rejected in the parent (jobs>1) BEFORE any
    worker spawns. Patch the parent validator to raise (fast, deterministic —
    no real 4-worker hang) and assert the run aborts with OracleLoadError and
    _run_parallel is never reached."""
    import memdiver.engine.brute_force as bf
    from memdiver.engine.oracle import OracleLoadError

    ref, target, cand_path, _ = _synth_setup(tmp_path)
    oracle = _write_oracle(tmp_path, "def verify(c): return True\n")

    def _reject(path, config=None, **kw):
        raise OracleLoadError("oracle load exceeded 0.5s wall-clock (possible hang)")

    def _boom_parallel(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("_run_parallel reached despite rejected oracle")

    monkeypatch.setattr(bf, "validate_oracle_sandboxed", _reject)
    monkeypatch.setattr(bf, "_run_parallel", _boom_parallel)
    with pytest.raises(OracleLoadError, match="wall-clock"):
        run_brute_force(
            candidates_path=cand_path,
            reference_data=ref,
            oracle_path=oracle,
            jobs=4,
            stride=8,
        )


def test_run_brute_force_hits_sorted_and_job_invariant(tmp_path):
    """Exhaustive hits are offset-sorted and identical across job counts.

    The emitted Vol3 plugin anchors on hits[0], so identical inputs must yield
    an identical plugin whether run with jobs=1 (serial) or jobs>1 (parallel,
    which discovers hits in completion order).
    """
    np.random.seed(11)
    ref = bytearray(np.random.randint(0, 256, 2048, dtype=np.uint8).tobytes())
    target = bytes(range(32))
    for off in (512, 256, 1024):  # same key planted at several offsets
        ref[off:off + 32] = target
    ref = bytes(ref)
    regions = [
        {"offset": 256, "length": 512},   # candidates at 256 and 512
        {"offset": 1024, "length": 64},   # candidate at 1024
    ]
    cand_path = tmp_path / "cands.json"
    cand_path.write_text(json.dumps({"regions": regions}))
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\n"
        "def verify(c): return c == TARGET\n",
    )

    def _offsets(jobs):
        r = run_brute_force(
            candidates_path=cand_path, reference_data=ref,
            oracle_path=oracle, jobs=jobs, stride=8, exhaustive=True,
        )
        return [h.offset for h in r.hits]

    serial = _offsets(1)
    parallel = _offsets(4)
    assert serial == [256, 512, 1024]        # offset-sorted, all found
    assert serial == parallel                # job-count invariant
    assert parallel == sorted(parallel)      # never completion order


def test_run_parallel_streams_with_bounded_window(tmp_path):
    """_run_parallel must not eagerly drain the candidate iterator.

    With the old eager ``[pool.submit(...) for job in jobs_iter]`` an
    unbounded candidate iterator would loop forever (and balloon memory)
    before any result was processed. A bounded in-flight window lets the
    non-exhaustive early-cancel fire and the call terminate. We also
    assert the generator was never fully drained — only a bounded prefix
    is ever pulled.
    """
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes([1]) * 32\n"
        "def verify(c): return c == TARGET\n",
    )
    pulled = {"count": 0}
    hit_payload = bytes([1]) * 32
    miss_payload = bytes([0]) * 32

    def unbounded_jobs():
        # First candidate is the hit so exhaustive=False can short-circuit;
        # the rest are an effectively infinite stream of misses. If the
        # iterator were drained eagerly this generator would never return.
        i = 0
        while True:
            payload = hit_payload if i == 0 else miss_payload
            pulled["count"] += 1
            yield (0, i, 32, payload)
            i += 1
            if i > 10_000_000:  # safety net so a regression fails fast
                raise AssertionError("iterator drained without back-pressure")

    raw_hits, total = _run_parallel(
        unbounded_jobs(),
        oracle,
        {},
        2,
        exhaustive=False,
        # Explicit small chunk so the bound below stays tight: the in-flight
        # window counts CHUNKS, so the most the generator can ever be pulled by
        # is jobs*4 windows * chunk + one trailing refill batch.
        chunk=4,
    )
    assert len(raw_hits) == 1
    assert raw_hits[0] == (0, 0, 32)
    # Window is jobs*4 == 8 chunks of 4 == 32 candidates resident; we must
    # never have pulled the whole stream.
    assert pulled["count"] < 1000


def test_run_parallel_exhaustive_finds_all_hits(tmp_path):
    """Streaming must still cover every candidate in exhaustive mode."""
    oracle = _write_oracle(
        tmp_path,
        "def verify(c): return c[:1] == b'\\xaa'\n",
    )
    jobs_list = [
        (0, i, 1, (b"\xaa" if i % 2 == 0 else b"\xbb"))
        for i in range(40)
    ]
    raw_hits, total = _run_parallel(
        iter(jobs_list),
        oracle,
        {},
        3,
        exhaustive=True,
        total_estimate=len(jobs_list),
    )
    assert total == 40
    assert len(raw_hits) == 20
    assert {h[1] for h in raw_hits} == {i for i in range(40) if i % 2 == 0}


def test_run_parallel_chunk_size_is_throughput_only(tmp_path):
    """``chunk`` batches IPC; it must never change the result.

    Sizes below, at, and above the candidate count must all yield an identical
    hit set and identical total. Batch size is a throughput knob, so a
    regression that let it alter coverage (e.g. a dropped trailing batch) would
    silently shrink an exhaustive sweep.
    """
    oracle = _write_oracle(
        tmp_path,
        "def verify(c): return c[:1] == b'\\xaa'\n",
    )
    jobs_list = [
        (0, i, 1, (b"\xaa" if i % 7 == 0 else b"\xbb"))
        for i in range(300)
    ]
    expected_hits = sorted(h[1] for h in jobs_list if h[3] == b"\xaa")

    seen = {}
    for chunk in (1, 16, 256):
        raw_hits, total = _run_parallel(
            iter(list(jobs_list)),
            oracle,
            {},
            2,
            exhaustive=True,
            total_estimate=len(jobs_list),
            chunk=chunk,
        )
        seen[chunk] = (total, sorted(h[1] for h in raw_hits))

    for chunk, (total, offsets) in seen.items():
        assert total == 300, chunk
        assert offsets == expected_hits, chunk
    assert seen[1] == seen[16] == seen[256]


def test_neighborhood_variance_attached_from_state(tmp_path):
    ref, target, cand_path, _ = _synth_setup(tmp_path)
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\ndef verify(c): return c == TARGET\n",
    )

    state_path = tmp_path / "cons.state"
    m2_path = tmp_path / "cons.m2.npy"
    mean_path = tmp_path / "cons.mean.npy"
    m2 = np.zeros(1024, dtype=np.float32)
    m2[256:288] = 45000.0  # variance = 15000 at N=3
    np.save(m2_path, m2)
    np.save(mean_path, np.zeros(1024, dtype=np.float32))
    state_path.write_text(json.dumps({
        "size": 1024, "num_dumps": 3,
        "mean_path": str(mean_path), "m2_path": str(m2_path),
    }))

    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=ref,
        oracle_path=oracle,
        state_path=state_path,
        stride=8,
    )
    hit = result.hits[0]
    assert hit.neighborhood_start == 192
    assert len(hit.neighborhood_variance) == 160
    # Middle 32 entries match the planted variance
    assert all(abs(v - 15000.0) < 0.1 for v in hit.neighborhood_variance[64:96])


def test_write_result_round_trip(tmp_path):
    ref, target, _, regions = _synth_setup(tmp_path)

    def verify(c):
        return c == target

    result = brute_force_with_oracle(regions, ref, verify, stride=8)
    out = write_result(result, tmp_path / "hits.json")
    reloaded = json.loads(out.read_text())
    assert reloaded["hits"][0]["key_hex"] == target.hex()
    assert reloaded["total_candidates"] == result.total_candidates


def test_auto_jobs_result_is_identical_to_serial(tmp_path):
    """``jobs=0`` (auto) must produce a byte-identical result to ``jobs=1``.

    Auto is a throughput decision only. Whether it resolved to serial or to a
    worker pool, the whole emitted artifact — hit list, offsets, key material,
    candidate totals and coverage fraction — must match the serial run exactly,
    because ``hits.json`` is the record a reader reproduces from.
    """
    np.random.seed(29)
    ref = bytearray(np.random.randint(0, 256, 8192, dtype=np.uint8).tobytes())
    target = bytes(range(32))
    for off in (1024, 96, 4096, 2048):  # several planted keys, out of order
        ref[off:off + 32] = target
    ref = bytes(ref)
    cand_path = tmp_path / "cands.json"
    cand_path.write_text(json.dumps({"regions": [{"offset": 0, "length": 8192}]}))
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\n"
        "def verify(c): return c == TARGET\n",
    )

    import memdiver.engine.brute_force as bf

    def _run(jobs):
        return run_brute_force(
            candidates_path=cand_path, reference_data=ref,
            oracle_path=oracle, jobs=jobs, stride=1, exhaustive=True,
        )

    serial = _run(1)

    # Drop the threshold and pin the cpu count so auto genuinely resolves to a
    # pool here — otherwise this 8k-candidate fixture would take the serial
    # branch and the comparison would prove nothing.
    took_parallel = {"n": 0}
    real_parallel = bf._run_parallel

    def _spy(*a, **k):
        took_parallel["n"] += 1
        return real_parallel(*a, **k)

    with patch.object(bf, "PARALLEL_MIN_CANDIDATES", 1), \
            patch.object(bf.os, "cpu_count", return_value=8), \
            patch.object(bf, "_run_parallel", _spy):
        auto = _run(0)

    assert took_parallel["n"] == 1, "auto did not take the parallel branch"
    assert [h.offset for h in serial.hits] == [96, 1024, 2048, 4096]
    assert auto.to_dict() == serial.to_dict()


def test_auto_jobs_stays_serial_for_a_first_hit_run(tmp_path):
    """A non-exhaustive run must never be auto-parallelised.

    The parallel path's post-hit drain makes ``total_candidates`` scheduling
    dependent, so a first-hit sweep at ``jobs=0`` must take the serial branch —
    asserted here by proving ``_run_parallel`` is never reached.
    """
    import memdiver.engine.brute_force as bf

    ref, target, cand_path, _ = _synth_setup(tmp_path)
    oracle = _write_oracle(
        tmp_path,
        "TARGET = bytes(range(32))\ndef verify(c): return c == TARGET\n",
    )

    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("auto parallelised a non-exhaustive run")

    with patch.object(bf, "_run_parallel", _boom), \
            patch.object(bf, "PARALLEL_MIN_CANDIDATES", 1):
        result = run_brute_force(
            candidates_path=cand_path, reference_data=ref,
            oracle_path=oracle, jobs=0, stride=1, exhaustive=False,
        )
    assert result.hits
