"""Tests for engine.brute_force — oracle-driven candidate iteration."""

import json
import os

import numpy as np
import pytest

from engine.brute_force import (
    EXIT_HIT,
    EXIT_NO_HIT,
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
