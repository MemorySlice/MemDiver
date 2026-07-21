"""Tests for engine.auto_floor — automated ground-truth-free floor selection.

Uses synthetic consensus vectors + a synthetic reference dump with a planted
32-byte "key" and a matching in-process oracle, so no real captures are needed.
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.engine.auto_floor import (  # noqa: E402
    DEFAULT_FLOOR,
    SIGMA_K2,
    VERDICT_ABSENT,
    VERDICT_FLOOR_TOO_HIGH,
    VERDICT_INCONCLUSIVE,
    VERDICT_RECOVERED,
    absence_confidence,
    compute_phi0,
    compute_phi_from_pmin,
    oracle_self_test,
    recall_lower_bound,
    run_auto_floor,
    write_auto_floor_artifacts,
    _enumerate_candidates,
    _sigma_k2_interior,
)
from memdiver.engine.candidate_pipeline import CandidateRegion  # noqa: E402

REDUCE_KWARGS = dict(
    alignment=8, block_size=32, density_threshold=0.5,
    entropy_window=32, entropy_threshold=4.5, min_region=16,
)
SIZE = 200_000
KOFF = 8 * 1234  # 8-aligned planted-key offset


def _fixture(key_variance: float):
    """Return (variance, reference, key, oracle) with a planted key window."""
    rng = np.random.default_rng(0)
    ref = bytearray(rng.integers(0, 4, SIZE, dtype=np.uint8).tobytes())  # low-entropy bg
    key = bytes(rng.integers(0, 256, 32, dtype=np.uint8).tolist())
    ref[KOFF:KOFF + 32] = key
    ref = bytes(ref)
    var = np.full(SIZE, 50.0, dtype=np.float32)
    var[KOFF:KOFF + 32] = key_variance

    def oracle(cand: bytes) -> bool:
        return cand == key

    return var, ref, key, oracle


# ── compute_phi0 ─────────────────────────────────────────────────────
def test_compute_phi0_lands_below_default_on_diluted_sample():
    rng = np.random.default_rng(1)
    structural = rng.uniform(50, 200, 4000)
    # depressed "crypto" band matching the gocryptfs footnote-2 observation
    crypto = rng.uniform(2231, 5380, 400)
    sample = np.concatenate([structural, crypto])
    res = compute_phi0(sample, num_dumps=20)
    # lower edge of the crypto component (~2231), deflated by CV(20)≈0.2 → ~1500
    assert 1000.0 < res.phi0 < DEFAULT_FLOOR
    assert res.v_lo > 2000.0  # high-component lower edge, not the antimode
    assert res.lcb_deflation < 1.0  # finite-N deflation applied


def test_compute_phi0_empty():
    res = compute_phi0(np.zeros(10, dtype=np.float32), num_dumps=5)
    assert res.phi0 == 0.0


# ── compute_phi_from_pmin (phi = p_min * sigma_k^2) ──────────────────
def _pmin_region(interior_var: float, region: int = 256):
    """Variance array + (offsets, sizes) for a stride-8 candidate region."""
    var = np.full(SIZE, 50.0, dtype=np.float64)
    var[KOFF:KOFF + region] = interior_var
    offs = np.arange(KOFF, KOFF + region - 32 + 1, 8, dtype=np.int64)
    szs = np.full(offs.size, 32, dtype=np.int64)
    return var, offs, szs


def test_phi_from_pmin_uses_ceiling_when_N_insufficient():
    var, offs, szs = _pmin_region(4000.0)
    # p_min=0.35 needs N>=ceil(5/0.35)=15; N=5 is insufficient → ceiling fallback
    res = compute_phi_from_pmin(var, offs, szs, p_min=0.35, num_dumps=5)
    assert res.method == "pmin"
    assert abs(res.v_lo - SIGMA_K2) < 1e-6           # sigma_k2_hat == ceiling
    assert abs(res.phi0 - 0.35 * SIGMA_K2) < 1e-6    # ~1911


def test_phi_from_pmin_interior_estimate_when_N_sufficient():
    var, offs, szs = _pmin_region(4000.0)
    res = compute_phi_from_pmin(var, offs, szs, p_min=0.35, num_dumps=20)
    # interior P90 ≈ 4000 (within [0.5*ceil, ceil]) → phi = 0.35*4000 = 1400
    assert abs(res.v_lo - 4000.0) < 50.0
    assert abs(res.phi0 - 0.35 * 4000.0) < 25.0


def test_phi_from_pmin_thin_interior_falls_back_to_ceiling():
    # a single window has only 16 interior bytes (< min_bytes=50) → None → ceiling
    var = np.full(SIZE, 50.0, dtype=np.float64)
    var[KOFF:KOFF + 32] = 4000.0
    est = _sigma_k2_interior(var, np.array([KOFF]), np.array([32]))
    assert est is None
    res = compute_phi_from_pmin(var, np.array([KOFF]), np.array([32]),
                                p_min=0.4, num_dumps=100)
    assert abs(res.phi0 - 0.4 * SIGMA_K2) < 1e-6


def test_phi_from_pmin_backsolves_manual_region():
    """The paper's back-solve: default 3000 ⇔ p_min≈0.55; manual 1500 ⇔ ~0.27."""
    var, offs, szs = _pmin_region(4000.0)  # thin/insufficient path uses ceiling
    phi_055 = compute_phi_from_pmin(var, offs, szs, p_min=0.55, num_dumps=3).phi0
    phi_027 = compute_phi_from_pmin(var, offs, szs, p_min=0.27, num_dumps=3).phi0
    assert abs(phi_055 - DEFAULT_FLOOR) < 50.0   # ≈ 3004 ~ shipped default 3000
    assert 1300.0 < phi_027 < 1600.0             # ≈ 1475 ~ manual 1500


def test_run_auto_floor_pmin_is_default():
    var, ref, key, oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, oracle, reduce_kwargs=REDUCE_KWARGS, coverage=1.0)
    assert r.phi0_detail is not None and r.phi0_detail.method == "pmin"
    assert r.phi0 is not None and r.phi0 > 0.0


# ── C3: recall lower bound keeps ABSENT confidence conservative ──────
def test_recall_lower_bound_is_below_point_estimate():
    assert recall_lower_bound(0, 0) == 0.0
    assert recall_lower_bound(0, 20) == 0.0
    lb = recall_lower_bound(20, 20)
    assert 0.0 < lb < 1.0              # never claims perfect recall
    # more evidence at the same rate → tighter (higher) lower bound
    assert recall_lower_bound(100, 100) > recall_lower_bound(20, 20)
    # a lower observed rate → lower bound
    assert recall_lower_bound(15, 20) < recall_lower_bound(19, 20)


def test_absence_confidence_only_lowered_by_recall_bound():
    # confidence = coverage * recall_lower_bound ≤ coverage (never inflated)
    conf = absence_confidence(1.0, recall_lower_bound(19, 20))
    assert conf is not None and conf < 1.0


# ── oracle_self_test ─────────────────────────────────────────────────
def test_oracle_self_test_healthy():
    _var, ref, key, oracle = _fixture(2300.0)
    h = oracle_self_test(oracle, ref, positive_control=key)
    assert h.healthy and h.negatives_ok and h.positive_ok and h.deterministic


def test_oracle_self_test_always_true_is_unhealthy():
    _var, ref, _key, _oracle = _fixture(2300.0)
    h = oracle_self_test(lambda c: True, ref)
    assert not h.healthy and not h.negatives_ok


def test_oracle_self_test_wrong_positive_control_is_unhealthy():
    _var, ref, _key, oracle = _fixture(2300.0)
    h = oracle_self_test(oracle, ref, positive_control=b"\x00" * 32)
    assert h.positive_ok is False and not h.healthy


# ── helpers ──────────────────────────────────────────────────────────
def test_enumerate_candidates_snaps_to_stride():
    regions = [CandidateRegion(offset=10, length=64, mean_entropy=5.0, mean_variance=1.0)]
    pairs = _enumerate_candidates(regions, dump_len=10_000, key_sizes=(32,), stride=8)
    # first offset snaps up from 10 -> 16, then steps by 8 while +32 fits in [10,74)
    assert pairs[0] == (16, 32)
    assert all(o % 8 == 0 and o + 32 <= 74 for o, _ in pairs)


def test_absence_confidence():
    assert absence_confidence(None, 0.9) is None
    assert absence_confidence(0.9, None) == pytest.approx(0.9)
    assert absence_confidence(0.8, 0.95) == pytest.approx(0.76)
    assert absence_confidence(1.5, 2.0) == pytest.approx(1.0)  # clamped


# ── run_auto_floor verdicts ──────────────────────────────────────────
def test_recovered_when_key_variance_above_default():
    var, ref, key, oracle = _fixture(5200.0)
    r = run_auto_floor(var, ref, 20, oracle, reduce_kwargs=REDUCE_KWARGS, coverage=1.0)
    assert r.verdict == VERDICT_RECOVERED
    assert r.offset == KOFF and r.key_hex == key.hex()
    assert r.exit_code == 0


def test_floor_too_high_when_key_variance_depressed():
    # key varies every run but its window variance sits BELOW the default floor
    var, ref, key, oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, oracle, reduce_kwargs=REDUCE_KWARGS, coverage=1.0,
                       positive_control=key)
    assert r.verdict == VERDICT_FLOOR_TOO_HIGH
    assert r.offset == KOFF and r.phi_star == pytest.approx(2300.0)
    assert r.neighborhood_variance  # populated for signature derivation


def test_absent_when_oracle_never_accepts():
    var, ref, _key, _oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, lambda c: False, reduce_kwargs=REDUCE_KWARGS,
                       coverage=0.9, filter_recall=0.95)
    assert r.verdict == VERDICT_ABSENT
    assert r.confidence == pytest.approx(0.855)
    assert r.exit_code == 2


def test_absent_unqualified_without_coverage():
    var, ref, _key, _oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, lambda c: False, reduce_kwargs=REDUCE_KWARGS)
    assert r.verdict == VERDICT_ABSENT and r.confidence is None


def test_inconclusive_on_bad_oracle():
    var, ref, _key, _oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, lambda c: True, reduce_kwargs=REDUCE_KWARGS,
                       coverage=1.0)
    assert r.verdict == VERDICT_INCONCLUSIVE and r.inconclusive_reason == "oracle"
    assert r.exit_code == 3


def test_inconclusive_on_low_coverage():
    var, ref, key, oracle = _fixture(2300.0)
    r = run_auto_floor(var, ref, 20, oracle, reduce_kwargs=REDUCE_KWARGS,
                       coverage=0.5, min_coverage=0.8)
    assert r.verdict == VERDICT_INCONCLUSIVE and r.inconclusive_reason == "coverage"


# ── artifacts ────────────────────────────────────────────────────────
def test_write_artifacts(tmp_path):
    var, ref, key, oracle = _fixture(5200.0)
    r = run_auto_floor(var, ref, 20, oracle, reduce_kwargs=REDUCE_KWARGS, coverage=1.0)
    paths = write_auto_floor_artifacts(r, tmp_path)
    assert Path(paths["verdict_json"]).is_file()
    assert Path(paths["report_md"]).is_file()
    import json
    v = json.loads(Path(paths["verdict_json"]).read_text())
    assert v["verdict"] == VERDICT_RECOVERED and v["exit_code"] == 0


# ── Phase B: robustness & credibility (conditional ABSENT, budget, dedup) ──
def _block_fixture(block_len: int = 512, key_variance: float = 2300.0):
    """A single high-entropy region with many stride-8 candidates + planted key."""
    rng = np.random.default_rng(3)
    ref = bytearray(rng.integers(0, 4, SIZE, dtype=np.uint8).tobytes())  # low-entropy bg
    ref[KOFF:KOFF + block_len] = rng.integers(0, 256, block_len, dtype=np.uint8).tobytes()
    key = bytes(ref[KOFF:KOFF + 32])
    var = np.full(SIZE, 50.0, dtype=np.float64)
    var[KOFF:KOFF + block_len] = 4000.0
    var[KOFF:KOFF + 32] = key_variance
    return var, bytes(ref), key


def test_absent_carries_reachability_assumptions():
    var, ref, _key = _block_fixture()
    r = run_auto_floor(var, ref, 20, lambda c: False,
                       reduce_kwargs=REDUCE_KWARGS, coverage=1.0)
    assert r.verdict == VERDICT_ABSENT
    assert r.assumptions and any("secret-shared" in a or "masked" in a
                                 for a in r.assumptions)


def test_budget_exhausted_is_inconclusive_cost_not_absent():
    var, ref, _key = _block_fixture()
    # self-test costs ~10 calls; allow only ~5 sweep calls → cannot exhaust.
    r = run_auto_floor(var, ref, 20, lambda c: False, reduce_kwargs=REDUCE_KWARGS,
                       coverage=1.0, self_test_trials=8, oracle_budget=15)
    assert r.verdict == VERDICT_INCONCLUSIVE and r.inconclusive_reason == "cost"
    assert r.maximal_candidates > r.tried    # set was NOT exhausted


def test_managed_region_no_hit_is_inconclusive_regime():
    var, ref, _key = _block_fixture()
    r = run_auto_floor(var, ref, 20, lambda c: False, reduce_kwargs=REDUCE_KWARGS,
                       coverage=1.0, managed_region=True)
    assert r.verdict == VERDICT_INCONCLUSIVE and r.inconclusive_reason == "regime"


def test_low_alignment_no_hit_is_inconclusive_alignment():
    var, ref, _key = _block_fixture()
    r = run_auto_floor(var, ref, 20, lambda c: False, reduce_kwargs=REDUCE_KWARGS,
                       coverage=1.0, alignment_quality=0.2, min_alignment=0.5)
    assert r.verdict == VERDICT_INCONCLUSIVE and r.inconclusive_reason == "alignment"


def test_dedup_skips_byte_identical_windows():
    # two identical high-entropy blocks → identical candidate windows.
    rng = np.random.default_rng(5)
    ref = bytearray(rng.integers(0, 4, SIZE, dtype=np.uint8).tobytes())
    block = rng.integers(0, 256, 256, dtype=np.uint8).tobytes()
    off_a, off_b = 8 * 1000, 8 * 5000
    ref[off_a:off_a + 256] = block
    ref[off_b:off_b + 256] = block          # exact duplicate
    var = np.full(SIZE, 50.0, dtype=np.float64)
    var[off_a:off_a + 256] = 4000.0
    var[off_b:off_b + 256] = 4000.0
    calls = {"n": 0}

    def counting_oracle(cand: bytes) -> bool:
        calls["n"] += 1
        return False

    r = run_auto_floor(var, bytes(ref), 20, counting_oracle,
                       reduce_kwargs=REDUCE_KWARGS, coverage=1.0, self_test_trials=8)
    assert r.verdict == VERDICT_ABSENT
    # dedup: the sweep tests strictly fewer windows than the maximal set (the
    # second identical block contributes only duplicates).
    assert r.tried < r.maximal_candidates
    self_test_cost = 8 + 2                            # trials + determinism probes
    assert calls["n"] - self_test_cost == r.tried     # no duplicate oracle calls in the sweep


def test_hit_still_recovers_under_gates():
    # a genuine hit is never suppressed by the negative-path gates.
    var, ref, key = _block_fixture(key_variance=5200.0)
    r = run_auto_floor(var, ref, 20, lambda c: c == key, reduce_kwargs=REDUCE_KWARGS,
                       coverage=1.0, managed_region=True, alignment_quality=0.1)
    assert r.verdict in (VERDICT_RECOVERED, VERDICT_FLOOR_TOO_HIGH)
    assert bytes.fromhex(r.key_hex) == key
