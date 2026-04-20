#!/usr/bin/env python3
"""Benchmark: Consensus convergence — how many dumps for reliable detection?

Sweeps N=[2,3,5,7,10,15,20,25,30] dumps and measures detection quality
at each point. Also compares raw flat-byte consensus vs MSL-aligned
consensus under ASLR conditions.

Usage: python benchmark_convergence.py [--num-runs 30]
"""
import argparse
import json
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from generate_realistic_fixtures import (
    generate_dataset, KEY_OFFSET, KEY_LENGTH, DUMP_SIZE,
)
from generate_aslr_fixtures import (
    generate_dataset as gen_aslr, STRUCT_OFFSET_IN_HEAP, STRUCT_SIZE,
)
from core.alignment_filter import alignment_filter
from core.dump_source import open_dump
from engine.consensus import ConsensusVector

# Detection helpers: reuse engine.convergence implementations where available.
# These are the canonical implementations; the local functions in this file
# previously duplicated them for standalone execution.
from engine.convergence import (
    _entropy_candidates,
    _variance_candidates,
    _compute_metrics as _metrics_raw,
)

# Verification: use engine.verification via the decryption_verifier wrapper.
try:
    from engine.verification import (
        AesCbcVerifier, VERIFICATION_PLAINTEXT, VERIFICATION_IV, HAS_CRYPTO,
    )
    _HAS_VERIFIER = True
except ImportError:
    _HAS_VERIFIER = False
    HAS_CRYPTO = False

N_VALUES = [2, 3, 5, 7, 10, 15, 20, 25, 30]


def _metrics(candidates: set, truth: set) -> dict:
    """Thin adapter: engine.convergence returns a DetectionMetrics dataclass;
    the benchmark code expects a plain dict."""
    m = _metrics_raw(candidates, truth)
    return {"tp": m.tp, "fp": m.fp, "precision": m.precision,
            "recall": m.recall, "candidates": m.candidates}


def _try_decrypt(dump_data: bytes, candidates: set, key_hex: str) -> bool:
    """Try AES-256-CBC decryption using engine.verification.AesCbcVerifier."""
    if not _HAS_VERIFIER or not HAS_CRYPTO:
        return False
    verifier = AesCbcVerifier()
    key = bytes.fromhex(key_hex)
    ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
    starts = sorted({(o // 16) * 16 for o in candidates})
    for s in starts:
        if s + 32 > len(dump_data):
            continue
        result = verifier.verify(dump_data[s:s + 32], ct, VERIFICATION_IV,
                                 VERIFICATION_PLAINTEXT)
        if result is True:
            return True
    return False


# ---------------------------------------------------------------------------
# Part 1: Convergence sweep on realistic fixtures
# ---------------------------------------------------------------------------

def run_convergence(tmpdir: Path, num_runs: int, threshold: float, seed: int):
    """Sweep N and show when detection converges."""
    meta = generate_dataset(tmpdir, num_runs=num_runs, seed=seed)
    truth = set(range(KEY_OFFSET, KEY_OFFSET + KEY_LENGTH))
    tool = meta["tools"][0]
    tool_dir = tmpdir / tool
    all_dumps = sorted(tool_dir.glob("*/*.dump"))
    first_data = all_dumps[0].read_bytes()
    key_hex = meta["runs"][0]["key_hex"]

    ent_cands = _entropy_candidates(first_data, threshold)

    print()
    print("=" * 100)
    print(f"  CONVERGENCE SWEEP — {tool} with realistic noise, threshold={threshold}")
    print("=" * 100)
    print(f"\n{'N':>4} │ {'Var Recall':>10} │ {'Var FP':>8} │ "
          f"{'Comb Recall':>11} │ {'Comb FP':>8} │ "
          f"{'Align Recall':>12} │ {'Align FP':>8} │ {'Decrypt':>7}")
    print(f"{'─' * 4}─┼{'─' * 11}─┼{'─' * 9}─┼"
          f"{'─' * 12}─┼{'─' * 9}─┼"
          f"{'─' * 13}─┼{'─' * 9}─┼{'─' * 8}")

    first_var_detect = None
    first_comb_detect = None
    first_align_detect = None
    first_decrypt = None

    for n in N_VALUES:
        if n > len(all_dumps):
            break

        cm = ConsensusVector()
        cm.build(all_dumps[:n])
        var_cands = _variance_candidates(cm)
        combined = ent_cands & var_cands
        aligned = alignment_filter(combined, block_size=32, alignment=16,
                                   density_threshold=0.75)

        var_m = _metrics(var_cands, truth)
        com_m = _metrics(combined, truth)
        ali_m = _metrics(aligned, truth)

        dec = _try_decrypt(first_data, aligned, key_hex)

        # Track first detection
        if first_var_detect is None and var_m["recall"] >= 0.875:
            first_var_detect = n
        if first_comb_detect is None and com_m["recall"] >= 0.875:
            first_comb_detect = n
        if first_align_detect is None and ali_m["recall"] >= 0.875:
            first_align_detect = n
        if first_decrypt is None and dec:
            first_decrypt = n

        dec_str = "YES" if dec else "no"
        print(f"{n:>4} │ {var_m['recall']:>9.1%} │ {var_m['fp']:>8,} │ "
              f"{com_m['recall']:>10.1%} │ {com_m['fp']:>8,} │ "
              f"{ali_m['recall']:>11.1%} │ {ali_m['fp']:>8,} │ {dec_str:>7}")

    print()
    print("First detection (recall >= 87.5%):")
    print(f"  Variance-only:    N = {first_var_detect or 'never'}")
    print(f"  Combined:         N = {first_comb_detect or 'never'}")
    print(f"  Combined+Aligned: N = {first_align_detect or 'never'}")
    print(f"  Decryption verified: N = {first_decrypt or 'never'}")
    print()


# ---------------------------------------------------------------------------
# Part 2: Raw vs MSL under ASLR
# ---------------------------------------------------------------------------

def run_aslr_comparison(tmpdir: Path, num_runs: int, threshold: float, seed: int):
    """Compare raw flat-byte consensus vs MSL region-aligned consensus."""
    aslr_dir = tmpdir / "_aslr"
    aslr_meta = gen_aslr(aslr_dir, num_runs=num_runs, seed=seed)

    # Load ASLR metadata
    meta = json.loads((aslr_dir / "metadata.json").read_text())

    print("=" * 80)
    print("  RAW (.dump) vs MSL (.msl) — ASLR comparison")
    print("=" * 80)

    # --- Raw consensus ---
    raw_dumps = sorted((aslr_dir / "raw").glob("*/*.dump"))
    if len(raw_dumps) >= 2:
        raw_cm = ConsensusVector()
        raw_cm.build(raw_dumps)
        raw_var = _variance_candidates(raw_cm)
        raw_ent = _entropy_candidates(raw_dumps[0].read_bytes(), threshold)
        raw_combined = raw_ent & raw_var
        raw_aligned = alignment_filter(raw_combined)

        # Raw truth: key moves across runs due to ASLR
        first_raw_off = meta["runs"][0]["struct_offset_in_raw"]
        raw_truth = set(range(first_raw_off + 0x10,
                              first_raw_off + 0x10 + 32))
        raw_m = _metrics(raw_aligned, raw_truth)
    else:
        raw_m = {"precision": 0, "recall": 0, "fp": 0, "candidates": 0}

    # --- MSL consensus (normalized) ---
    msl_files = sorted((aslr_dir / "msl").glob("*/*.msl"))
    if len(msl_files) >= 2:
        msl_sources = [open_dump(p) for p in msl_files]
        for s in msl_sources:
            s.open()
        msl_cm = ConsensusVector()
        msl_cm.build_from_sources(msl_sources, normalize=True)
        msl_var = _variance_candidates(msl_cm)
        msl_flat = msl_sources[0].read_all()
        msl_ent = _entropy_candidates(msl_flat, threshold)
        msl_combined = msl_ent & msl_var
        msl_aligned = alignment_filter(msl_combined)

        msl_key_off = STRUCT_OFFSET_IN_HEAP + 0x10
        msl_truth = set(range(msl_key_off, msl_key_off + 32))
        msl_m = _metrics(msl_aligned, msl_truth)
    else:
        msl_m = {"precision": 0, "recall": 0, "fp": 0, "candidates": 0}

    w = 30
    print(f"\n{'Metric':<{w}} | {'Raw (.dump)':>15} | {'MSL (.msl)':>15}")
    print(f"{'-' * w}-+-{'-' * 15}-+-{'-' * 15}")
    print(f"{'Combined+Aligned candidates':<{w}} | "
          f"{raw_m.get('candidates', 0):>15,} | {msl_m.get('candidates', 0):>15,}")
    print(f"{'Precision':<{w}} | "
          f"{raw_m['precision']:>14.2%} | {msl_m['precision']:>14.2%}")
    print(f"{'Recall':<{w}} | "
          f"{raw_m['recall']:>14.1%} | {msl_m['recall']:>14.1%}")
    print(f"{'False positives':<{w}} | "
          f"{raw_m['fp']:>15,} | {msl_m['fp']:>15,}")
    print()
    if raw_m["recall"] < 0.5 and msl_m["recall"] > 0.5:
        print("  >> MSL region alignment REQUIRED for ASLR-resilient detection")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Consensus convergence benchmark")
    parser.add_argument("--num-runs", type=int, default=30)
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    tmpdir = Path(tempfile.mkdtemp())
    try:
        run_convergence(tmpdir, args.num_runs, args.threshold, args.seed)
        run_aslr_comparison(tmpdir, args.num_runs, args.threshold, args.seed)
    finally:
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
