#!/usr/bin/env python3
"""Master experiment: AES-256 key detection method comparison.

Compares four detection approaches on realistic memory dumps:
1. Entropy-only: Shannon entropy sliding window (single dump)
2. Variance-only: Consensus matrix across N dumps
3. Combined: Intersection of entropy AND variance candidates
4. Combined+Aligned: Combined filtered to 16-byte aligned, dense 32-byte blocks

Produces a formatted table with precision, recall, false positives,
decryption verification, and improvement metrics.

Usage: python benchmark_experiment.py [--num-runs 30] [--threshold 4.5]

Note on thresholds: For a 32-byte sliding window, the theoretical max
entropy is ~5.0 bits (log2(32) when all bytes unique). Real AES keys
achieve ~4.5-5.0. A threshold of 4.5 is appropriate for 32-byte windows.
The classic 7.0+ threshold applies to 256+ byte windows.
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
    VERIFICATION_IV, VERIFICATION_PLAINTEXT,
)
from core.alignment_filter import alignment_filter
from engine.consensus import ConsensusVector

# Detection helpers: reuse engine.convergence implementations.
# See engine/convergence.py for the canonical convergence sweep logic.
from engine.convergence import (
    _entropy_candidates,
    _variance_candidates,
)

# Verification: use engine.verification (the canonical implementation).
try:
    from engine.verification import (
        AesCbcVerifier, VERIFICATION_PLAINTEXT as VP, VERIFICATION_IV as VI,
        extract_and_verify, HAS_CRYPTO,
    )
    _HAS_VERIFIER = True
except ImportError:
    _HAS_VERIFIER = False
    HAS_CRYPTO = False


def _ground_truth() -> set:
    """Return set of byte offsets that are actual key bytes."""
    return set(range(KEY_OFFSET, KEY_OFFSET + KEY_LENGTH))


def _compute_metrics(candidates: set, truth: set) -> dict:
    """Compute precision, recall, F1, false positives."""
    tp = len(candidates & truth)
    fp = len(candidates - truth)
    fn = len(truth - candidates)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / len(truth) if truth else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "candidates": len(candidates),
    }


def _get_aligned_block_starts(candidates: set, alignment: int = 16,
                              block_size: int = 32) -> list:
    """Get sorted list of aligned block start offsets from filtered candidates."""
    if not candidates:
        return []
    starts = set()
    for o in candidates:
        starts.add((o // alignment) * alignment)
    return sorted(starts)


# ---------------------------------------------------------------------------
# Decryption verification
# ---------------------------------------------------------------------------

def _try_decryption(dump_data: bytes, aligned_cands: set,
                    key_hex: str) -> str:
    """Try decryption verification on aligned candidate blocks.

    Uses engine.verification.AesCbcVerifier for the actual crypto check.
    """
    if not _HAS_VERIFIER or not HAS_CRYPTO:
        return "N/A (no crypto)"

    verifier = AesCbcVerifier()
    key = bytes.fromhex(key_hex)
    ciphertext = verifier.create_ciphertext(key, VP, VI)

    block_starts = _get_aligned_block_starts(aligned_cands)
    for start in block_starts:
        if start + KEY_LENGTH > len(dump_data):
            continue
        candidate = dump_data[start:start + KEY_LENGTH]
        if verifier.verify(candidate, ciphertext, VI, VP) is True:
            return "YES"
    return "NO"


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------

def _print_table(results: dict, num_runs: int, threshold: float):
    """Print the formatted comparison table per tool."""
    cw = [17, 14, 15, 10, 17, 22]  # column widths

    print()
    print("=" * 101)
    print(f"  AES-256 KEY DETECTION -- {num_runs} runs, "
          f"entropy threshold={threshold}")
    print("=" * 101)

    for tool, r in results.items():
        ent = r["entropy"]
        var = r["variance"]
        com = r["combined"]
        ali = r["aligned"]
        dec = r["decryption"]

        # Improvement: aligned vs entropy
        if ent["fp"] > 0 and ali["fp"] >= 0:
            fp_reduction = (1 - ali["fp"] / ent["fp"]) * 100
        else:
            fp_reduction = 0.0

        if ent["precision"] > 0:
            prec_improvement = ali["precision"] / ent["precision"]
        else:
            prec_improvement = float("inf")

        recall_delta = (ali["recall"] - ent["recall"]) * 100

        sep = (f"+-{'-' * cw[0]}-+-{'-' * cw[1]}-+-{'-' * cw[2]}-+"
               f"-{'-' * cw[3]}-+-{'-' * cw[4]}-+-{'-' * cw[5]}-+")

        print(f"\n+-{'-' * cw[0]}-+-{'-' * cw[1]}-+-{'-' * cw[2]}-+"
              f"-{'-' * cw[3]}-+-{'-' * cw[4]}-+-{'-' * cw[5]}-+")
        print(f"| {'Metric':^{cw[0]}} | {'Entropy-only':^{cw[1]}} |"
              f" {'Variance-only':^{cw[2]}} | {'Combined':^{cw[3]}} |"
              f" {'Comb+Aligned':^{cw[4]}} |"
              f" {'Improvement':^{cw[5]}} |")
        print(sep)
        print(f"| {tool:^{cw[0]}} | {'':^{cw[1]}} | {'':^{cw[2]}} |"
              f" {'':^{cw[3]}} | {'':^{cw[4]}} | {'':^{cw[5]}} |")
        print(sep)
        print(f"| {'Precision':^{cw[0]}} |"
              f" {ent['precision']:>{cw[1]-3}.2%}   |"
              f" {var['precision']:>{cw[2]-3}.2%}   |"
              f" {com['precision']:>{cw[3]-3}.2%}   |"
              f" {ali['precision']:>{cw[4]-3}.2%}   |"
              f" {prec_improvement:>5.0f}x over entropy  |")
        print(sep)
        print(f"| {'False positives':^{cw[0]}} |"
              f" {ent['fp']:>{cw[1]-3},}   |"
              f" {var['fp']:>{cw[2]-3},}   |"
              f" {com['fp']:>{cw[3]-3},}   |"
              f" {ali['fp']:>{cw[4]-3},}   |"
              f" {fp_reduction:>5.1f}% reduction    |")
        print(sep)
        print(f"| {'Recall':^{cw[0]}} |"
              f" {ent['recall']:>{cw[1]-3}.1%}   |"
              f" {var['recall']:>{cw[2]-3}.1%}   |"
              f" {com['recall']:>{cw[3]-3}.1%}   |"
              f" {ali['recall']:>{cw[4]-3}.1%}   |"
              f" {recall_delta:>+5.1f}pp              |")
        print(sep)
        print(f"| {'Decryption':^{cw[0]}} |"
              f" {'N/A':^{cw[1]}} |"
              f" {'N/A':^{cw[2]}} |"
              f" {'N/A':^{cw[3]}} |"
              f" {dec:^{cw[4]}} |"
              f" {'Key verified' if dec == 'YES' else '':^{cw[5]}}  |")
        print(f"+-{'-' * cw[0]}-+-{'-' * cw[1]}-+-{'-' * cw[2]}-+"
              f"-{'-' * cw[3]}-+-{'-' * cw[4]}-+-{'-' * cw[5]}-+")


def _print_summary(results: dict):
    """Print cross-tool summary."""
    print(f"\n{'=' * 85}")
    print("CROSS-TOOL SUMMARY")
    print(f"{'=' * 85}")
    print(f"\n{'Tool':<12} | {'Ent FP':>8} | {'Var FP':>8} |"
          f" {'Comb FP':>8} | {'Align FP':>8} | {'Reduction':>10} | {'Decrypt':>7}")
    print(f"{'-' * 12}-+-{'-' * 8}-+-{'-' * 8}-+-"
          f"{'-' * 8}-+-{'-' * 8}-+-{'-' * 10}-+-{'-' * 7}")
    for tool, r in results.items():
        ent_fp = r["entropy"]["fp"]
        ali_fp = r["aligned"]["fp"]
        reduction = (1 - ali_fp / ent_fp) * 100 if ent_fp > 0 else 0
        print(f"{tool:<12} | {ent_fp:>8,} | {r['variance']['fp']:>8,} |"
              f" {r['combined']['fp']:>8,} | {ali_fp:>8,} |"
              f" {reduction:>9.1f}% | {r['decryption']:>7}")
    print()


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

def run_experiment(num_runs: int = 30, entropy_threshold: float = 4.5,
                   seed: int = 42):
    """Run the full experiment."""
    tmpdir = Path(tempfile.mkdtemp())
    try:
        meta = generate_dataset(tmpdir, num_runs=num_runs, seed=seed)
        truth = _ground_truth()
        tools = meta["tools"]

        all_results = {}
        for tool in tools:
            tool_dir = tmpdir / tool
            dumps = sorted(tool_dir.glob("*/*.dump"))

            # Read first dump for entropy + decryption
            first_dump = dumps[0].read_bytes()

            # Extract actual key from this dump for decryption verification
            actual_key_hex = first_dump[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH].hex()

            # 1. Entropy-only (single dump)
            ent_cands = _entropy_candidates(first_dump, entropy_threshold)

            # 2. Variance-only (consensus across all dumps)
            cm = ConsensusVector()
            cm.build(dumps)
            var_cands = _variance_candidates(cm)

            # 3. Combined: intersection
            combined = ent_cands & var_cands

            # 4. Combined + Aligned: apply alignment filter
            aligned = alignment_filter(combined, block_size=32, alignment=16,
                                       density_threshold=0.75)

            # Metrics
            ent_m = _compute_metrics(ent_cands, truth)
            var_m = _compute_metrics(var_cands, truth)
            com_m = _compute_metrics(combined, truth)
            ali_m = _compute_metrics(aligned, truth)

            # Decryption verification (extract key from dump directly)
            dec = _try_decryption(first_dump, aligned, actual_key_hex)

            all_results[tool] = {
                "entropy": ent_m, "variance": var_m,
                "combined": com_m, "aligned": ali_m,
                "decryption": dec,
            }

        _print_table(all_results, num_runs, entropy_threshold)
        _print_summary(all_results)

        # Also output JSON for downstream processing
        json_path = tmpdir / "experiment_results.json"
        json_path.write_text(json.dumps(all_results, indent=2, default=str))
        print(f"JSON results: {json_path}")

        return all_results

    finally:
        shutil.rmtree(tmpdir)


def main():
    parser = argparse.ArgumentParser(
        description="AES-256 key detection experiment")
    parser.add_argument("--num-runs", type=int, default=30)
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    run_experiment(args.num_runs, args.threshold, args.seed)


if __name__ == "__main__":
    main()
