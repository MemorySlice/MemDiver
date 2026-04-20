#!/usr/bin/env python3
"""Benchmark: Entropy-only vs Variance-only vs Combined vs Combined+Aligned detection.

Compares four approaches for finding AES-256 keys in memory dumps:
1. Entropy-only: Shannon entropy sliding window (single dump)
2. Variance-only: Consensus matrix across N dumps
3. Combined: Intersection of entropy + variance candidates
4. Combined+Aligned: Combined candidates filtered by alignment constraints

Produces tables with precision, recall, false positives, and improvement.

Usage: python benchmark_methods.py [--num-runs 30] [--threshold 7.0]
"""
import argparse
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from generate_realistic_fixtures import (
    generate_dataset, KEY_OFFSET, KEY_LENGTH, DUMP_SIZE,
)
from core.entropy import compute_entropy_profile, find_high_entropy_regions
from engine.consensus import ConsensusVector
from engine.convergence import _entropy_candidates, _variance_candidates
from core.variance import ByteClass
from core.alignment_filter import alignment_filter
import numpy as np


def _ground_truth() -> set:
    """Return set of byte offsets that are actual key bytes."""
    return set(range(KEY_OFFSET, KEY_OFFSET + KEY_LENGTH))


def _compute_metrics(candidates: set, truth: set, total_bytes: int) -> dict:
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


def run_benchmark(num_runs: int = 30, entropy_threshold: float = 4.5,
                  seed: int = 42):
    """Run the full benchmark and print results."""
    tmpdir = Path(tempfile.mkdtemp())
    try:
        meta = generate_dataset(tmpdir, num_runs=num_runs, seed=seed)
        truth = _ground_truth()
        tools = meta["tools"]

        all_results = {}
        for tool in tools:
            tool_dir = tmpdir / tool
            dumps = sorted(tool_dir.glob("*/*.dump"))

            # --- Entropy-only (use first dump as representative) ---
            first_dump = dumps[0].read_bytes()
            ent_cands = _entropy_candidates(first_dump, entropy_threshold)

            # --- Variance-only (consensus across all dumps) ---
            cm = ConsensusVector()
            cm.build(dumps)
            var_cands = _variance_candidates(cm)

            # --- Combined: intersection ---
            combined = ent_cands & var_cands

            # --- Combined + Aligned: apply alignment filter ---
            aligned = alignment_filter(combined, block_size=32, alignment=16,
                                       density_threshold=0.75)

            ent_m = _compute_metrics(ent_cands, truth, DUMP_SIZE)
            var_m = _compute_metrics(var_cands, truth, DUMP_SIZE)
            com_m = _compute_metrics(combined, truth, DUMP_SIZE)
            ali_m = _compute_metrics(aligned, truth, DUMP_SIZE)

            all_results[tool] = {
                "entropy": ent_m, "variance": var_m, "combined": com_m,
                "aligned": ali_m,
            }

        # --- Print results ---
        _print_comparison_table(all_results, num_runs, entropy_threshold)
        _print_raw_vs_msl_table(tmpdir, tools[0], num_runs,
                                entropy_threshold, truth)
        _print_detection_summary(all_results)

    finally:
        shutil.rmtree(tmpdir)


def _print_comparison_table(results: dict, num_runs: int, threshold: float):
    """Print the main comparison table per tool."""
    w = 17  # column width

    print()
    print("=" * 104)
    print(f"ENTROPY vs VARIANCE vs COMBINED vs ALIGNED — {num_runs} runs,"
          f" entropy threshold={threshold}")
    print("=" * 104)

    for tool, r in results.items():
        ent, var, com = r["entropy"], r["variance"], r["combined"]
        ali = r["aligned"]

        # Improvement calculation
        if ent["fp"] > 0 and com["fp"] > 0:
            fp_reduction = (1 - com["fp"] / ent["fp"]) * 100
        elif ent["fp"] > 0:
            fp_reduction = 100.0
        else:
            fp_reduction = 0.0

        if ent["fp"] > 0 and ali["fp"] > 0:
            ali_fp_reduction = (1 - ali["fp"] / ent["fp"]) * 100
        elif ent["fp"] > 0:
            ali_fp_reduction = 100.0
        else:
            ali_fp_reduction = 0.0

        if ent["precision"] > 0:
            prec_improvement = com["precision"] / ent["precision"]
        else:
            prec_improvement = float("inf")

        recall_delta = (com["recall"] - ent["recall"]) * 100

        print(f"\n┌{'─' * w}┬{'─' * 14}┬{'─' * 15}┬{'─' * 10}┬{'─' * 10}┬{'─' * 22}┐")
        print(f"│{'Metric':^{w}}│{'Entropy-only':^14}│"
              f"{'Variance-only':^15}│{'Combined':^10}│"
              f"{'Aligned':^10}│"
              f"{'Improvement':^22}│")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{tool:^{w}}│{'':^14}│{'':^15}│{'':^10}│{'':^10}│{'':^22}│")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'Precision':^{w}}│"
              f"{ent['precision']:>11.2%}   │"
              f"{var['precision']:>12.2%}   │"
              f"{com['precision']:>7.2%}   │"
              f"{ali['precision']:>7.2%}   │"
              f" {prec_improvement:>5.0f}x over entropy  │")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'False positives':^{w}}│"
              f"{ent['fp']:>11,}   │"
              f"{var['fp']:>12,}   │"
              f"{com['fp']:>7,}   │"
              f"{ali['fp']:>7,}   │"
              f" {ali_fp_reduction:>5.1f}% reduction    │")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'Recall':^{w}}│"
              f"{ent['recall']:>11.1%}   │"
              f"{var['recall']:>12.1%}   │"
              f"{com['recall']:>7.1%}   │"
              f"{ali['recall']:>7.1%}   │"
              f" {recall_delta:>+5.1f}pp              │")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'F1 Score':^{w}}│"
              f"{ent['f1']:>11.4f}   │"
              f"{var['f1']:>12.4f}   │"
              f"{com['f1']:>7.4f}   │"
              f"{ali['f1']:>7.4f}   │"
              f"{'':^22}│")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'Candidates':^{w}}│"
              f"{ent['candidates']:>11,}   │"
              f"{var['candidates']:>12,}   │"
              f"{com['candidates']:>7,}   │"
              f"{ali['candidates']:>7,}   │"
              f"{'':^22}│")
        print(f"├{'─' * w}┼{'─' * 14}┼{'─' * 15}┼{'─' * 10}┼{'─' * 10}┼{'─' * 22}┤")
        print(f"│{'True positives':^{w}}│"
              f"{ent['tp']:>11}/32  │"
              f"{var['tp']:>12}/32  │"
              f"{com['tp']:>7}/32  │"
              f"{ali['tp']:>7}/32  │"
              f"{'':^22}│")
        print(f"└{'─' * w}┴{'─' * 14}┴{'─' * 15}┴{'─' * 10}┴{'─' * 10}┴{'─' * 22}┘")


def _print_raw_vs_msl_table(tmpdir: Path, tool: str, num_runs: int,
                            threshold: float, truth: set):
    """Compare raw flat consensus vs MSL-aligned consensus."""
    from core.dump_source import open_dump
    from tests.fixtures.generate_aslr_fixtures import (
        generate_dataset as gen_aslr, STRUCT_OFFSET_IN_HEAP,
    )

    print(f"\n{'=' * 90}")
    print(f"RAW DUMP vs MSL FORMAT — Combined Method (entropy + variance)")
    print(f"{'=' * 90}")

    # Generate ASLR fixtures
    aslr_dir = tmpdir / "_aslr"
    gen_aslr(aslr_dir, num_runs=num_runs, seed=42)

    # Raw consensus
    raw_dumps = sorted((aslr_dir / "raw").glob("*/*.dump"))
    raw_cm = ConsensusVector()
    raw_cm.build(raw_dumps)
    raw_var = _variance_candidates(raw_cm)
    raw_ent = _entropy_candidates(raw_dumps[0].read_bytes(), threshold)
    raw_combined = raw_ent & raw_var

    # ASLR truth: key is at STRUCT_OFFSET_IN_HEAP=0x100 + 0x10 (struct header)
    # within the heap region, but raw offset varies per run due to ASLR.
    # For raw ASLR: compute truth as union of all runs' key offsets so that
    # if the consensus finds the key at ANY run's offset, it counts as TP.
    import json
    aslr_meta = json.loads((aslr_dir / "metadata.json").read_text())
    all_raw_truth: set = set()
    for run_meta in aslr_meta["runs"]:
        off = run_meta["struct_offset_in_raw"]
        all_raw_truth.update(range(off + 0x10, off + 0x10 + 32))

    raw_m = _compute_metrics(raw_combined, all_raw_truth, raw_cm.size)

    # MSL consensus
    msl_files = sorted((aslr_dir / "msl").glob("*/*.msl"))
    msl_sources = [open_dump(p) for p in msl_files]
    for s in msl_sources:
        s.open()
    msl_cm = ConsensusVector()
    msl_cm.build_from_sources(msl_sources, normalize=True)
    msl_var = _variance_candidates(msl_cm)
    # For MSL entropy: read the aligned flat bytes
    msl_flat = b""
    for s in msl_sources[:1]:
        msl_flat = s.read_all()
    msl_ent = _entropy_candidates(msl_flat, threshold)
    msl_combined = msl_ent & msl_var

    # MSL truth: in aligned view, heap is at consistent offset
    # The key is at STRUCT_OFFSET_IN_HEAP (0x100) + 0x10 in the heap
    msl_key_off = STRUCT_OFFSET_IN_HEAP + 0x10
    msl_truth = set(range(msl_key_off, msl_key_off + 32))
    msl_m = _compute_metrics(msl_combined, msl_truth, msl_cm.size)

    w = 30
    print(f"\n{'Metric':<{w}} | {'Raw (.dump)':>15} | {'MSL (.msl)':>15}")
    print(f"{'-' * w}-+-{'-' * 15}-+-{'-' * 15}")
    print(f"{'Variance candidates':<{w}} | {len(raw_var):>15,} |"
          f" {len(msl_var):>15,}")
    print(f"{'Entropy candidates':<{w}} | {len(raw_ent):>15,} |"
          f" {len(msl_ent):>15,}")
    print(f"{'Combined candidates':<{w}} | {len(raw_combined):>15,} |"
          f" {len(msl_combined):>15,}")
    print(f"{'Precision (combined)':<{w}} | {raw_m['precision']:>14.2%} |"
          f" {msl_m['precision']:>14.2%}")
    print(f"{'Recall (combined)':<{w}} | {raw_m['recall']:>14.1%} |"
          f" {msl_m['recall']:>14.1%}")
    print(f"{'False positives':<{w}} | {raw_m['fp']:>15,} |"
          f" {msl_m['fp']:>15,}")
    print(f"{'True positives':<{w}} | {raw_m['tp']:>12}/32 |"
          f" {msl_m['tp']:>12}/32")
    print()


def _print_detection_summary(results: dict):
    """Print a compact cross-tool summary."""
    print(f"\n{'=' * 82}")
    print("CROSS-TOOL SUMMARY")
    print(f"{'=' * 82}")
    print(f"\n{'Tool':<12} | {'Ent FP':>8} | {'Var FP':>8} |"
          f" {'Comb FP':>8} | {'Align FP':>8} | {'Reduction':>10} | {'Recall':>7}")
    print(f"{'-' * 12}-+-{'-' * 8}-+-{'-' * 8}-+-"
          f"{'-' * 8}-+-{'-' * 8}-+-{'-' * 10}-+-{'-' * 7}")
    for tool, r in results.items():
        ent_fp = r["entropy"]["fp"]
        var_fp = r["variance"]["fp"]
        com_fp = r["combined"]["fp"]
        ali_fp = r["aligned"]["fp"]
        reduction = (1 - ali_fp / ent_fp) * 100 if ent_fp > 0 else 0
        recall = r["aligned"]["recall"]
        print(f"{tool:<12} | {ent_fp:>8,} | {var_fp:>8,} |"
              f" {com_fp:>8,} | {ali_fp:>8,} | {reduction:>9.1f}% | {recall:>6.1%}")

    print(f"\nKey: Ent FP = entropy-only false positives,")
    print(f"     Var FP = variance-only false positives,")
    print(f"     Comb FP = combined (intersection) false positives,")
    print(f"     Align FP = combined + alignment filter false positives")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark: entropy vs variance vs combined detection")
    parser.add_argument("--num-runs", type=int, default=30,
                        help="Number of dumps per tool (default: 30)")
    parser.add_argument("--threshold", type=float, default=4.5,
                        help="Entropy threshold (default: 4.5)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    run_benchmark(args.num_runs, args.threshold, args.seed)


if __name__ == "__main__":
    main()
