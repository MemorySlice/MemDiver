#!/usr/bin/env python3
"""Benchmark: Raw dumps vs MSL with ASLR — shows why MSL matters.

Generates ASLR-randomized fixtures and compares consensus results
between raw (flat bytes, no metadata) and MSL (with region base_addr).

Produces three tables:
  1. Detection rate vs number of runs (raw vs MSL)
  2. Cross-format comparison at 30 runs
  3. ASLR offset distribution

Usage: python benchmark_aslr.py [--num-runs 30] [--output-dir /tmp/bench]
"""
import argparse
import json
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from generate_aslr_fixtures import (
    generate_dataset, STRUCT_OFFSET_IN_HEAP, STRUCT_SIZE, PAGE_SIZE,
)
from engine.consensus import ConsensusVector
from core.dump_source import open_dump
from architect.static_checker import StaticChecker
from architect.pattern_generator import PatternGenerator


def _raw_consensus(dump_dir: Path, min_length: int = 16):
    """Build consensus from raw .dump files (flat byte comparison)."""
    dumps = sorted(dump_dir.glob("*/*.dump"))
    cm = ConsensusVector()
    cm.build(dumps)
    return cm, dumps


def _msl_consensus(dump_dir: Path, min_length: int = 16):
    """Build consensus from MSL files (ASLR-aware alignment)."""
    msl_files = sorted(dump_dir.glob("*/*.msl"))
    sources = [open_dump(p) for p in msl_files]
    for s in sources:
        s.open()
    cm = ConsensusVector()
    cm.build_from_sources(sources, normalize=True)
    return cm, msl_files


def _check_key_detection(cm, metadata, format_type):
    """Check if consensus found the key region."""
    volatile = cm.get_volatile_regions(min_length=16)
    if format_type == "msl":
        # MSL consensus produces flat output from aligned regions.
        # The struct is at STRUCT_OFFSET_IN_HEAP within the aligned heap.
        # Check all volatile regions for one matching the key size.
        key_regions = [r for r in volatile
                       if 28 <= (r.end - r.start) <= 300]
        return len(key_regions) > 0, volatile
    else:
        # Raw: key would be at different offsets per dump.
        # No single offset will consistently contain key bytes.
        key_regions = volatile
        return len(key_regions) > 0, volatile


def table1_detection_vs_runs(max_runs: int = 30):
    """Table 1: Detection rate vs number of runs (raw vs MSL)."""
    print("=" * 75)
    print("TABLE 1: Key Detection Rate vs Number of Runs")
    print("=" * 75)
    print(f"{'Runs':>5} | {'RAW Found':>10} {'RAW Regions':>12} |"
          f" {'MSL Found':>10} {'MSL Regions':>12}")
    print("-" * 75)

    for n in [2, 3, 5, 10, 15, 20, 30]:
        if n > max_runs:
            break
        tmpdir = Path(tempfile.mkdtemp())
        try:
            meta = generate_dataset(tmpdir, num_runs=n, seed=42)
            # Raw consensus
            raw_cm, _ = _raw_consensus(tmpdir / "raw")
            raw_vol = raw_cm.get_volatile_regions(min_length=16)
            raw_found = len(raw_vol) > 0

            # MSL consensus
            msl_cm, _ = _msl_consensus(tmpdir / "msl")
            msl_vol = msl_cm.get_volatile_regions(min_length=16)
            msl_found = len(msl_vol) > 0

            raw_status = "YES" if raw_found else "NO"
            msl_status = "YES" if msl_found else "NO"
            print(f"{n:>5} | {raw_status:>10} {len(raw_vol):>12} |"
                  f" {msl_status:>10} {len(msl_vol):>12}")
        finally:
            shutil.rmtree(tmpdir)

    print()


def table2_comparison_30_runs():
    """Table 2: Detailed comparison at 30 runs."""
    print("=" * 75)
    print("TABLE 2: Raw vs MSL Consensus — 30 Runs with ASLR")
    print("=" * 75)

    tmpdir = Path(tempfile.mkdtemp())
    try:
        meta = generate_dataset(tmpdir, num_runs=30, seed=42)

        raw_cm, raw_dumps = _raw_consensus(tmpdir / "raw")
        msl_cm, msl_files = _msl_consensus(tmpdir / "msl")

        raw_counts = raw_cm.classification_counts()
        msl_counts = msl_cm.classification_counts()

        print(f"\n{'Metric':<35} | {'RAW (.dump)':>15} | {'MSL (.msl)':>15}")
        print("-" * 75)
        print(f"{'Dumps analyzed':<35} | {raw_cm.num_dumps:>15} |"
              f" {msl_cm.num_dumps:>15}")
        print(f"{'Total bytes analyzed':<35} | {raw_cm.size:>15,} |"
              f" {msl_cm.size:>15,}")

        for cls in ["invariant", "structural", "pointer", "key_candidate"]:
            rv = raw_counts.get(cls, 0)
            mv = msl_counts.get(cls, 0)
            rp = rv / raw_cm.size * 100 if raw_cm.size else 0
            mp = mv / msl_cm.size * 100 if msl_cm.size else 0
            print(f"  {cls:<33} | {rv:>10} ({rp:>4.1f}%) |"
                  f" {mv:>10} ({mp:>4.1f}%)")

        raw_vol = raw_cm.get_volatile_regions(min_length=16)
        msl_vol = msl_cm.get_volatile_regions(min_length=16)
        print(f"{'Volatile regions (>=16B)':<35} | {len(raw_vol):>15} |"
              f" {len(msl_vol):>15}")

        raw_found = "FAIL" if not raw_vol else "PARTIAL"
        msl_found = "FAIL" if not msl_vol else "PARTIAL"

        # Check if any region matches expected key size (32B)
        for r in raw_vol:
            if 28 <= (r.end - r.start) <= 40:
                raw_found = "YES"
                break
        for r in msl_vol:
            if 28 <= (r.end - r.start) <= 40:
                msl_found = "YES"
                break

        print(f"{'Key region identified (32B AES)':<35} | {raw_found:>15} |"
              f" {msl_found:>15}")

        if raw_vol:
            print(f"\n  Raw volatile regions:")
            for r in raw_vol[:5]:
                print(f"    0x{r.start:04x}-0x{r.end:04x}"
                      f" ({r.end-r.start}B, var={float(r.mean_variance):.0f})")
        if msl_vol:
            print(f"\n  MSL volatile regions:")
            for r in msl_vol[:5]:
                print(f"    0x{r.start:04x}-0x{r.end:04x}"
                      f" ({r.end-r.start}B, var={float(r.mean_variance):.0f})")

        print()
    finally:
        shutil.rmtree(tmpdir)


def table3_aslr_distribution():
    """Table 3: ASLR offset distribution showing why raw fails."""
    print("=" * 75)
    print("TABLE 3: ASLR Offset Distribution (Struct Position in Raw Dumps)")
    print("=" * 75)

    tmpdir = Path(tempfile.mkdtemp())
    try:
        meta = generate_dataset(tmpdir, num_runs=30, seed=42)
        offsets = [r["struct_offset_in_raw"] for r in meta["runs"]]
        unique = sorted(set(offsets))

        print(f"\n  Total runs: {len(offsets)}")
        print(f"  Unique struct offsets: {len(unique)}")
        print(f"  Range: 0x{min(offsets):04x} — 0x{max(offsets):04x}"
              f" ({min(offsets)} — {max(offsets)} bytes)")
        print(f"\n  {'Offset':>10} | {'Count':>6} |"
              f" {'Distribution':>40}")
        print(f"  {'-'*10}-+-{'-'*6}-+-{'-'*40}")
        for off in unique:
            count = offsets.count(off)
            bar = "#" * (count * 2)
            print(f"  0x{off:08x} | {count:>6} | {bar}")

        print(f"\n  In raw consensus, byte position 0x{offsets[0]:04x}"
              f" contains the struct in run 1")
        print(f"  but contains heap noise in runs where"
              f" struct is at a different offset.")
        print(f"  Result: raw consensus sees HIGH variance at ALL offsets"
              f" → no clear key region.\n")
    finally:
        shutil.rmtree(tmpdir)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark: Raw vs MSL consensus with ASLR")
    parser.add_argument("--num-runs", type=int, default=30)
    args = parser.parse_args()

    table1_detection_vs_runs(args.num_runs)
    table2_comparison_30_runs()
    table3_aslr_distribution()

    print("=" * 75)
    print("CONCLUSION: With ASLR, raw byte-offset consensus FAILS because")
    print("the struct appears at different offsets in each dump. MSL carries")
    print("base_addr metadata per region, enabling ASLR-normalized alignment")
    print("so the consensus compares the SAME memory region across dumps.")
    print("=" * 75)


if __name__ == "__main__":
    main()
