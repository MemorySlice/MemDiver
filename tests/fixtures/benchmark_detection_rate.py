#!/usr/bin/env python3
"""Benchmark: Detection rate vs number of runs (no ASLR, fixed offsets).

Uses the simple fixture generator where key is at a fixed offset.
Shows how many runs are needed for reliable consensus detection.

Usage: python benchmark_detection_rate.py
"""
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
from generate_aes_fixtures import (
    generate_dataset, KEY_OFFSET, KEY_LENGTH, DUMP_SIZE,
)
from engine.consensus import ConsensusVector
from core.variance import ByteClass, POINTER_MAX


def main():
    print("=" * 80)
    print("Detection Rate vs Number of Runs (Fixed Offset, No ASLR)")
    print("=" * 80)
    print(f"\nKey: 32-byte AES-256 at offset 0x{KEY_OFFSET:04x}")
    print(f"Threshold for KEY_CANDIDATE: variance > {POINTER_MAX}")
    print()

    hdr = (f"{'Runs':>5} | {'Key':>5} | {'Key Bytes':>10} | {'FP Regions':>10} |"
           f" {'Min Var':>10} | {'Mean Var':>10} | {'Max Var':>10}")
    print(hdr)
    print("-" * len(hdr))

    for num_runs in [2, 3, 5, 7, 10, 12, 15, 20, 25, 30]:
        tmpdir = Path(tempfile.mkdtemp())
        try:
            generate_dataset(tmpdir, num_runs=num_runs, seed=42)
            tool_dir = tmpdir / "AES256" / "aes_key_in_memory" / "lldb"
            dumps = sorted(tool_dir.glob("*/*.dump"))

            cm = ConsensusVector()
            cm.build(dumps)
            volatile = cm.get_volatile_regions(min_length=16)

            import numpy as np
            key_vars = cm.variance[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
            n_kc = sum(1 for c in cm.classifications[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
                       if c == ByteClass.KEY_CANDIDATE)

            key_regions = [r for r in volatile
                           if r.start <= KEY_OFFSET + 2 and r.end >= KEY_OFFSET + KEY_LENGTH - 2]
            found = "YES" if key_regions else "NO"
            fp = len([r for r in volatile if r.end <= KEY_OFFSET or r.start >= KEY_OFFSET + KEY_LENGTH])

            min_v = float(np.min(key_vars))
            mean_v = float(np.mean(key_vars))
            max_v = float(np.max(key_vars))

            print(f"{num_runs:>5} | {found:>5} | {n_kc:>7}/32 |"
                  f" {fp:>10} | {min_v:>10.0f} | {mean_v:>10.0f} | {max_v:>10.0f}")
        finally:
            shutil.rmtree(tmpdir)

    print(f"\nNote: With only {DUMP_SIZE} byte synthetic dumps at fixed offsets,")
    print("0 false positives because all non-key bytes are identical (structural).")
    print("Real dumps would have more noise, requiring more runs for clean detection.")


if __name__ == "__main__":
    main()
