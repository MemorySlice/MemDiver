"""Build a flat-VAS consensus (variance.npy + reference.bin + meta.json) from N
gocryptfs runs, for the Phase-A experiment / auto-floor validation.

Memory-bounded: folds one ~185 MB VAS slab at a time with a chunked Welford
update into float32 accumulators, shrinking to the min VAS width across runs.
The run_0001 master key lands at flat offset 0x57a220 in this coordinate.

Usage:
    python scripts/build_gocryptfs_consensus.py \
        --dataset ".../mempdumps/dataset_memory_slice/gocryptfs/dataset_gocryptfs" \
        --n 20 --out artifacts/gocryptfs_consensus
Then:
    python scripts/phase_a_experiment.py --consensus-dir artifacts/gocryptfs_consensus \
        --key-offset 0x57a220
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from memdiver.core.dump_source import open_dump

CHUNK = 8_000_000


def _welford_fold(mean, m2, count: int, du8, size: int) -> None:
    """Fold one uint8 dump slab into float32 Welford accumulators, in place.

    ``mean`` and ``m2`` are float32 arrays of length ``size``; ``count`` is the
    running number of dumps folded *including* this one. Chunked in float64 to
    keep the running variance numerically stable while storing float32.
    """
    for c in range(0, size, CHUNK):
        e = min(c + CHUNK, size)
        x = du8[c:e].astype(np.float64)
        m = mean[c:e].astype(np.float64)
        delta = x - m
        m += delta / count
        m2f = m2[c:e].astype(np.float64) + delta * (x - m)
        mean[c:e] = m.astype(np.float32)
        m2[c:e] = m2f.astype(np.float32)


def build(dataset: Path, n: int, out: Path, emit_halves: bool = False) -> None:
    paths = sorted(glob.glob(str(dataset / "run_*" / "memslicer.msl")))[:n]
    if len(paths) < n:
        raise SystemExit(f"only {len(paths)} memslicer.msl under {dataset}")
    out.mkdir(parents=True, exist_ok=True)

    mean = m2 = None
    # Complementary-pairs halves (even/odd run index) for subsample-stability.
    mean_a = m2_a = mean_b = m2_b = None
    ref = b""
    size = None
    count = count_a = count_b = 0
    t0 = time.time()
    for i, p in enumerate(paths):
        with open_dump(p) as s:
            try:
                data = s.read_all(view="vas")
            except TypeError:
                data = s.read_all()
        du8 = np.frombuffer(data, dtype=np.uint8)
        length = du8.size
        if size is None:
            size = length
            mean = np.zeros(size, dtype=np.float32)
            m2 = np.zeros(size, dtype=np.float32)
            ref = bytes(data[:size])
            if emit_halves:
                mean_a = np.zeros(size, dtype=np.float32)
                m2_a = np.zeros(size, dtype=np.float32)
                mean_b = np.zeros(size, dtype=np.float32)
                m2_b = np.zeros(size, dtype=np.float32)
        if length < size:                       # shrink to running-min width
            size = length
            mean = mean[:size].copy(); m2 = m2[:size].copy(); ref = ref[:size]
            if emit_halves:
                mean_a = mean_a[:size].copy(); m2_a = m2_a[:size].copy()
                mean_b = mean_b[:size].copy(); m2_b = m2_b[:size].copy()
        count += 1
        _welford_fold(mean, m2, count, du8, size)
        if emit_halves:
            if i % 2 == 0:                       # deterministic complementary split
                count_a += 1
                _welford_fold(mean_a, m2_a, count_a, du8, size)
            else:
                count_b += 1
                _welford_fold(mean_b, m2_b, count_b, du8, size)
        del data, du8
        print(f"folded {i + 1}/{n}  size={size}  t={time.time() - t0:.1f}s", flush=True)

    variance = (m2.astype(np.float64) / count).astype(np.float32)
    np.save(out / "variance.npy", variance)
    (out / "reference.bin").write_bytes(ref)
    meta = {"num_dumps": count}
    if emit_halves:
        variance_a = (m2_a.astype(np.float64) / count_a).astype(np.float32)
        variance_b = (m2_b.astype(np.float64) / count_b).astype(np.float32)
        np.save(out / "variance_a.npy", variance_a)
        np.save(out / "variance_b.npy", variance_b)
        meta["num_dumps_a"] = count_a
        meta["num_dumps_b"] = count_b
    (out / "meta.json").write_text(json.dumps(meta))
    print(f"consensus: size={size} N={count} wall={time.time() - t0:.1f}s → {out}",
          flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True,
                    help="dir containing run_*/memslicer.msl")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--emit-halves", action="store_true",
                    help="also write variance_a.npy/variance_b.npy over complementary "
                         "even/odd run halves (for subsample-stability analysis)")
    args = ap.parse_args()
    build(args.dataset, args.n, args.out, emit_halves=args.emit_halves)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
