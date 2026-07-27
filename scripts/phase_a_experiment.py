"""Run the Phase-A offline auto-floor experiments (A1 R_c + A2 floor selection).

Zero oracle calls. Consumes an already-computed consensus (per-byte variance +
one reference buffer) and the KNOWN key offset, and writes a markdown + JSON
evidence report.

Usage
-----
Real gocryptfs data (once you have a pipeline consensus artifact directory that
contains ``variance.npy`` + ``reference.bin``):

    python scripts/phase_a_experiment.py \
        --consensus-dir /path/to/artifacts/consensus \
        --key-offset 0x57a220 \
        --out /path/to/phase_a_report

The recovered gocryptfs master key sits at VAS offset 0x57a220 (== 5743136);
the consensus reference buffer must be the VAS-view reference the pipeline
persisted, so the offset lines up.

No data on this machine? Run the synthetic demonstration (builds a
master-equation fixture and shows the harness end-to-end):

    python scripts/phase_a_experiment.py --demo
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import numpy as np

from memdiver.app.reports import render_candidate_report
from memdiver.engine.candidate_stats import load_consensus, run_phase_a
from memdiver.engine.subsample_stability import load_halves


def _parse_offset(text: str) -> int:
    return int(text, 0)


def _run_real(consensus_dir: Path, key_offset: int, key_size: int,
              stride: int, out: Path, halves_dir: Path = None) -> int:
    variance, reference, num_dumps = load_consensus(consensus_dir)
    var_a, var_b, num_a, num_b = load_halves(halves_dir or consensus_dir)
    halves_note = (f" + halves (N_a={num_a}, N_b={num_b})"
                   if var_a is not None else "")
    print(f"[phase-a] consensus: {variance.size} bytes, N={num_dumps or '?'} "
          f"dumps, key at 0x{key_offset:x}{halves_note}", flush=True)
    result = run_phase_a(variance, reference, num_dumps or 20, key_offset,
                         key_size=key_size, stride=stride,
                         var_a=var_a, var_b=var_b, num_a=num_a, num_b=num_b)
    _write(result, out)
    return 0


def _run_demo(out: Path) -> int:
    """Self-contained master-equation fixture (mirrors the unit test)."""
    rng = np.random.default_rng(1234)
    total = 0x8000
    ref = np.full(total, 0x41, dtype=np.uint8)
    var = np.zeros(total, dtype=np.float64)
    key_off, ksize = 0x1000, 32

    def uniform(off, length):
        ref[off:off + length] = rng.integers(0, 256, size=length, dtype=np.uint8)

    uniform(key_off, 256)
    var[key_off:key_off + 256] = 2156.0
    kv = np.full(ksize, 3000.0); kv[:18] = 1500.0
    var[key_off:key_off + ksize] = kv
    for off in (0x1400, 0x1800, 0x1C00):
        uniform(off, 256); var[off:off + 256] = 5400.0
    ref[0x2000:0x2100] = (np.arange(256) % 256).astype(np.uint8)
    var[0x2000:0x2100] = 5000.0
    uniform(0x4000, 0x2000); var[0x4000:0x6000] = 1300.0

    print("[phase-a] DEMO: synthetic master-equation fixture "
          "(diluted key + fresh clutter + structured clutter + heap band)", flush=True)
    result = run_phase_a(var, ref.tobytes(), 8, key_off, key_size=ksize, stride=8)
    _write(result, out)
    return 0


def _write(result, out: Path) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phase_a.json").write_text(json.dumps(result.to_dict(), indent=2))
    report = render_candidate_report(result)
    (out / "phase_a.md").write_text(report)
    print(report, flush=True)
    print(f"[phase-a] wrote {out/'phase_a.md'} and {out/'phase_a.json'}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--consensus-dir", type=Path,
                    help="dir with variance.npy + reference.bin (+ optional meta.json)")
    ap.add_argument("--halves-dir", type=Path, default=None,
                    help="dir with variance_a.npy/variance_b.npy for the experimental "
                         "subsample-stability instrument (defaults to --consensus-dir)")
    ap.add_argument("--key-offset", type=_parse_offset, default=0x57a220)
    ap.add_argument("--key-size", type=int, default=32)
    ap.add_argument("--stride", type=int, default=8)
    ap.add_argument("--out", type=Path,
                    default=REPO_ROOT / "scripts" / "phase_a_report")
    ap.add_argument("--demo", action="store_true",
                    help="run the synthetic demonstration instead of real data")
    args = ap.parse_args()

    if args.demo:
        return _run_demo(args.out)
    if not args.consensus_dir or not args.consensus_dir.exists():
        print("[phase-a] No --consensus-dir given / not found. The real "
              "gocryptfs consensus (variance.npy + reference.bin) is not in the "
              "repo; point --consensus-dir at a pipeline artifact dir, or run "
              "with --demo to exercise the harness on synthetic data.",
              file=sys.stderr, flush=True)
        return 2
    return _run_real(args.consensus_dir, args.key_offset, args.key_size,
                     args.stride, args.out, args.halves_dir)


if __name__ == "__main__":
    raise SystemExit(main())
