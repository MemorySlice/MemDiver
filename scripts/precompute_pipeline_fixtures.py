#!/usr/bin/env python3
"""Precompute pipeline fixtures for README shots 09 & 10.

Runs `memdiver n-sweep` against the gocryptfs reference dataset and
transforms the resulting `report.json` into Playwright-friendly fixture
JSONs that the `readme-screenshots.spec.ts` shots 09 and 10 inject into
the pipeline store via `window.__usePipelineStore.setState(...)`.

Outputs three files under `tests/e2e/fixtures/pipeline/`:

- `nsweep_events.json`  -- a list of synthetic `TaskProgressEvent`s of
  type `stage_start` / `stage_end` / `nsweep_point` / `done` that can be
  fed through the reducer to rebuild the full run state.
- `run_record.json`     -- a cut-down `TaskRecord` approximation for the
  getPipelineRun() fetch (not strictly required — the injection path
  bypasses the backend).
- `summary.json`        -- headline + timing info for human inspection.

Re-run by hand after dataset changes. Not part of CI: the compute is
multi-minute on a real dataset and the output is committed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS_DIR = (
    "/Users/danielbaier/research/projects/github/issues/2024 fritap issues/"
    "2026_success/mempdumps/dataset_memory_slice/gocryptfs/dataset_gocryptfs"
)
DEFAULT_OUTPUT_DIR = REPO_ROOT / "tests/e2e/fixtures/pipeline"


def run_nsweep_cli(
    *,
    runs_dir: str,
    oracle: str,
    oracle_config: str,
    n_values: str,
    output_dir: Path,
    first_hit: bool,
    dump_glob: str = "*.msl",
) -> Path:
    """Invoke the memdiver CLI and return the path to report.json."""
    nsweep_out = output_dir / "nsweep_gocryptfs"
    nsweep_out.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(REPO_ROOT / "cli.py"),
        "n-sweep",
        "--runs-dir", runs_dir,
        "--dump-glob", dump_glob,
        "--n-values", n_values,
        "--oracle", oracle,
        "--oracle-config", oracle_config,
        "--output-dir", str(nsweep_out),
        "-v",
    ]
    if first_hit:
        cmd.append("--first-hit")

    print(f"[precompute] running: {' '.join(cmd)}")
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    elapsed = time.monotonic() - start
    report = nsweep_out / "report.json"

    # Accept the common case where the CLI exits non-zero only because
    # the optional Plotly HTML report step failed (Plotly Python isn't
    # installed) — report.json is written BEFORE that step, so we keep
    # going if it exists. Any other failure still aborts.
    if not report.exists():
        raise FileNotFoundError(
            f"n-sweep did not produce {report} (rc={proc.returncode}); "
            f"compute itself failed."
        )
    print(
        f"[precompute] n-sweep finished in {elapsed:.1f}s "
        f"(rc={proc.returncode}; report.json OK)"
    )
    return report


def build_events(report: dict, task_id: str) -> list[dict]:
    """Transform an `NSweepResult.to_dict()` blob into synthetic
    TaskProgressEvent entries the pipeline-store reducer consumes.
    """
    events: list[dict] = []
    seq = 0
    # Mirror the sequence a live run would emit: one pair of
    # stage_start/stage_end around the consensus + reduce + brute_force
    # umbrella stage, then one nsweep_point per N.
    stages = ["consensus", "reduce", "brute_force"]
    ts0 = time.time() - 60  # synthetic: "one minute ago"
    for stage in stages:
        events.append({
            "task_id": task_id,
            "type": "stage_start",
            "stage": stage,
            "seq": (seq := seq + 1),
            "ts": ts0 + len(events),
            "msg": f"running {stage}",
        })
        events.append({
            "task_id": task_id,
            "type": "stage_end",
            "stage": stage,
            "seq": (seq := seq + 1),
            "ts": ts0 + len(events),
            "pct": 1.0,
            "msg": f"{stage} complete",
        })

    for point in report.get("points", []):
        events.append({
            "task_id": task_id,
            "type": "nsweep_point",
            "seq": (seq := seq + 1),
            "ts": ts0 + len(events),
            "extra": {
                "n": point["n"],
                "stages": point.get("stages", {}),
                "candidates_tried": point.get("candidates_tried", 0),
                "hits": point.get("hits", 0),
                "hit_offset": point.get("hit_offset"),
                "timing_ms": point.get("timing_ms", {}),
            },
        })

    # Terminal event
    events.append({
        "task_id": task_id,
        "type": "done",
        "seq": (seq := seq + 1),
        "ts": time.time(),
    })
    return events


def build_run_record(report: dict, task_id: str) -> dict:
    """A minimal TaskRecord. The Playwright test doesn't currently hit
    the backend for this id; kept so the JSON is self-describing.
    """
    return {
        "task_id": task_id,
        "kind": "pipeline",
        "status": "succeeded",
        "params": {"oracle": "gocryptfs", "n_values": [p["n"] for p in report.get("points", [])]},
        "stages": [
            {
                "name": name,
                "status": "succeeded",
                "pct": 1.0,
                "msg": f"{name} complete",
                "started_at": time.time() - 60,
                "ended_at": time.time() - 30,
            }
            for name in ("consensus", "reduce", "brute_force")
        ],
        "artifacts": [
            {
                "name": "nsweep-report.json",
                "relpath": "nsweep/report.json",
                "media_type": "application/json",
            },
        ],
        "created_at": time.time() - 70,
        "started_at": time.time() - 60,
        "ended_at": time.time() - 10,
        "error": None,
        "schema_version": 1,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR)
    ap.add_argument(
        "--oracle",
        default=str(REPO_ROOT / "docs/oracle/examples/gocryptfs.py"),
    )
    ap.add_argument(
        "--oracle-config",
        default=str(REPO_ROOT / "docs/oracle/examples/gocryptfs.toml"),
    )
    ap.add_argument("--n-values", default="1,3,5,10,15,20")
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Playwright fixture destination (default: tests/e2e/fixtures/pipeline).",
    )
    ap.add_argument(
        "--first-hit",
        action="store_true",
        default=True,
        help="Stop the n-sweep after the oracle's first successful decrypt (default on).",
    )
    ap.add_argument(
        "--task-id",
        default="fixture-gocryptfs",
    )
    ap.add_argument(
        "--skip-cli",
        action="store_true",
        help=(
            "Skip the n-sweep CLI invocation and reuse the existing "
            "nsweep_gocryptfs/report.json — useful after a transform tweak."
        ),
    )
    args = ap.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.skip_cli:
        report_path = args.output_dir / "nsweep_gocryptfs" / "report.json"
        if not report_path.exists():
            raise FileNotFoundError(
                f"--skip-cli requires an existing {report_path}; run once without it first."
            )
        print(f"[precompute] reusing {report_path}")
    else:
        report_path = run_nsweep_cli(
            runs_dir=args.runs_dir,
            oracle=args.oracle,
            oracle_config=args.oracle_config,
            n_values=args.n_values,
            output_dir=args.output_dir,
            first_hit=args.first_hit,
        )
    report = json.loads(report_path.read_text())

    events = build_events(report, args.task_id)
    run_record = build_run_record(report, args.task_id)

    (args.output_dir / "nsweep_events.json").write_text(json.dumps(events, indent=2))
    (args.output_dir / "run_record.json").write_text(json.dumps(run_record, indent=2))
    (args.output_dir / "summary.json").write_text(json.dumps({
        "headline": report.get("headline"),
        "first_hit_n": report.get("first_hit_n"),
        "first_hit_offset_hex": (
            f"0x{report['first_hit_offset']:x}"
            if report.get("first_hit_offset") is not None
            else None
        ),
        "total_dumps": report.get("total_dumps"),
        "n_values": [p["n"] for p in report.get("points", [])],
    }, indent=2))

    print(f"[precompute] wrote fixtures to {args.output_dir}")
    print(f"[precompute] headline: {report.get('headline')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
