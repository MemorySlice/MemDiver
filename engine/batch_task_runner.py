"""TaskManager worker entry for batch analysis.

Mirrors :mod:`engine.pipeline_runner` for the Phase B
``POST /api/analysis/batch`` endpoint. The router translates a
:class:`BatchRunRequest` into a JSON-friendly ``params`` dict and
hands it to ``TaskManager.submit(runner_dotted="engine.batch_task_runner.run_batch")``.
This module then reconstructs a :class:`core.input_schemas.BatchRequest`
from those params, drives the existing :class:`engine.batch.BatchRunner`,
and writes the aggregated result JSON into the per-task artifact
directory so it can be served via
``GET /api/analysis/runs/{task_id}/artifacts/{name}`` (same artifact
contract as the pipeline endpoint).

Design notes:

* ``run_batch`` is a top-level function so the spawn-context worker
  trampoline can pickle it. No closures, no captured state.
* We force ``use_processes=False`` on the inner ``BatchRunner`` because
  this function already runs inside a TaskManager worker process and
  nesting a second ProcessPool on macOS spawn is exactly the failure
  mode :mod:`api.services.task_manager` flagged. Thread-level
  parallelism is fine — every batch job is dominated by I/O and
  GIL-releasing numpy work.
* Progress is emitted through the same ``ctx.emit`` mp-queue contract
  ``engine.pipeline_runner`` uses, so the WebSocket consumer treats
  batch tasks identically.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.engine.batch_task_runner")


def _register_artifact(
    artifacts: List[Dict[str, Any]],
    artifact_dir: Path,
    *,
    name: str,
    relpath: str,
    media_type: str = "application/octet-stream",
) -> Dict[str, Any]:
    """Compute size + sha256 and append an artifact spec dict."""
    full = artifact_dir / relpath
    try:
        size = full.stat().st_size
    except OSError:
        size = 0
    sha = hashlib.sha256(full.read_bytes()).hexdigest() if full.is_file() else None
    spec = {
        "name": name,
        "relpath": relpath,
        "media_type": media_type,
        "size": size,
        "sha256": sha,
    }
    artifacts.append(spec)
    return spec


def _job_dict_to_request(job: Dict[str, Any]):
    """Translate a JSON-friendly job dict into a real ``AnalyzeRequest``.

    Pydantic models on the router side serialize ``Path`` as ``str``,
    so we re-hydrate ``library_dirs`` here. The dataclass __post_init__
    validates that each library_dir exists; any failure surfaces as a
    pickled exception that ``TaskManager._on_error`` reports.
    """
    from core.input_schemas import AnalyzeRequest

    return AnalyzeRequest(
        library_dirs=[Path(d) for d in job["library_dirs"]],
        phase=job["phase"],
        protocol_version=job["protocol_version"],
        keylog_filename=job.get("keylog_filename", "keylog.csv"),
        template_name=job.get("template_name", "Auto-detect"),
        max_runs=job.get("max_runs", 10),
        normalize=job.get("normalize", False),
        expand_keys=job.get("expand_keys", True),
        algorithms=job.get("algorithms"),
    )


def run_batch(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry for batch analysis.

    ``params`` keys:

    * ``task_root`` (str, required): root dir under which the
      TaskManager has provisioned ``<task_id>/`` for our artifacts.
      The router copies this from ``manager.artifact_store.root`` so
      the worker doesn't need to know the store API.
    * ``artifact_dir`` (str, optional): explicit override for tests.
    * ``jobs`` (list[dict], required): one ``AnalyzeRequest`` per job
      in JSON-friendly form (``library_dirs`` as ``list[str]``).
    * ``output_format`` (str, default ``"json"``): forwarded to
      :class:`core.input_schemas.BatchRequest` for output_format
      validation parity with the CLI.
    * ``workers`` (int, default 1): inner thread count.

    Returns the dict shape ``TaskManager._on_success`` expects:

        {
          "artifacts": [<ArtifactSpec dicts>],
          "summary": { ... batch totals ... }
        }
    """
    from core.input_schemas import BatchRequest
    from engine.batch import BatchRunner

    if "artifact_dir" in params:
        artifact_dir = Path(params["artifact_dir"]).expanduser()
    else:
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    artifact_dir.mkdir(parents=True, exist_ok=True)

    jobs_raw: List[Dict[str, Any]] = list(params.get("jobs", []))
    if not jobs_raw:
        raise ValueError("batch params: jobs list is empty")
    output_format = params.get("output_format", "json")
    workers = int(params.get("workers", 1))

    jobs = [_job_dict_to_request(j) for j in jobs_raw]
    batch = BatchRequest(jobs=jobs, output_format=output_format)

    total = len(jobs)
    ctx.emit(
        "stage_start",
        stage="batch",
        pct=0.0,
        msg=f"running {total} job(s) workers={workers}",
    )

    def _progress(current: int, total_jobs: int, status: Optional[str]) -> None:
        # Mirror engine.pipeline_runner's bridge: forward as fine-grained
        # progress on the parent stage. ``current``/``total_jobs`` lets
        # the UI render a job counter alongside the percentage.
        if ctx.is_cancelled():
            # BatchRunner has no cancel hook of its own; this still gives
            # us a best-effort early-exit signal once the in-flight job
            # finishes — same as nsweep / brute_force behavior elsewhere.
            return
        pct = (current / total_jobs) if total_jobs else None
        ctx.emit(
            "progress",
            stage="batch",
            pct=pct,
            msg=status or "",
            extra={"completed": current, "total": total_jobs},
        )

    # Force threads to avoid nesting a ProcessPool inside the
    # TaskManager-provided worker process (see module docstring).
    runner = BatchRunner(workers=workers, use_processes=False)
    result = runner.run(batch, progress_callback=_progress)
    result_dict = result.to_dict()

    # Persist the aggregated batch result so it can be downloaded via
    # the artifact API. We honor output_format the same way the CLI
    # does: jsonl gets newline-delimited per-job records, json a single
    # pretty-printed object.
    relpath = "batch/result.jsonl" if output_format == "jsonl" else "batch/result.json"
    out_path = artifact_dir / relpath
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "jsonl":
        lines = [json.dumps(j) for j in result_dict.get("jobs", [])]
        summary = {k: v for k, v in result_dict.items() if k != "jobs"}
        summary["_type"] = "summary"
        lines.append(json.dumps(summary))
        out_path.write_text("\n".join(lines) + "\n")
    else:
        out_path.write_text(json.dumps(result_dict, indent=2))

    artifacts: List[Dict[str, Any]] = []
    _register_artifact(
        artifacts,
        artifact_dir,
        name="batch_result",
        relpath=relpath,
        media_type=(
            "application/x-ndjson" if output_format == "jsonl"
            else "application/json"
        ),
    )

    summary = {
        "total_jobs": result_dict.get("total_jobs", total),
        "succeeded_count": result_dict.get("succeeded_count", 0),
        "failed_count": result_dict.get("failed_count", 0),
        "total_duration_seconds": result_dict.get("total_duration_seconds", 0.0),
        "output_format": output_format,
        "result_path": str(out_path),
    }
    ctx.emit(
        "stage_end",
        stage="batch",
        pct=1.0,
        msg=(
            f"{summary['succeeded_count']}/{summary['total_jobs']} jobs "
            f"succeeded in {summary['total_duration_seconds']:.1f}s"
        ),
        extra=summary,
    )

    return {"artifacts": artifacts, "summary": summary}
