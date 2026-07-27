"""TaskManager worker entries for the interactive analysis surface.

This module is the async counterpart to the two formerly-synchronous
FastAPI routes ``POST /api/analysis/run`` and
``POST /api/analysis/run-file``. Both routes used to run GIL-bound
algorithm loops inline on the request thread — a 2026-04-13 benchmark
recorded ~102.5 s for ``entropy_scan`` on a 10 MB dump, which blocks the
worker that long and risks proxy/gateway timeouts.

The two top-level functions here (``run_analysis`` / ``run_file``) match
the ``runner_dotted`` contract shared by
:mod:`engine.pipeline_runner`, :mod:`engine.batch_task_runner`, and
:mod:`engine.experiment_task_runner`: each takes ``(params, ctx)`` where
``ctx`` is a :class:`api.services.task_manager.WorkerContext`, emits
progress via ``ctx.emit``, and returns the
``{"artifacts": [...], "summary": {...}}`` shape
``TaskManager._on_success`` consumes.

Design notes:

* Both functions stay top-level (no closures, no instance methods) so
  the spawn-context worker trampoline can pickle them.
* All heavy imports are lazy (inside the functions) so a spawn worker
  starts cleanly and an import error surfaces as a reported task failure
  rather than a crash before the first event.
* The full ``AnalysisResult`` (the same dict the sync routes returned)
  is written to ``analysis/result.json`` in the per-task artifact
  directory and registered as the ``analysis_result`` artifact, so the
  SPA fetches it via the shared artifact contract
  (``GET /api/pipeline/runs/{task_id}/artifacts/analysis_result``) —
  identical to how ``engine.batch_task_runner`` exposes ``batch_result``.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("memdiver.engine.analysis_task_runner")

STAGE = "analyze"


def _resolve_artifact_dir(params: Dict[str, Any], ctx) -> Path:
    """Pick the per-task artifact directory the same way the other runners do."""
    if "artifact_dir" in params:
        artifact_dir = Path(params["artifact_dir"]).expanduser()
    elif "task_root" in params:
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    else:
        # Fallback for ad-hoc invocations (tests). The TaskManager always
        # provides ``task_root`` in production.
        artifact_dir = Path("./analysis_output").expanduser() / ctx.task_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def _write_result_artifact(
    result: Dict[str, Any],
    artifact_dir: Path,
) -> List[Dict[str, Any]]:
    """Persist ``result`` as ``analysis/result.json`` and return its artifact spec.

    Returns the ``artifacts`` list (single entry) in the dict shape
    ``TaskManager._on_success`` expects.
    """
    relpath = "analysis/result.json"
    out_path = artifact_dir / relpath
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    try:
        size = out_path.stat().st_size
    except OSError:
        size = 0
    sha = hashlib.sha256(out_path.read_bytes()).hexdigest()
    return [
        {
            "name": "analysis_result",
            "relpath": relpath,
            "media_type": "application/json",
            "size": size,
            "sha256": sha,
        }
    ]


def _result_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact terminal summary from a full AnalysisResult dict.

    Thin wrapper that delegates to
    :func:`engine.serializer.summarize_result`, the single source of truth
    for this projection. Kept as a named module function so its existing
    callers (``run_file`` / ``run_analysis``) are unaffected. The import is
    lazy to match this module's spawn-worker import discipline.
    """
    from memdiver.engine.serializer import summarize_result

    return summarize_result(result)


def run_analysis(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry for ``POST /api/analysis/run``.

    ``params`` keys (mirror :class:`api.models.AnalyzeRequestAPI`):

    * ``library_dirs`` (list[str], required)
    * ``phase`` / ``protocol_version`` (str, required)
    * ``keylog_filename`` (str, default ``"keylog.csv"``)
    * ``template_name`` (str, default ``"Auto-detect"``)
    * ``max_runs`` (int, default 10)
    * ``normalize`` (bool, default False)
    * ``expand_keys`` (bool, default True)
    * ``algorithms`` (list[str] | None)
    * ``task_root`` / ``artifact_dir`` — per-task output location.

    Reuses :func:`mcp_server.tools.analyze_library` (which itself drives
    ``engine.batch.run_analysis_request`` + ``engine.serializer``) so the
    algorithm logic is never duplicated. Returns the
    ``{"artifacts": [...], "summary": {...}}`` shape.
    """
    from memdiver.mcp_server.session import ToolSession
    from memdiver.mcp_server.tools import analyze_library

    artifact_dir = _resolve_artifact_dir(params, ctx)

    library_dirs = list(params.get("library_dirs", []))
    ctx.emit(
        "stage_start",
        stage=STAGE,
        pct=0.0,
        msg=f"analyzing {len(library_dirs)} library dir(s)",
    )

    if ctx.is_cancelled():
        ctx.emit("error", error="cancelled")
        raise RuntimeError("analysis cancelled")

    # analyze_library takes a ToolSession purely for API symmetry; the
    # library-analysis path does not read session state, so a fresh
    # instance is sufficient here.
    # analyze_library RAISES a CapabilityError for user-correctable input
    # problems (e.g. a missing directory). Surface it as a task failure so the
    # SPA renders the message instead of a silent empty result. The worker/task
    # contract reports such input failures as a ValueError.
    from memdiver.core.service_errors import CapabilityError

    try:
        result = analyze_library(
            ToolSession(),
            library_dirs,
            params["phase"],
            params["protocol_version"],
            keylog_filename=params.get("keylog_filename", "keylog.csv"),
            template_name=params.get("template_name", "Auto-detect"),
            max_runs=int(params.get("max_runs", 10)),
            normalize=bool(params.get("normalize", False)),
            expand_keys=bool(params.get("expand_keys", True)),
            algorithms=params.get("algorithms"),
        )
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc

    artifacts = _write_result_artifact(result, artifact_dir)
    summary = _result_summary(result)
    ctx.emit(
        "stage_end",
        stage=STAGE,
        pct=1.0,
        msg=(
            f"{summary['total_hits']} hit(s) across "
            f"{summary['library_count']} library report(s)"
        ),
        extra=summary,
    )
    return {"artifacts": artifacts, "summary": summary}


def run_file(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry for ``POST /api/analysis/run-file``.

    ``params`` keys (mirror :class:`api.models.AnalyzeFileRequest`):

    * ``dump_path`` (str, required)
    * ``algorithms`` (list[str], required)
    * ``user_regex`` (str | None)
    * ``custom_patterns`` (list[dict] | None)
    * ``passphrase`` / ``key_hex`` / ``kem_key_hex`` — optional decryption
      material for encrypted ``.msl`` inputs (spec §10).
    * ``task_root`` / ``artifact_dir`` — per-task output location.

    Runs every requested single-file algorithm sequentially, emitting one
    ``progress`` event per algorithm. This body was lifted verbatim from
    the former synchronous ``api.routers.analysis.run_file_analysis`` so
    behavior is preserved exactly; only the transport (inline -> task)
    changed.
    """
    from memdiver.algorithms.base import AnalysisContext
    from memdiver.algorithms.registry import get_registry
    from memdiver.core.dump_source import open_dump
    from memdiver.core.key_material import from_hex

    artifact_dir = _resolve_artifact_dir(params, ctx)

    dump_path = params["dump_path"]
    path = Path(dump_path)
    if not path.is_file():
        ctx.emit("error", error=f"File not found: {dump_path}")
        raise FileNotFoundError(f"File not found: {dump_path}")

    filename = path.name
    algorithms: List[str] = list(params.get("algorithms", []))

    ctx.emit(
        "stage_start",
        stage=STAGE,
        pct=0.0,
        msg=f"loading {filename} for {len(algorithms)} algorithm(s)",
    )

    # Read dump data via DumpSource (key material decrypts encrypted .msl).
    km = from_hex(
        params.get("passphrase"),
        params.get("key_hex"),
        params.get("kem_key_hex"),
    ) or {}
    source = open_dump(path, **km)
    with source:
        dump_data = source.read_all()

    # Build context for algorithms.
    extra: dict = {}
    if params.get("user_regex"):
        extra["user_patterns"] = [
            {"name": "user_regex", "regex": params["user_regex"]}
        ]
    if params.get("custom_patterns"):
        extra["custom_patterns"] = params["custom_patterns"]

    context = AnalysisContext(
        library=filename,
        protocol_version="unknown",
        phase="file",
        extra=extra,
    )

    # Run algorithms sequentially. A prior implementation used
    # ThreadPoolExecutor here, but every single-file algorithm (entropy_scan,
    # pattern_match, change_point, structure_scan, user_regex) is a pure-
    # Python GIL-bound loop with no I/O, so threads delivered zero
    # parallelism — wall-clock was identical to sequential, minus ~1s of
    # thread-pool overhead. A 2026-04-13 benchmark on a 10 MB dump recorded
    # ~102.5 s sequential vs ~103.5 s ThreadPool; entropy_scan alone takes
    # ~94.7 s, so the dispatch wrapper is not the bottleneck and
    # ProcessPool parallelism cannot meaningfully help either (total is
    # gated by the slowest single algorithm). See PR 2 in
    # .claude-work/plans/curried-jumping-lantern.md for the benchmark
    # results and the decision rationale. Running the whole route as one
    # TaskManager task moves this cost off the request thread instead.
    registry = get_registry()
    hits: List[dict] = []
    algorithm_metadata: dict = {}
    total = max(len(algorithms), 1)

    for idx, algo_name in enumerate(algorithms):
        if ctx.is_cancelled():
            ctx.emit("error", error="cancelled")
            raise RuntimeError("analysis cancelled")

        try:
            algorithm = registry.get(algo_name)
        except KeyError:
            logger.warning("Unknown algorithm: %s", algo_name)
            algorithm_metadata[algo_name] = {
                "error": f"unknown algorithm: {algo_name}"
            }
            ctx.emit(
                "progress",
                stage=STAGE,
                pct=(idx + 1) / total,
                msg=f"{algo_name}: unknown algorithm",
                extra={"algorithm": algo_name, "unknown": True},
            )
            continue

        try:
            result = algorithm.run(dump_data, context)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Algorithm %s failed", algo_name)
            algorithm_metadata[algo_name] = {"error": str(exc)}
            ctx.emit(
                "progress",
                stage=STAGE,
                pct=(idx + 1) / total,
                msg=f"{algo_name}: failed ({exc})",
                extra={"algorithm": algo_name, "failed": True},
            )
            continue

        algorithm_metadata[algo_name] = {
            "confidence": result.confidence,
            "match_count": len(result.matches),
        }

        for match in result.matches:
            hits.append(
                {
                    "secret_type": algo_name,
                    "offset": match.offset,
                    "length": match.length,
                    "dump_path": dump_path,
                    "library": filename,
                    "phase": "file",
                    "run_id": 0,
                    "confidence": match.confidence,
                }
            )

        ctx.emit(
            "progress",
            stage=STAGE,
            pct=(idx + 1) / total,
            msg=f"{algo_name}: {len(result.matches)} match(es)",
            extra={
                "algorithm": algo_name,
                "match_count": len(result.matches),
                "confidence": result.confidence,
            },
        )

    library_report = {
        "library": filename,
        "protocol_version": "unknown",
        "phase": "file",
        "num_runs": 1,
        "hits": hits,
        "static_regions": [],
        "metadata": {
            "algorithms": algorithms,
            "dump_path": dump_path,
            "algorithm_results": algorithm_metadata,
        },
    }
    result_payload = {"libraries": [library_report], "metadata": {}}

    artifacts = _write_result_artifact(result_payload, artifact_dir)
    summary = _result_summary(result_payload)
    ctx.emit(
        "stage_end",
        stage=STAGE,
        pct=1.0,
        msg=f"{len(hits)} hit(s) from {len(algorithms)} algorithm(s)",
        extra=summary,
    )
    return {"artifacts": artifacts, "summary": summary}
