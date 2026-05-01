"""Analysis router — run the full analysis pipeline."""

from __future__ import annotations

import json
import logging

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from algorithms.base import AnalysisContext
from algorithms.registry import get_registry
from api.dependencies import (
    get_tool_session,
    task_manager_or_503 as _task_manager_or_503,
)
from api.models import (
    AnalyzeFileRequest,
    AnalyzeRequestAPI,
    AutoExportRequest,
    BatchRunRequest,
    BatchRunResponse,
    ConsensusRequest,
    ConvergenceRequest,
    VerifyKeyRequest,
)
from core.dump_source import open_dump
from engine.consensus import ConsensusVector
from mcp_server import tools
from mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.analysis")

router = APIRouter()


@router.post("/run")
def run_analysis(
    request: AnalyzeRequestAPI,
    session: ToolSession = Depends(get_tool_session),
):
    """Run the full analysis pipeline on library directories.

    Runs synchronously for now; Phase B adds ProcessPool dispatch.
    """
    return tools.analyze_library(
        session,
        request.library_dirs,
        request.phase,
        request.protocol_version,
        keylog_filename=request.keylog_filename,
        template_name=request.template_name,
        max_runs=request.max_runs,
        normalize=request.normalize,
        expand_keys=request.expand_keys,
        algorithms=request.algorithms,
    )


@router.post("/consensus")
def run_consensus(
    req: ConsensusRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Build consensus vector from multiple dumps."""
    if len(req.dump_paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dumps")

    sources = [open_dump(Path(p)) for p in req.dump_paths]
    try:
        cm = ConsensusVector()
        cm.build_from_sources(sources, normalize=req.normalize)
    finally:
        for src in sources:
            try:
                src.close()
            except Exception as exc:
                logger.warning("Failed to close dump source: %s", exc)

    # Cache in session for range queries
    session._consensus_cache = cm

    static_regions = []
    for r in cm.get_static_regions():
        static_regions.append({
            "start": r.start,
            "end": r.end,
            "length": r.end - r.start,
            "mean_variance": float(r.mean_variance),
        })

    volatile_regions = []
    for r in cm.get_volatile_regions():
        volatile_regions.append({
            "start": r.start,
            "end": r.end,
            "length": r.end - r.start,
            "mean_variance": float(r.mean_variance),
        })

    return {
        "size": cm.size,
        "num_dumps": cm.num_dumps,
        "counts": cm.classification_counts(),
        "static_regions": static_regions,
        "volatile_regions": volatile_regions,
    }


@router.get("/consensus/range")
def consensus_range(
    offset: int = 0,
    length: int = 1024,
    session: ToolSession = Depends(get_tool_session),
):
    """Get variance classifications for a byte range."""
    cm = getattr(session, "_consensus_cache", None)
    if cm is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")

    length = min(length, 16384)
    end = min(offset + length, cm.size)
    actual_offset = max(0, offset)

    classifications = cm.classifications[actual_offset:end].tolist()

    return {
        "offset": actual_offset,
        "length": end - actual_offset,
        "classifications": classifications,
    }


@router.post("/run-file")
def run_file_analysis(
    request: AnalyzeFileRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Run analysis on a single dump file without dataset context."""
    path = Path(request.dump_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {request.dump_path}")

    filename = path.name

    # Read dump data via DumpSource
    source = open_dump(path)
    with source:
        dump_data = source.read_all()

    # Build context for algorithms
    extra: dict = {}
    if request.user_regex:
        extra["user_patterns"] = [{"name": "user_regex", "regex": request.user_regex}]
    if request.custom_patterns:
        extra["custom_patterns"] = request.custom_patterns

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
    # results and the decision rationale.
    registry = get_registry()
    hits: list[dict] = []
    algorithm_metadata: dict = {}

    for algo_name in request.algorithms:
        try:
            algorithm = registry.get(algo_name)
        except KeyError:
            logger.warning("Unknown algorithm: %s", algo_name)
            algorithm_metadata[algo_name] = {"error": f"unknown algorithm: {algo_name}"}
            continue

        try:
            result = algorithm.run(dump_data, context)
        except Exception as exc:
            logger.exception("Algorithm %s failed", algo_name)
            algorithm_metadata[algo_name] = {"error": str(exc)}
            continue

        algorithm_metadata[algo_name] = {
            "confidence": result.confidence,
            "match_count": len(result.matches),
        }

        for match in result.matches:
            hits.append({
                "secret_type": algo_name,
                "offset": match.offset,
                "length": match.length,
                "dump_path": request.dump_path,
                "library": filename,
                "phase": "file",
                "run_id": 0,
                "confidence": match.confidence,
            })

    library_report = {
        "library": filename,
        "protocol_version": "unknown",
        "phase": "file",
        "num_runs": 1,
        "hits": hits,
        "static_regions": [],
        "metadata": {
            "algorithms": request.algorithms,
            "dump_path": request.dump_path,
            "algorithm_results": algorithm_metadata,
        },
    }

    return {"libraries": [library_report], "metadata": {}}


@router.get("/patterns")
def list_patterns():
    """List available JSON pattern definitions."""
    patterns_dir = Path(__file__).parent.parent.parent / "algorithms" / "patterns"
    patterns = []
    if patterns_dir.is_dir():
        for f in sorted(patterns_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                patterns.append({
                    "filename": f.name,
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "applicable_to": data.get("applicable_to", {}),
                })
            except Exception:
                logger.exception("Failed to load pattern %s", f.name)
                patterns.append({"filename": f.name, "name": f.stem, "description": "Error loading", "applicable_to": {}})
    return {"patterns": patterns}


@router.post("/batch", response_model=BatchRunResponse)
def run_batch(request: BatchRunRequest):
    """Submit a batch analysis task and return a task_id.

    Mirrors :func:`api.routers.pipeline.run_pipeline_endpoint`: the
    request is translated into JSON-friendly worker params, dispatched
    to the TaskManager's ProcessPool via
    ``engine.batch_task_runner.run_batch``, and a ``task_id`` is
    returned immediately. Progress streams over ``/ws/tasks/{task_id}``
    and the aggregated batch result is downloadable as the
    ``batch_result`` artifact via the same artifact contract the
    pipeline endpoint uses.
    """
    manager = _task_manager_or_503()
    worker_params: dict = {
        "task_root": str(manager.artifact_store.root),
        "jobs": [job.model_dump() for job in request.jobs],
        "output_format": request.output_format,
        "workers": request.workers,
    }
    record = manager.submit(
        kind="batch",
        params=worker_params,
        runner_dotted="engine.batch_task_runner.run_batch",
        stage_names=["batch"],
    )
    return BatchRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.post("/convergence")
def run_convergence(req: ConvergenceRequest):
    """Run convergence sweep: build consensus at N=[2..max] and return metrics."""
    from engine.convergence import run_convergence_sweep
    from engine.serializer import serialize_convergence_result

    paths = [Path(p) for p in req.dump_paths]
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise HTTPException(status_code=404, detail=f"Files not found: {missing[:3]}")
    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dumps")

    result = run_convergence_sweep(
        paths,
        n_values=req.n_values,
        max_fp=req.max_fp,
    )
    return serialize_convergence_result(result)


@router.post("/verify-key")
def verify_key(req: VerifyKeyRequest):
    """Attempt decryption verification of a candidate key."""
    from engine.verification import (
        VERIFIER_REGISTRY,
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
    )

    if req.cipher not in VERIFIER_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown cipher: {req.cipher}. Available: {list(VERIFIER_REGISTRY)}",
        )

    verifier = VERIFIER_REGISTRY[req.cipher]

    try:
        with open_dump(Path(req.dump_path)) as source:
            candidate = source.read_range(req.offset, req.length)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Dump not found: {req.dump_path}")

    if len(candidate) < req.length:
        raise HTTPException(
            status_code=400,
            detail=f"Offset+length exceeds dump size",
        )

    ciphertext = bytes.fromhex(req.ciphertext_hex)
    iv = bytes.fromhex(req.iv_hex) if req.iv_hex else VERIFICATION_IV

    verified = verifier.verify(candidate, ciphertext, iv, VERIFICATION_PLAINTEXT)

    return {
        "verified": verified,
        "offset": req.offset,
        "cipher": req.cipher,
        "key_hex": candidate.hex() if verified else None,
    }


@router.post("/auto-export")
def auto_export(req: AutoExportRequest):
    """Auto-detect key region and export as YARA/JSON/Volatility3.

    Thin HTTP adapter over ``api.services.analysis_service.auto_export_pattern``.
    The service function owns the consensus → pattern pipeline so the
    CLI and API cannot drift again. Prior to PR 4 this route had its own
    copy of the pipeline that called ``cm.build(paths)`` (flat-bytes),
    producing file-relative offsets for native MSL inputs that users
    could not map back to memory.
    """
    from api.services.analysis_service import (
        AnalysisServiceError,
        auto_export_pattern,
    )

    try:
        return auto_export_pattern(
            req.dump_paths,
            fmt=req.format,
            name=req.name,
            align=req.align,
            context=req.context,
        )
    except AnalysisServiceError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
