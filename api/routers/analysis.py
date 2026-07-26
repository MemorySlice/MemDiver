"""Analysis router — run the full analysis pipeline."""

from __future__ import annotations

import json
import logging

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from memdiver.api.adapters import analyze_run_params, batch_run_params
from memdiver.api.dependencies import (
    task_manager_or_503 as _task_manager_or_503,
)
from memdiver.api.models import (
    AnalysisRunResponse,
    AnalyzeFileRequest,
    AnalyzeRequestAPI,
    AutoExportRequest,
    BatchRunRequest,
    BatchRunResponse,
    ConsensusRequest,
    ConvergenceRequest,
    VerifyKeyRequest,
)
from memdiver.api.services.consensus_session import (
    ConsensusSessionManager,
    get_consensus_manager,
)
from memdiver.api.services.key_material import decode_key_material
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.consensus_service import build_consensus

logger = logging.getLogger("memdiver.api.routers.analysis")

router = APIRouter()


@router.post("/run", response_model=AnalysisRunResponse)
def run_analysis(request: AnalyzeRequestAPI):
    """Submit the full library-analysis pipeline as a task and return a task_id.

    Previously this ran ``tools.analyze_library`` inline on the request
    thread ("Runs synchronously for now"). The GIL-bound algorithm work
    is now dispatched to the TaskManager's ProcessPool via
    ``engine.analysis_task_runner.run_analysis`` — the same async pattern
    as ``POST /api/analysis/batch`` and the pipeline endpoint. Progress
    streams over ``/ws/tasks/{task_id}`` and the full ``AnalysisResult``
    is downloadable as the ``analysis_result`` artifact.

    The identical algorithm logic still lives in
    ``mcp_server.tools.analyze_library`` (which the runner calls and the
    MCP server continues to use synchronously), so no behavior is lost.
    """
    manager = _task_manager_or_503()
    # Field mapping lives in the single conversion seam (api.adapters) so the
    # wire model and core AnalyzeRequest can't drift. This stays a dict (not a
    # core dataclass) so the ProcessPool payload is unchanged and library_dir
    # validation stays deferred to the worker.
    worker_params: dict = analyze_run_params(
        request, task_root=str(manager.artifact_store.root)
    )
    record = manager.submit(
        kind="analysis",
        params=worker_params,
        runner_dotted="memdiver.engine.analysis_task_runner.run_analysis",
        stage_names=["analyze"],
    )
    return AnalysisRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.post("/consensus")
def run_consensus(
    req: ConsensusRequest,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Build consensus vector from multiple dumps."""
    if len(req.dump_paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dumps")

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    # open+build is the shared skeleton; build_consensus opens each dump as a
    # context-managed source, builds the vector while they are all live, and
    # closes them once the vector holds its own copies. No disk writes here.
    cm = build_consensus(req.dump_paths, normalize=req.normalize, key_material=km)

    # Register the build under its own id so range queries are isolated per
    # client — no shared mutable state on a process-wide singleton.
    built = manager.register(cm)

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
        "consensus_id": built.session_id,
        "size": cm.size,
        "num_dumps": cm.num_dumps,
        "counts": cm.classification_counts(),
        "static_regions": static_regions,
        "volatile_regions": volatile_regions,
    }


@router.get("/consensus/range")
def consensus_range(
    consensus_id: str,
    offset: int = 0,
    length: int = 1024,
    manager: ConsensusSessionManager = Depends(get_consensus_manager),
):
    """Get variance classifications for a byte range of a specific build.

    ``consensus_id`` is the id returned by ``POST /consensus``; range queries
    are scoped to that build so concurrent clients never read each other's
    results.
    """
    built = manager.get(consensus_id)
    if built is None:
        raise HTTPException(status_code=404, detail="No consensus computed yet")
    cm = built.matrix

    length = min(length, 16384)
    end = min(offset + length, cm.size)
    actual_offset = max(0, offset)

    classifications = cm.classifications[actual_offset:end].tolist()

    return {
        "offset": actual_offset,
        "length": end - actual_offset,
        "classifications": classifications,
    }


@router.post("/run-file", response_model=AnalysisRunResponse)
def run_file_analysis(request: AnalyzeFileRequest):
    """Submit single-file analysis as a task and return a task_id.

    Previously this read the dump and ran every requested algorithm
    inline on the request thread. A 2026-04-13 benchmark recorded
    ~102.5 s for ``entropy_scan`` on a 10 MB dump — long enough to trip
    proxy/gateway timeouts. The GIL-bound work now runs on the
    TaskManager's ProcessPool via
    ``engine.analysis_task_runner.run_file`` (which preserves the exact
    algorithm loop, including optional decryption key material). Progress
    streams over ``/ws/tasks/{task_id}`` — one event per algorithm — and
    the full ``AnalysisResult`` is downloadable as the ``analysis_result``
    artifact.

    The path existence check stays here so callers still get a fast 404
    for a missing file instead of a task that fails asynchronously.
    """
    path = Path(request.dump_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {request.dump_path}")

    manager = _task_manager_or_503()
    worker_params: dict = {
        "task_root": str(manager.artifact_store.root),
        "dump_path": request.dump_path,
        "algorithms": list(request.algorithms),
        "user_regex": request.user_regex,
        "custom_patterns": request.custom_patterns,
        # Forward raw key material; the worker decodes it in-process so the
        # params stay JSON-friendly across the multiprocessing queue.
        "passphrase": request.passphrase,
        "key_hex": request.key_hex,
        "kem_key_hex": request.kem_key_hex,
    }
    record = manager.submit(
        kind="analysis",
        params=worker_params,
        runner_dotted="memdiver.engine.analysis_task_runner.run_file",
        stage_names=["analyze"],
    )
    return AnalysisRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


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
    # Same single conversion seam as /run. Kept dict-based so each job's
    # AnalyzeRequest __post_init__ validation stays deferred to the worker's
    # per-job re-hydration (unchanged pool payload).
    worker_params: dict = batch_run_params(
        request, task_root=str(manager.artifact_store.root)
    )
    record = manager.submit(
        kind="batch",
        params=worker_params,
        runner_dotted="memdiver.engine.batch_task_runner.run_batch",
        stage_names=["batch"],
    )
    return BatchRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


@router.post("/convergence")
def run_convergence(req: ConvergenceRequest):
    """Run convergence sweep: build consensus at N=[2..max] and return metrics."""
    from memdiver.engine.convergence import run_convergence_sweep
    from memdiver.engine.serializer import serialize_convergence_result

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
    """Attempt decryption verification of a candidate key.

    Thin HTTP adapter over ``app.tools_pipeline.verify_key_result`` — the same
    producer the CLI ``verify`` command and the MCP ``verify`` tool use, so the
    candidate-read + decryption check cannot drift across surfaces. The
    producer's transport-agnostic ``CapabilityError`` is translated to an
    ``HTTPException`` here (preserving this route's ``{"detail": ...}`` shape +
    per-category status), rather than through the global handler, because the
    404/400 contract predates that handler.
    """
    from memdiver.app.tools_pipeline import verify_key_result

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    try:
        result = verify_key_result(
            dump_path=req.dump_path,
            offset=req.offset,
            length=req.length,
            ciphertext_hex=req.ciphertext_hex,
            cipher=req.cipher,
            iv_hex=req.iv_hex,
            key_material=km,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc

    return {
        "verified": result["verified"],
        "offset": result["offset"],
        "cipher": result["cipher"],
        "key_hex": result["key_hex"],
    }


@router.post("/auto-export")
def auto_export(req: AutoExportRequest):
    """Auto-detect key region and export as YARA/JSON/Volatility3.

    Thin HTTP adapter over the ``app`` producer
    :func:`memdiver.app.tools_pipeline.export_pattern`, which owns the
    consensus → pattern pipeline so the CLI, API and MCP surfaces cannot
    drift again. Prior to PR 4 this route had its own copy of the pipeline
    that called ``cm.build(paths)`` (flat-bytes), producing file-relative
    offsets for native MSL inputs that users could not map back to memory.

    The producer returns the same ``{format, content, pattern, region}``
    payload the pre-relocation service returned, so the response body is
    unchanged.
    """
    from memdiver.app.tools_pipeline import export_pattern

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex)
    try:
        return export_pattern(
            dump_paths=list(req.dump_paths),
            fmt=req.format,
            name=req.name,
            align=req.align,
            context=req.context,
            key_material=km,
        )
    except CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
