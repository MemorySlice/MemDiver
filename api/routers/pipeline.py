"""HTTP surface for the Phase 25 end-to-end pipeline.

Single-orchestrator design: one ``POST /api/pipeline/run`` endpoint
accepts a dump list + armed oracle + reduce/brute-force/nsweep/
emit-plugin params and returns a ``task_id``. Progress streams over
``/ws/tasks/{task_id}``. Artifact metadata + stage state live on the
TaskRecord at ``GET /api/pipeline/runs/{task_id}``; individual
artifacts are downloadable at ``GET /api/pipeline/runs/{task_id}/artifacts/{name}``.

Per-stage endpoints (search-reduce / brute-force / n-sweep by
themselves) are deferred to v2 per the plan — keeping the surface
small forces the frontend to treat the pipeline as one coherent
story and avoids duplicating orchestration in TypeScript.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from api.dependencies import (
    oracle_registry_or_503 as _oracle_registry_or_503,
    task_manager_or_503 as _task_manager_or_503,
)
from api.services.artifact_store import (
    ArtifactNotFound,
    ArtifactStoreError,
    InvalidArtifactName,
)
from api.services.oracle_registry import (
    OracleNotArmed,
    OracleNotFound,
    OracleRegistryError,
)
from api.services.task_manager import TERMINAL_STATUSES

logger = logging.getLogger("memdiver.api.routers.pipeline")

router = APIRouter()


# ------------------------------------------------------------------
# pydantic models
# ------------------------------------------------------------------


class ReduceParams(BaseModel):
    alignment: int = 8
    block_size: int = 32
    density_threshold: float = 0.5
    min_variance: float = 3000.0
    entropy_window: int = 32
    entropy_threshold: float = 4.5
    min_region: int = 16


class BruteForceParams(BaseModel):
    key_sizes: List[int] = Field(default_factory=lambda: [32])
    stride: int = 8
    jobs: int = 1
    exhaustive: bool = True
    top_k: int = 10


class NSweepParams(BaseModel):
    n_values: List[int]
    reduce_kwargs: Optional[ReduceParams] = None
    key_sizes: List[int] = Field(default_factory=lambda: [32])
    stride: int = 8
    exhaustive: bool = True


class EmitParams(BaseModel):
    name: str = "memdiver_plugin"
    description: Optional[str] = None
    hit_index: int = 0
    min_static_ratio: float = 0.3
    variance_threshold: Optional[float] = None


class RefineRequest(BaseModel):
    additional_paths: List[str] = Field(..., min_length=1)


class RefineResponse(BaseModel):
    num_dumps: int
    static_count: int
    dynamic_count: int
    hit_neighborhoods: List[Dict[str, Any]]


class PipelineRunRequest(BaseModel):
    source_paths: List[str] = Field(..., min_length=1)
    oracle_id: str
    reduce: ReduceParams = Field(default_factory=ReduceParams)
    brute_force: BruteForceParams = Field(default_factory=BruteForceParams)
    nsweep: Optional[NSweepParams] = None
    emit: Optional[EmitParams] = None


class PipelineRunResponse(BaseModel):
    task_id: str
    status: str
    oracle_sha256: str


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------


def _build_worker_params(
    request: PipelineRunRequest,
    oracle_path: Path,
    task_root: Path,
) -> dict:
    """Translate the Pydantic request into the plain-dict the worker expects."""
    reduce_kwargs = request.reduce.model_dump()
    bf_kwargs = request.brute_force.model_dump()
    worker: dict = {
        "task_root": str(task_root),
        "source_paths": list(request.source_paths),
        "oracle_path": str(oracle_path),
        "reduce_kwargs": reduce_kwargs,
        "brute_force": bf_kwargs,
    }
    if request.nsweep is not None:
        nsweep_dict = request.nsweep.model_dump()
        if nsweep_dict.get("reduce_kwargs") is None:
            nsweep_dict["reduce_kwargs"] = reduce_kwargs
        worker["nsweep"] = nsweep_dict
    if request.emit is not None:
        worker["emit"] = request.emit.model_dump()
    return worker


# ------------------------------------------------------------------
# routes
# ------------------------------------------------------------------


@router.post("/run", response_model=PipelineRunResponse)
def run_pipeline_endpoint(request: PipelineRunRequest):
    """Submit the Phase 25 pipeline and return a task_id."""
    manager = _task_manager_or_503()
    registry = _oracle_registry_or_503()

    try:
        entry = registry.require_armed(request.oracle_id)
    except OracleNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OracleNotArmed as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OracleRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    for p in request.source_paths:
        if not Path(p).is_file():
            raise HTTPException(
                status_code=400,
                detail=f"source path not found: {p}",
            )

    stage_names = ["consensus", "search_reduce", "brute_force"]
    if request.nsweep is not None:
        stage_names.append("nsweep")
    if request.emit is not None:
        stage_names.append("emit_plugin")

    worker_params = _build_worker_params(
        request,
        oracle_path=entry.path,
        task_root=manager.artifact_store.root,
    )
    record = manager.submit(
        kind="pipeline",
        params=worker_params,
        runner_dotted="engine.pipeline_runner.run_pipeline",
        stage_names=stage_names,
    )
    return PipelineRunResponse(
        task_id=record.task_id,
        status=record.status.value,
        oracle_sha256=entry.sha256,
    )


@router.get("/runs/{task_id}")
def get_run(task_id: str):
    """Return the TaskRecord for a pipeline task (stages + artifacts)."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    return record.to_dict()


@router.delete("/runs/{task_id}")
def cancel_run(task_id: str):
    """Cooperative cancel. Use DELETE for idempotent semantics."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    if record.status in TERMINAL_STATUSES:
        return {"task_id": task_id, "cancelled": False,
                "status": record.status.value}
    manager.cancel(task_id)
    return {"task_id": task_id, "cancelled": True}


@router.get("/runs/{task_id}/artifacts/{name}")
def download_artifact(task_id: str, name: str):
    """Serve a registered artifact via FileResponse, traversal-guarded."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    spec = next((a for a in record.artifacts if a.name == name), None)
    if spec is None:
        raise HTTPException(
            status_code=404,
            detail=f"artifact not found: {name}",
        )
    # Prefer the ArtifactStore's validated opener. Fall back to a
    # direct resolve against the task dir if the store does not yet
    # know about the spec (e.g. task registered artifacts via the
    # TaskManager but not the store — current worker path).
    store = manager.artifact_store
    try:
        full_path = store.open(task_id, name)
    except ArtifactNotFound:
        task_dir = store.task_dir(task_id)
        candidate = (task_dir / spec.relpath).resolve()
        try:
            candidate.relative_to(task_dir.resolve())
        except ValueError as exc:
            raise HTTPException(status_code=400,
                                detail="artifact escapes task dir") from exc
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="artifact file missing")
        full_path = candidate
    except (ArtifactStoreError, InvalidArtifactName) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return FileResponse(
        full_path,
        media_type=spec.media_type,
        filename=Path(spec.relpath).name,
    )


@router.post("/runs/{task_id}/refine", response_model=RefineResponse)
async def refine_consensus(task_id: str, body: RefineRequest):
    """Fold additional dumps into the consensus and return updated variance stats.

    Loads the persisted Welford state, folds new dumps synchronously (fast),
    saves updated state, and returns per-hit neighborhood slices.
    """
    import json

    import numpy as np

    from core.dump_source import open_dump
    from core.variance import WelfordVariance
    from engine.vol3_emit import PLUGIN_STATIC_THRESHOLD

    manager = _task_manager_or_503()
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(404, f"task {task_id} not found")

    # Find the consensus state.json in the task's artifact dir
    artifact_dir = (
        Path(task.get("artifact_dir", ""))
        if isinstance(task, dict)
        else Path(getattr(task, "artifact_dir", ""))
    )
    # Try common locations
    state_path = None
    for candidate in [
        artifact_dir / "consensus" / "state.json",
        Path(
            str(artifact_dir)
            .replace("/brute_force", "")
            .replace("/emit_plugin", "")
        )
        / "consensus"
        / "state.json",
    ]:
        if candidate.exists():
            state_path = candidate
            break

    if state_path is None:
        raise HTTPException(
            400,
            "consensus state not found for this task "
            "— was the pipeline run completed?",
        )

    state = json.loads(state_path.read_text())
    mean = np.load(state["mean_path"])
    m2 = np.load(state["m2_path"])
    welford = WelfordVariance.from_state(mean, m2, int(state["num_dumps"]))

    # Validate and fold each additional dump
    for p in body.additional_paths:
        path = Path(p).expanduser()
        if not path.exists():
            raise HTTPException(400, f"dump not found: {p}")
        with open_dump(path) as src:
            data = src.read_all()[: welford.size]
        if len(data) < welford.size:
            continue  # skip short dumps
        welford.add_dump(data)

    # Save updated state
    new_mean, new_m2, new_n = welford.state_arrays()
    np.save(state["mean_path"], new_mean)
    np.save(state["m2_path"], new_m2)
    state["num_dumps"] = new_n
    state_path.write_text(json.dumps(state, indent=2))

    # Update variance.npy
    variance = welford.variance()
    variance_path = state_path.parent / "variance.npy"
    np.save(variance_path, variance)

    # Compute classification counts
    static_count = int(np.sum(variance <= PLUGIN_STATIC_THRESHOLD))
    dynamic_count = int(np.sum(variance > PLUGIN_STATIC_THRESHOLD))

    # Extract neighborhood slices for known hits
    hit_neighborhoods: List[Dict[str, Any]] = []
    hits_path = state_path.parent.parent / "brute_force" / "hits.json"
    if hits_path.exists():
        hits_data = json.loads(hits_path.read_text())
        for hit in hits_data.get("hits", []):
            offset = int(hit["offset"])
            length = int(hit["length"])
            nb_pad = 64
            start = max(0, offset - nb_pad)
            end = min(len(variance), offset + length + nb_pad)
            nb_var = (
                m2[start:end].astype(np.float32) / float(new_n)
            ).tolist()
            nb_static = sum(
                1 for v in nb_var if v <= PLUGIN_STATIC_THRESHOLD
            )
            hit_neighborhoods.append(
                {
                    "offset": offset,
                    "neighborhood_start": start,
                    "neighborhood_variance": nb_var,
                    "static_count": nb_static,
                    "dynamic_count": len(nb_var) - nb_static,
                }
            )

    return RefineResponse(
        num_dumps=new_n,
        static_count=static_count,
        dynamic_count=dynamic_count,
        hit_neighborhoods=hit_neighborhoods,
    )


@router.get("/runs/{task_id}/neighborhood")
async def get_neighborhood(
    task_id: str, offset: int, length: int = 32
):
    """Return the variance slice around a specific offset from the consensus state."""
    import json

    import numpy as np

    manager = _task_manager_or_503()
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(404, f"task {task_id} not found")

    artifact_dir = (
        Path(task.get("artifact_dir", ""))
        if isinstance(task, dict)
        else Path(getattr(task, "artifact_dir", ""))
    )
    state_path = artifact_dir / "consensus" / "state.json"
    if not state_path.exists():
        raise HTTPException(400, "consensus state not found")

    state = json.loads(state_path.read_text())
    n = int(state["num_dumps"])
    if n == 0:
        return {
            "offset": offset,
            "length": length,
            "variance": [],
            "num_dumps": 0,
        }

    m2 = np.load(state["m2_path"], mmap_mode="r")
    nb_pad = 64
    start = max(0, offset - nb_pad)
    end = min(len(m2), offset + length + nb_pad)
    variance_slice = (
        m2[start:end].astype(np.float32) / float(n)
    ).tolist()

    return {
        "offset": offset,
        "neighborhood_start": start,
        "num_dumps": n,
        "variance": variance_slice,
    }
