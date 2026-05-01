"""HTTP surface for the SPA experiment runner.

A single ``POST /api/experiment/run`` endpoint lifts the orchestration
that ``cli.py:_cmd_experiment`` performs (spawn target, dump with each
tool, build per-tool consensus, verify, optionally emit a Volatility3
plugin) onto the TaskManager's worker pool. Progress streams over the
existing ``/ws/tasks/{task_id}`` WebSocket; the request returns
immediately with a ``task_id``.

Like :mod:`api.routers.pipeline`, the request body is the only place
parameters are validated; the worker entry point in
:mod:`engine.experiment_task_runner` consumes a plain dict.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import task_manager_or_503 as _task_manager_or_503

logger = logging.getLogger("memdiver.api.routers.experiment")

router = APIRouter()


class ExperimentRunRequest(BaseModel):
    """Request body for ``POST /api/experiment/run``.

    Only ``target`` is required; the other fields surface knobs the CLI
    ``experiment`` subcommand exposes so the SPA can stay parity-feature
    with ``memdiver experiment ...``.
    """

    target: str = Field(..., description="Path to target binary or script.")
    num_runs: int = Field(default=10, ge=1, le=200,
                          description="Iterations per dump tool.")
    tools: Optional[List[str]] = Field(
        default=None,
        description="Dump tools to use (default: auto-detect).",
    )
    export_format: str = Field(
        default="volatility3",
        description="Plugin export format: volatility3 | yara | json.",
    )
    oracle_id: Optional[str] = Field(
        default=None,
        description="Reserved for armed-oracle verification (Phase 25+).",
    )
    protocol_version: str = Field(
        default="TLS13",
        description="Protocol tag surfaced to the SPA in the result summary.",
    )
    phase: str = Field(
        default="pre_abort",
        description="Phase tag surfaced to the SPA in the result summary.",
    )


class ExperimentRunResponse(BaseModel):
    task_id: str
    status: str


@router.post("/run", response_model=ExperimentRunResponse)
def run_experiment_endpoint(request: ExperimentRunRequest):
    """Submit an experiment run and return a streaming task_id.

    The endpoint accepts a non-existent target so the worker can fail
    fast with a clear error event over the WebSocket — that keeps the
    error surface symmetric with the CLI which logs to stderr but does
    not validate the path before dispatch.
    """
    manager = _task_manager_or_503()

    # Light pre-flight validation: bare-string targets like an empty
    # string are obviously bogus and would otherwise tie up a worker.
    if not request.target.strip():
        raise HTTPException(
            status_code=400, detail="target must be a non-empty path",
        )

    params = request.model_dump()
    # Hand the worker the same task_root pipeline_runner uses so it can
    # derive ``<task_root>/<task_id>`` itself from ctx.task_id.
    params["task_root"] = str(Path(manager.artifact_store.root))

    record = manager.submit(
        kind="experiment",
        params=params,
        runner_dotted="engine.experiment_task_runner.run_experiment",
        stage_names=["capture", "consensus", "verify"],
    )
    return ExperimentRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )
