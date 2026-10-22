"""HTTP surface for the SPA experiment runner.

A single ``POST /api/experiment/run`` endpoint lifts the orchestration
that ``cli.py:_cmd_experiment`` performs (spawn target, dump with each
tool, build per-tool consensus, verify, optionally emit a Volatility3
plugin) onto the TaskManager's worker pool. Progress streams over the
existing ``/ws/tasks/{task_id}`` WebSocket; the request returns
immediately with a ``task_id``.

Like :mod:`api.routers.pipeline`, the request body is the only place
parameters are validated; the worker entry point in
:mod:`app.pipeline.experiment_task_runner` consumes a plain dict.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from memdiver.api.dependencies import task_manager_or_503 as _task_manager_or_503
from memdiver.api.models import MemoryOverrideFields

logger = logging.getLogger("memdiver.api.routers.experiment")

router = APIRouter()


class ExperimentRunRequest(MemoryOverrideFields):
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
        runner_dotted="memdiver.app.pipeline.experiment_task_runner.run_experiment",
        stage_names=["capture", "consensus", "verify"],
    )
    return ExperimentRunResponse(
        task_id=record.task_id,
        status=record.status.value,
    )


class CaptureRequest(BaseModel):
    """Request body for ``POST /api/experiment/capture`` (one dump of a live process)."""

    target: str = Field(..., description="Process ID, or process / Android package name.")
    tool: str = Field(default="memslicer", description="memslicer | lldb | fridump.")
    device: str = Field(
        default="local",
        description="local | usb | usb:<frida-device-id> | remote:<host>[:<port>].")
    output: Optional[str] = Field(
        default=None,
        description="Output dump path (default: <task artifact root>/captures/...).")
    max_region_size: Optional[int] = Field(
        default=None, ge=1, description="Skip (and report) regions >= this many bytes.")
    include_large_readonly: bool = Field(
        default=False,
        description="lldb: also capture non-writable regions >= 100 MiB.")
    timeout: Optional[float] = Field(default=None, gt=0,
                                     description="Backend timeout in seconds.")


def _default_capture_output(request: CaptureRequest) -> str:
    import datetime
    import re

    root = Path(_task_manager_or_503().artifact_store.root) / "captures"
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", request.target.strip()) or "target"
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = "msl" if request.tool == "memslicer" else "bin"
    return str(root / f"{stem}_{request.tool}_{stamp}.{ext}")


@router.post("/capture")
def capture_endpoint(request: CaptureRequest) -> dict:
    """Capture one dump synchronously and return the capture report.

    The report lists every region that was not captured under ``skipped``
    (base / size / reason) plus ``summary_warnings``; ``ok`` false carries
    ``error``. Invalid input / a missing backend propagate as
    ``CapabilityError`` (400 / 412 via the app-level handler).
    """
    from memdiver.app.experiment_orchestration import capture_result

    if not request.target.strip():
        raise HTTPException(status_code=400, detail="target must be a pid or a name")
    output = request.output or _default_capture_output(request)
    return capture_result(
        target=request.target, output=output, tool=request.tool,
        device=request.device, max_region_size=request.max_region_size,
        include_large_readonly=request.include_large_readonly,
        timeout=request.timeout)
