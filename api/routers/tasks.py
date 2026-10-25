"""Tasks router — thin HTTP surface for the TaskManager singleton."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from memdiver.api.dependencies import task_manager_or_503 as _manager_or_503
from memdiver.api.services.artifact_store import ArtifactStoreError
from memdiver.api.services.task_manager import TERMINAL_STATUSES, TaskStatus

logger = logging.getLogger("memdiver.api.routers.tasks")

router = APIRouter()


@router.get("/")
def list_tasks():
    """List every known task, newest first."""
    mgr = _manager_or_503()
    tasks = sorted(
        mgr.list_tasks(), key=lambda r: r.created_at, reverse=True
    )
    return {"tasks": [t.to_dict() for t in tasks]}


@router.get("/{task_id}")
def get_task(task_id: str):
    """Full task record including stages + artifacts."""
    mgr = _manager_or_503()
    record = mgr.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    return record.to_dict()


def _result_payload(mgr, record) -> Optional[Any]:
    """The full parsed ``<kind>_result`` JSON artifact of a succeeded task, else ``None``.

    The task WebSocket delivers a result already parsed by ``JSON.parse`` (integers
    above 2**53 are rounded); this is the exact, losslessly-parseable copy.
    """
    if record.status is not TaskStatus.SUCCEEDED:
        return None
    spec = next((a for a in record.artifacts if a.name == f"{record.kind}_result"
                 and a.media_type == "application/json"), None)
    if spec is None:
        return None
    try:
        path = mgr.artifact_store._resolve(record.task_id, spec.relpath, require_file=True)
        return json.loads(path.read_text(encoding="utf-8"))
    except (ArtifactStoreError, OSError, ValueError):
        logger.warning("task %s: result artifact unreadable", record.task_id)
        return None


@router.get("/{task_id}/result")
def get_task_result(task_id: str):
    """The task record once terminal (``result``), plus ``payload``: the job's full
    result document for a succeeded job that stored one (``vol3`` runs)."""
    mgr = _manager_or_503()
    record = mgr.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    return {
        "task_id": task_id,
        "status": record.status.value,
        "result": record.to_dict() if record.status in TERMINAL_STATUSES else None,
        "payload": _result_payload(mgr, record),
    }


@router.delete("/{task_id}")
def cancel_task(task_id: str):
    """Cooperative cancel. Returns 404 if unknown, 409 if already terminal."""
    mgr = _manager_or_503()
    record = mgr.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    if record.status in TERMINAL_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"task already in terminal state: {record.status.value}",
        )
    ok = mgr.cancel(task_id)
    return {"task_id": task_id, "cancelled": ok}
