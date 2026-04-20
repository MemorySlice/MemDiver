"""Tasks router — thin HTTP surface for the TaskManager singleton."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from api.dependencies import task_manager_or_503 as _manager_or_503
from api.services.task_manager import TERMINAL_STATUSES

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


@router.get("/{task_id}/result")
def get_task_result(task_id: str):
    """Alias for ``GET /{task_id}`` retained for the old frontend contract."""
    mgr = _manager_or_503()
    record = mgr.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    return {
        "task_id": task_id,
        "status": record.status.value,
        "result": record.to_dict() if record.status in TERMINAL_STATUSES else None,
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
