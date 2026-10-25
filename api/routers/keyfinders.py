"""Key-finder router — recognise key material by structure (``keyfinders.*`` capabilities).

The web face of :mod:`memdiver.app.tools_keyfinders`:

* ``GET  /api/keyfinders``      — the key finders and the ``params`` each reads.
* ``POST /api/keyfinders/scan`` — scan the CAPTURED bytes of a dump. SYNCHRONOUS while
  the bytes to read stay within ``SYNC_MAX_BYTES``; a bigger scan, or ``async: true``,
  submits a JOB and returns ``{"task_id", "status"}``. Progress streams over
  ``/ws/tasks/{task_id}``; the payload is the ``keyfinders_result`` artifact.

Reads (``dump_path``, ``case_dir``) go through the opt-in read sandbox; the paths the
server WRITES (``case_dir``, ``candidates_out``) are contained like the case router's.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers.image import _case_target, _contained
from memdiver.app import tools_keyfinders

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.keyfinders_task_runner.run_keyfinders_job"
#: A scan reading at most this many captured bytes is answered inline.
SYNC_MAX_BYTES = 64 * 1024 * 1024


class _Strict(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


class ScanRequest(_Strict):
    dump_path: str
    finders: List[str] = Field(default_factory=lambda: list(tools_keyfinders.DEFAULT_FINDERS))
    view: Optional[str] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    heap_policy: str = "annotate"
    params: Dict[str, Any] = Field(default_factory=dict)
    case_dir: Optional[str] = None
    limit: int = tools_keyfinders.DEFAULT_LIMIT
    candidates_out: Optional[str] = None
    annotate: bool = True
    async_: bool = Field(default=False, alias="async")


def _scan_kwargs(req: ScanRequest) -> Dict[str, Any]:
    return {"dump_path": req.dump_path, "finders": tuple(req.finders), "view": req.view,
            "offset": req.offset, "length": req.length, "heap_policy": req.heap_policy,
            "params": req.params, "case_dir": _case_target(req.case_dir),
            "limit": req.limit, "candidates_out": _contained(req.candidates_out),
            "annotate": req.annotate}


def _is_long_scan(req: ScanRequest) -> bool:
    return req.async_ or tools_keyfinders._scan_size(
        req.dump_path, req.view, req.offset, req.length) > SYNC_MAX_BYTES


def _submit_scan(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    manager = task_manager_or_503()
    record = manager.submit(
        kind="keyfinders",
        params={"args": kwargs, "task_root": str(manager.artifact_store.root)},
        runner_dotted=_RUNNER, stage_names=["keyfinders"])
    return {"task_id": record.task_id, "status": record.status.value}


@router.get("")
def list_finders():
    """The key finders and their parameters."""
    return tools_keyfinders.keyfinders_list_result().payload


@router.post("/scan")
def scan_dump(req: ScanRequest):
    """Scan inline, or as a job for a large capture / ``async: true``."""
    kwargs = _scan_kwargs(req)
    if _is_long_scan(req):
        return _submit_scan(kwargs)
    return tools_keyfinders.keyfinders_scan_result(**kwargs).payload
