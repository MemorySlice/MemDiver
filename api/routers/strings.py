"""Strings-table router — every string of the captured bytes (``strings.table``).

The web face of :mod:`memdiver.app.tools_strings`:

* ``POST /api/strings/table`` — SYNCHRONOUS while the bytes to read stay within
  ``SYNC_MAX_BYTES``; a bigger scan, or ``async: true``, submits a JOB and returns
  ``{"task_id", "status"}``. Progress streams over ``/ws/tasks/{task_id}``; the
  payload is the ``strings_result`` artifact.

Reads (``dump_path``, ``case_dir``) go through the opt-in read sandbox; the
``case_dir`` the server WRITES is contained like the case router's.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers._common import SYNC_MAX_BYTES, StrictModel, submit_job
from memdiver.api.routers.image import _case_target
from memdiver.app import tools_strings

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.strings_task_runner.run_strings_job"


class TableRequest(StrictModel):
    dump_path: str
    view: Optional[str] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    min_len: int = tools_strings.DEFAULT_MIN_LEN
    encodings: List[str] = Field(default_factory=lambda: list(tools_strings.DEFAULT_ENCODINGS))
    limit: int = tools_strings.DEFAULT_LIMIT
    case_dir: Optional[str] = None
    async_: bool = Field(default=False, alias="async")


def _region(req: TableRequest):
    return tools_strings._region_of(req.offset, req.length)


def _table_kwargs(req: TableRequest) -> Dict[str, Any]:
    return {"dump_path": req.dump_path, "view": req.view, "region": _region(req),
            "min_len": req.min_len, "encodings": tuple(req.encodings),
            "limit": req.limit, "case_dir": _case_target(req.case_dir)}


def _is_long_scan(req: TableRequest) -> bool:
    return req.async_ or tools_strings._scan_size(
        req.dump_path, req.view, _region(req)) > SYNC_MAX_BYTES


@router.post("/table")
def strings_table(req: TableRequest):
    """Extract inline, or as a job for a large capture / ``async: true``."""
    kwargs = _table_kwargs(req)
    if _is_long_scan(req):
        return submit_job(task_manager_or_503(), "strings", _RUNNER, {"args": kwargs})
    return tools_strings.strings_table_result(**kwargs).payload
