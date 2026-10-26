"""Case router — the case data lake and ``locate_context``.

The web face of the ``case.*`` capabilities; every route is a thin adapter over
its shared producer in :mod:`memdiver.app.tools_case`:

* ``POST /api/case/init``       — create (or re-open) a case.
* ``GET  /api/case/status``     — manifest, tables, annotation captures.
* ``GET  /api/case/schema``     — columns and row counts per table.
* ``POST /api/case/query``      — one read-only SELECT (``case_dir`` is read-sandboxed).
* ``POST /api/case/context-at`` — what contains an address.
* ``POST /api/case/export``     — dump -> case tables (JOB; can take seconds on a
  multi-GB image). Returns ``{"task_id", "status"}``; the producer payload is the
  ``image_result`` artifact of the task (see :mod:`memdiver.api.routers.image`).

Reads go through the opt-in read-path sandbox (``case_dir`` is in
``READ_PATH_KEYS``). ``init`` WRITES, so its target is always contained (a bare
name resolves under ``~/.memdiver/cases``), like the annotations router.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.read_roots import sandbox_roots
from memdiver.api.routers.annotations import contained_case_dir
from memdiver.app import tools_case

router = APIRouter()


_RUNNER = "memdiver.app.pipeline.image_task_runner.run_image_job"


class _Strict(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


class InitRequest(_Strict):
    case: str


class QueryRequest(_Strict):
    case_dir: str
    sql: str
    limit: int = tools_case.DEFAULT_QUERY_LIMIT
    params: List[Any] = Field(default_factory=list)


class ContextAtRequest(_Strict):
    case_dir: str
    location: Dict[str, Any]
    length: int = 1
    dump_path: Optional[str] = None
    tables: Optional[List[str]] = None


class ExportRequest(_Strict):
    case_dir: str
    dump_path: str
    what: List[str] = Field(default_factory=lambda: ["auto"])
    run_id: Optional[str] = None


def _init_target(case: str) -> str:
    """A bare name stays a name (the producer files it under the cases root)."""
    bare = "/" not in case and "\\" not in case and not case.startswith((".", "~"))
    return case if bare else contained_case_dir(case)


@router.post("/init")
def init_case(req: InitRequest):
    """Create (or re-open) a case."""
    return tools_case.case_init_result(_init_target(req.case)).payload


@router.get("/status")
def case_status(case_dir: str):
    """Manifest, tables (runs and rows) and annotation captures."""
    return tools_case.case_status_result(case_dir).payload


@router.get("/manifest")
def case_manifest(case_dir: str):
    """Inventory of the case: views, images, captures, annotations, ISF, plugins, tables."""
    return tools_case.case_manifest_result(case_dir, read_roots=sandbox_roots()).payload


@router.get("/schema")
def case_schema(case_dir: str):
    """Columns, location mappings and row counts per table."""
    return tools_case.case_schema_result(case_dir).payload


@router.post("/query")
def case_query(req: QueryRequest):
    """Run one read-only SELECT over the case tables."""
    return tools_case.case_query_result(
        req.case_dir, req.sql, req.limit, req.params).payload


@router.post("/context-at")
def context_at(req: ContextAtRequest):
    """The containing stack of ``location``, outermost first."""
    return tools_case.context_at_result(
        req.case_dir, req.location, req.length, req.dump_path, req.tables).payload


@router.post("/export")
def export_case(req: ExportRequest):
    """Submit the job that exports a dump's tables into the case."""
    manager = task_manager_or_503()
    args = {"case_dir": contained_case_dir(req.case_dir), "dump_path": req.dump_path,
            "what": list(req.what), "run_id": req.run_id}
    record = manager.submit(
        kind="image", params={"job": "case_export", "args": args,
                              "task_root": str(manager.artifact_store.root)},
        runner_dotted=_RUNNER, stage_names=["image"])
    return {"task_id": record.task_id, "status": record.status.value}
