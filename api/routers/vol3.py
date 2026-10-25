"""Vol3 router — Volatility 3 plugins over ``.mdview`` views (``vol3.*`` capabilities).

The web face of :mod:`memdiver.app.tools_vol3` and :mod:`memdiver.app.tools_vol3_dev`:

* ``GET  /api/vol3/plugins``      — bundled plugins of an OS family.
* ``POST /api/vol3/describe``     — a plugin's user requirements (name or ``source``).
* ``POST /api/vol3/run``          — run a plugin over a view. SYNCHRONOUS while
  ``timeout_s`` <= 30 and ``limit`` <= 10000 (the defaults); a longer budget, or
  ``async: true``, submits a JOB and returns ``{"task_id", "status"}``. Progress
  streams over ``/ws/tasks/{task_id}``; the payload is the ``vol3_result`` artifact.
* ``POST /api/vol3/query``        — SQL or a saved query over a case; neither lists
  the saved queries.
* ``POST /api/vol3/annotate``     — file ``plugin_row`` entries for a registered run.
* ``POST /api/vol3/scaffold``     — source text of a new plugin.
* ``POST /api/vol3/check``        — load plugin ``source`` (and test it against a view).
* ``POST /api/vol3/import``       — register an external vol3 output file as a case table.
* ``POST /api/vol3/write-config`` — write a ``config.json`` reproducing a view's stack.
* ``GET  /api/vol3/sources``      — stored user plugin sources of a case.
* ``GET  /api/vol3/sources/{name}`` — one stored source.
* ``PUT  /api/vol3/sources/{name}`` — store a source in the case and return its check.
* ``GET  /api/vol3/fixtures``     — stored plugin fixtures of a case.
* ``PUT  /api/vol3/fixtures/{name}`` — store a fixture (plugin/source, view, predicates).
* ``POST /api/vol3/fixtures/{name}/run`` — run it; verdict pass|fail|indeterminate.

``source_name`` + ``case_dir`` stand in for raw ``source`` on describe/run/check.

SECURITY: a user plugin (``source``) runs UNSANDBOXED, in-process, with the server's
privileges (D7). The server is meant to be bound to 127.0.0.1; the SHA-256 of every
executed source is logged. Reads (``view_path``, ``case_dir``, ``path``) go through
the opt-in read sandbox; every path the server WRITES (``out_path``, ``out_dir``,
``case_dir`` of run/annotate/import) is contained like the case router's.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers.image import _case_target, _contained
from memdiver.app import (
    tools_case,
    tools_vol3,
    tools_vol3_dev,
    tools_vol3_fixtures,
    tools_vol3_sources,
)

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.vol3_task_runner.run_vol3_job"
#: A run within both bounds is answered inline; beyond either it becomes a job.
SYNC_MAX_TIMEOUT_S = 30.0
SYNC_MAX_LIMIT = 10_000


class _Strict(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


class DescribeRequest(_Strict):
    plugin: str = ""
    source: Optional[str] = None
    source_name: Optional[str] = None
    case_dir: Optional[str] = None


class RunRequest(_Strict):
    view_path: str
    plugin: str = ""
    args: Dict[str, Any] = Field(default_factory=dict)
    case_dir: Optional[str] = None
    limit: int = SYNC_MAX_LIMIT
    timeout_s: float = SYNC_MAX_TIMEOUT_S
    max_rows: int = tools_vol3.DEFAULT_MAX_ROWS
    column_map: Optional[Dict[str, Optional[str]]] = None
    source: Optional[str] = None
    source_name: Optional[str] = None
    out_dir: Optional[str] = None
    async_: bool = Field(default=False, alias="async")


class QueryRequest(_Strict):
    case_dir: str
    sql: Optional[str] = None
    saved: Optional[str] = None
    params: List[Any] = Field(default_factory=list)
    limit: int = tools_case.DEFAULT_QUERY_LIMIT


class AnnotateRequest(_Strict):
    case_dir: str
    table: str
    run_id: str
    column: str
    rows: Optional[List[int]] = None
    label_column: Optional[str] = None
    author: str = "tool:vol3"


class ScaffoldRequest(_Strict):
    name: str
    os_family: str = "linux"
    description: str = ""
    per_process: bool = True


class CheckRequest(_Strict):
    source: Optional[str] = None
    source_name: Optional[str] = None
    case_dir: Optional[str] = None
    view_path: Optional[str] = None


class SourcePutRequest(_Strict):
    case_dir: str
    source: str
    view_path: Optional[str] = None


class FixturePutRequest(_Strict):
    case_dir: str
    view_path: str
    expect: List[Dict[str, Any]]
    plugin: str = ""
    source_name: Optional[str] = None
    args: Dict[str, Any] = Field(default_factory=dict)


class FixtureRunRequest(_Strict):
    case_dir: str
    view_path: Optional[str] = None
    limit: int = tools_vol3_fixtures.DEFAULT_FIXTURE_ROWS
    timeout_s: float = tools_vol3_fixtures.DEFAULT_FIXTURE_TIMEOUT_S
    register_run: bool = False


class ImportRequest(_Strict):
    case_dir: str
    path: str
    table: str
    capture_id: str
    image_sha256: Optional[str] = None
    locations: Optional[Dict[str, str]] = None
    format: str = "auto"


class WriteConfigRequest(_Strict):
    view_path: str
    out_path: str
    plugin: str = "linux.pslist.PsList"
    source: Optional[str] = None
    source_name: Optional[str] = None
    case_dir: Optional[str] = None


def _run_kwargs(req: RunRequest) -> Dict[str, Any]:
    return {"view_path": req.view_path, "plugin": req.plugin, "args": req.args,
            "case_dir": _case_target(req.case_dir), "limit": req.limit,
            "timeout_s": req.timeout_s, "max_rows": req.max_rows,
            "column_map": req.column_map, "source": req.source,
            "source_name": req.source_name, "out_dir": _contained(req.out_dir)}


def _is_long_run(req: RunRequest) -> bool:
    return (req.async_ or req.timeout_s > SYNC_MAX_TIMEOUT_S
            or req.limit > SYNC_MAX_LIMIT)


def _submit_run(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    manager = task_manager_or_503()
    record = manager.submit(
        kind="vol3", params={"args": kwargs, "task_root": str(manager.artifact_store.root)},
        runner_dotted=_RUNNER, stage_names=["vol3"])
    return {"task_id": record.task_id, "status": record.status.value}


@router.get("/plugins")
def list_plugins(os_family: str = "linux"):
    """The bundled plugins of one OS family."""
    return tools_vol3.vol3_plugins_result(os_family).payload


@router.post("/describe")
def describe_plugin(req: DescribeRequest):
    """A plugin's user requirements."""
    return tools_vol3.vol3_describe_result(
        req.plugin, req.source, source_name=req.source_name, case_dir=req.case_dir).payload


@router.post("/run")
def run_plugin(req: RunRequest):
    """Run a plugin inline, or as a job for a long budget / ``async: true``."""
    kwargs = _run_kwargs(req)
    if _is_long_run(req):
        return _submit_run(kwargs)
    return tools_vol3.vol3_run_result(**kwargs).payload


@router.post("/query")
def query_case(req: QueryRequest):
    """SQL or a saved query over a case; neither lists the saved queries."""
    return tools_vol3.vol3_query_result(
        req.case_dir, req.sql, req.saved, req.params, req.limit).payload


@router.post("/annotate")
def annotate_run(req: AnnotateRequest):
    """File one ``plugin_row`` entry per row of a registered run."""
    return tools_vol3.vol3_annotate_result(
        _case_target(req.case_dir) or req.case_dir, req.table, req.run_id, req.column,
        rows=req.rows, label_column=req.label_column, author=req.author).payload


@router.post("/scaffold")
def scaffold_plugin(req: ScaffoldRequest):
    """Source text of a new plugin."""
    return tools_vol3_dev.vol3_scaffold_result(
        req.name, os_family=req.os_family, description=req.description,
        per_process=req.per_process).payload


@router.post("/check")
def check_plugin(req: CheckRequest):
    """Load plugin source and report its description or a structured failure."""
    return tools_vol3_dev.vol3_check_result(
        req.source, req.view_path, source_name=req.source_name, case_dir=req.case_dir).payload


@router.post("/import")
def import_table(req: ImportRequest):
    """Register an external vol3 output file as a case table."""
    return tools_vol3_dev.vol3_import_parquet_result(
        _case_target(req.case_dir) or req.case_dir, req.path, table=req.table,
        capture_id=req.capture_id, image_sha256=req.image_sha256,
        locations=req.locations, format=req.format).payload


@router.post("/write-config")
def write_config(req: WriteConfigRequest):
    """Write a ``config.json`` reproducing the view's stack for a plugin."""
    return tools_vol3_dev.vol3_write_config_result(
        req.view_path, _contained(req.out_path) or req.out_path, req.plugin,
        source=req.source, source_name=req.source_name,
        case_dir=_case_target(req.case_dir) if req.case_dir else None).payload


def _case(case_dir: str) -> str:
    return _case_target(case_dir) or case_dir


@router.get("/sources")
def list_sources(case_dir: str):
    """Stored user plugin sources of a case (metadata only)."""
    return tools_vol3_sources.vol3_source_list_result(_case(case_dir)).payload


@router.get("/sources/{name}")
def get_source(name: str, case_dir: str):
    """One stored plugin source with its metadata."""
    return tools_vol3_sources.vol3_source_get_result(_case(case_dir), name).payload


@router.put("/sources/{name}")
def put_source(name: str, req: SourcePutRequest):
    """Store plugin source in the case, then check it (the check runs the source's module code)."""
    return tools_vol3_sources.vol3_source_put_result(
        _case(req.case_dir), name, req.source, req.view_path).payload


@router.get("/fixtures")
def list_fixtures(case_dir: str):
    """Stored plugin fixtures of a case."""
    return tools_vol3_fixtures.vol3_fixture_list_result(_case(case_dir)).payload


@router.put("/fixtures/{name}")
def put_fixture(name: str, req: FixturePutRequest):
    """Store a plugin fixture (validated predicates; an overwrite keeps the old one)."""
    return tools_vol3_fixtures.vol3_fixture_put_result(
        _case(req.case_dir), name, view_path=req.view_path, expect=req.expect,
        plugin=req.plugin, source_name=req.source_name, args=req.args).payload


@router.post("/fixtures/{name}/run")
def run_fixture(name: str, req: FixtureRunRequest):
    """Run a fixture inline; the verdict is filed in the analysis record."""
    return tools_vol3_fixtures.vol3_fixture_run_result(
        _case(req.case_dir), name, view_path=req.view_path, limit=req.limit,
        timeout_s=req.timeout_s, register_run=req.register_run).payload
