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
* ``GET  /api/vol3/plugin-dir``   — the installed ``memdiver/vol3plugins`` (``vol -p``).
* ``POST /api/vol3/synthesize``   — located key -> standalone plugin, verified by its
  oracle (``synthesize_vol3_plugin``). The key to synthesize for arrives as
  ``secret_hex`` (and the full image's ground truth as ``full_image_secret_hex``);
  ``key_hex`` / ``passphrase`` / ``kem_key_hex`` decrypt an encrypted ``.msl``
  (see ``api.models.KeyMaterialFields``). No key is echoed. ``case_dir`` must be
  an EXISTING case. At most 16 dumps, and a full-image run must fit a 3600 s
  worst-case vol budget (``app.vol3_surface_limits``). INLINE without
  ``full_image`` and ``async``; with either it is a JOB (kind ``vol3_synth``)
  answering ``{"task_id", "status"}``. Before the job exists the router runs
  the request bounds, the key-material decode, the case resolution and the
  producer's own pre-flight (``preflight_synthesize_vol3_plugin``: oracle,
  verify targets, the vol launcher, image / sample paths, ``;`` in paths, key
  form, hex and per-dump lengths, a hit's shape, then the dumps: each must
  exist and an encrypted ``.msl``'s key is probed on block 0 -- one key
  derivation, no dump opened or decrypted on the request thread), so a bad
  request is the same 4xx as inline. Only a ciphertext tampered beyond block 0
  and a hit outside its dump need the full read: those are a 202 whose job
  fails with the inline ``code`` on its ``error`` event; progress
  streams over ``/ws/tasks/{task_id}``, ``DELETE /api/tasks/{id}`` cancels it
  (killing a running vol), and the payload -- what the inline call returns -- is
  the ``vol3_synth_result`` artifact (``GET /api/tasks/{id}/result``).
* ``POST /api/vol3/exec``         — run a plugin by NAME under stock ``vol`` (a
  subprocess; ``vol3_exec_result``). Synchronous within ``timeout_s`` (<= 900).
  vol GLOBAL options in ``args`` are refused; plugin-specific path arguments are
  NOT checked against the read sandbox.

``source_name`` + ``case_dir`` stand in for raw ``source`` on describe/run/check.

SECURITY: a user plugin (``source``) runs UNSANDBOXED, in-process, with the server's
privileges (D7). The server is meant to be bound to 127.0.0.1; the SHA-256 of every
executed source is logged. Reads (``view_path``, ``case_dir``, ``path``) go through
the opt-in read sandbox; every path the server WRITES (``out_path``, ``out_dir``,
``case_dir`` of run/annotate/import) is contained like the case router's.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter
from pydantic import Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.models import KeyMaterialFields
from memdiver.api.routers._common import StrictModel, submit_job
from memdiver.api.routers.image import _case_target, _contained
from memdiver.api.services.key_material import decode_key_material
from memdiver.app.vol3_surface_limits import (
    MAX_EXEC_TIMEOUT_S,
    SYNTH_MAX_DUMPS,
    check_synth_request,
)
from memdiver.app import (
    tools_case,
    tools_pipeline,
    tools_vol3,
    tools_vol3_dev,
    tools_vol3_fixtures,
    tools_vol3_sources,
)

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.vol3_task_runner.run_vol3_job"
_SYNTH_RUNNER = "memdiver.app.pipeline.vol3_synth_task_runner.run_synth_job"
#: Job kind of a background synthesis; its artifact is ``vol3_synth_result``.
SYNTH_JOB_KIND = "vol3_synth"
#: A run within both bounds is answered inline; beyond either it becomes a job.
SYNC_MAX_TIMEOUT_S = 30.0
SYNC_MAX_LIMIT = 10_000


class DescribeRequest(StrictModel):
    plugin: str = ""
    source: Optional[str] = None
    source_name: Optional[str] = None
    case_dir: Optional[str] = None


class RunRequest(StrictModel):
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


class QueryRequest(StrictModel):
    case_dir: str
    sql: Optional[str] = None
    saved: Optional[str] = None
    params: List[Any] = Field(default_factory=list)
    limit: int = tools_case.DEFAULT_QUERY_LIMIT


class AnnotateRequest(StrictModel):
    case_dir: str
    table: str
    run_id: str
    column: str
    rows: Optional[List[int]] = None
    label_column: Optional[str] = None
    author: str = "tool:vol3"


class ScaffoldRequest(StrictModel):
    name: str
    os_family: str = "linux"
    description: str = ""
    per_process: bool = True


class CheckRequest(StrictModel):
    source: Optional[str] = None
    source_name: Optional[str] = None
    case_dir: Optional[str] = None
    view_path: Optional[str] = None


class SourcePutRequest(StrictModel):
    case_dir: str
    source: str
    view_path: Optional[str] = None


class FixturePutRequest(StrictModel):
    case_dir: str
    view_path: str
    expect: List[Dict[str, Any]]
    plugin: str = ""
    source_name: Optional[str] = None
    args: Dict[str, Any] = Field(default_factory=dict)


class FixtureRunRequest(StrictModel):
    case_dir: str
    view_path: Optional[str] = None
    limit: int = tools_vol3_fixtures.DEFAULT_FIXTURE_ROWS
    timeout_s: float = tools_vol3_fixtures.DEFAULT_FIXTURE_TIMEOUT_S
    register_run: bool = False


class ImportRequest(StrictModel):
    case_dir: str
    path: str
    table: str
    capture_id: str
    image_sha256: Optional[str] = None
    locations: Optional[Dict[str, str]] = None
    format: str = "auto"


class WriteConfigRequest(StrictModel):
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
        return submit_job(task_manager_or_503(), "vol3", _RUNNER, {"args": kwargs})
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
        case_dir=_case_target(req.case_dir)).payload


def _case(case_dir: str) -> str:
    return _case_target(case_dir) or case_dir


@router.get("/sources")
def list_sources(case_dir: str):
    """Stored user plugin sources of a case (metadata only)."""
    return tools_vol3_sources.vol3_source_list_result(_case(case_dir)).payload


@router.get("/sources/{name}")
def get_source(name: str, case_dir: str, origin: Optional[str] = None):
    """One stored plugin source with its metadata (``origin`` picks a side on a name clash)."""
    return tools_vol3_sources.vol3_source_get_result(_case(case_dir), name, origin).payload


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


class SynthesizeRequest(StrictModel, KeyMaterialFields):
    """Body of ``POST /synthesize``: ``synthesize_vol3_plugin``'s parameters.

    ``secret_hex`` is the producer's ``key_hex`` (one for all dumps or one per
    dump) and ``full_image_secret_hex`` its ``full_image_key_hex``: the inherited
    ``key_hex`` keeps its container-decryption meaning (KeyMaterialFields).
    """

    dump_paths: List[str] = Field(min_length=1, max_length=SYNTH_MAX_DUMPS)
    name: str
    oracle_kind: str
    secret_hex: Union[str, List[str]] = ""
    hit: Optional[Dict[str, Any]] = None
    oracle_sample_path: Union[None, str, List[Optional[str]]] = None
    oracle_params: Optional[Dict[str, Any]] = None
    context: int = tools_pipeline.SYNTH_DEFAULT_CONTEXT
    case_dir: Optional[str] = None
    verify_on: List[str] = Field(default_factory=lambda: list(tools_pipeline.SYNTH_VERIFY_TARGETS))
    full_image: Optional[str] = None
    pid: Optional[int] = None
    full_image_sample: Optional[str] = None
    full_image_secret_hex: str = ""
    symbol_dirs: List[str] = Field(default_factory=list)
    vol_bin: Optional[str] = None
    vol_python: Optional[str] = None
    allow_high_entropy_context: bool = False
    async_: bool = Field(default=False, alias="async")


class ExecRequest(StrictModel):
    plugin: str
    image_path: str
    plugin_dirs: List[str] = Field(default_factory=list)
    symbol_dirs: List[str] = Field(default_factory=list)
    args: List[str] = Field(default_factory=list)
    include_memdiver_plugins: bool = True
    timeout_s: int = Field(default=tools_vol3_dev.DEFAULT_EXEC_TIMEOUT_S, ge=1,
                           le=MAX_EXEC_TIMEOUT_S)
    max_rows: int = tools_vol3_dev.DEFAULT_EXEC_MAX_ROWS
    vol_bin: Optional[str] = None
    vol_python: Optional[str] = None
    out_dir: Optional[str] = None


@router.get("/plugin-dir")
def plugin_dir():
    """The installed ``memdiver/vol3plugins`` directory, for ``vol -p``."""
    return tools_pipeline.vol3_plugin_dir()


def _synth_kwargs(req: SynthesizeRequest) -> Dict[str, Any]:
    """The producer's kwargs (no container key material), the case resolved.

    ``existing_case_dir`` refuses a missing case HERE, so a job is never
    submitted for a request that could only fail.
    """
    from memdiver.analysis.case import existing_case_dir

    return {"dump_paths": list(req.dump_paths), "name": req.name, "key_hex": req.secret_hex,
            "hit": req.hit, "oracle_kind": req.oracle_kind,
            "oracle_sample_path": req.oracle_sample_path, "oracle_params": req.oracle_params,
            "context": req.context, "case_dir": existing_case_dir(_case_target(req.case_dir)),
            "verify_on": tuple(req.verify_on), "full_image": req.full_image, "pid": req.pid,
            "vol_bin": req.vol_bin, "vol_python": req.vol_python,
            "allow_high_entropy_context": req.allow_high_entropy_context,
            "full_image_sample": req.full_image_sample,
            "full_image_key_hex": req.full_image_secret_hex,
            "symbol_dirs": list(req.symbol_dirs)}


def _is_synth_job(req: SynthesizeRequest) -> bool:
    """A full-image run (minutes of vol) or an explicit ``async`` is a job."""
    return req.async_ or bool(req.full_image)


@router.post("/synthesize")
def synthesize_plugin(req: SynthesizeRequest):
    """A key located in N dumps -> a standalone vol3 plugin, RUN and judged by ``Proven``.

    Inline, or a job for ``async: true`` / a ``full_image`` (see the module
    docstring). ``case_dir`` (name or path) must be an existing case; a path is
    contained like every case write. The key never reaches the response, and a
    job's persisted record has every secret redacted (``TaskManager.submit``).
    """
    check_synth_request(req.dump_paths, req.full_image, req.full_image_sample)
    wire_km = {"passphrase": req.passphrase, "key_hex": req.key_hex,
               "kem_key_hex": req.kem_key_hex}
    km = decode_key_material(**wire_km) or {}  # malformed hex: a 400 now, not a failed job
    kwargs = _synth_kwargs(req)
    if _is_synth_job(req):
        tools_pipeline.preflight_synthesize_vol3_plugin(**kwargs, key_material=km)
        return submit_job(task_manager_or_503(), SYNTH_JOB_KIND, _SYNTH_RUNNER,
                          {"kwargs": kwargs, "key_material_hex": wire_km})
    return tools_pipeline.synthesize_vol3_plugin(**kwargs, key_material=km)


@router.post("/exec")
def exec_plugin(req: ExecRequest):
    """Run a plugin by NAME under the stock ``vol`` launcher; a failing plugin is ``ok: false``."""
    return tools_vol3_dev.vol3_exec_result(
        req.plugin, req.image_path, plugin_dirs=req.plugin_dirs,
        symbol_dirs=req.symbol_dirs, args=req.args,
        include_memdiver_plugins=req.include_memdiver_plugins, timeout_s=req.timeout_s,
        max_rows=req.max_rows, vol_bin=req.vol_bin, vol_python=req.vol_python,
        out_dir=_contained(req.out_dir)).payload
