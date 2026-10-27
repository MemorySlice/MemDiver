"""ISF workbench router — pakunoda probes, ISF drafts, the try-loop (``isf.*``).

The web face of :mod:`memdiver.app.tools_isf`:

* ``POST /api/isf/probe`` — run one pakunoda probe on a full image (optionally feeding a
  draft). Inline by default; ``async: true`` submits an ``image`` JOB (kallsyms on a
  multi-GB image can take over a minute) and returns ``{"task_id", "status"}``.
* ``POST /api/isf/try`` — try a draft or an ISF file against the image with a Volatility
  plugin (inline, or the same ``async`` job).
* ``POST /api/isf/drafts`` — create a draft; ``GET /api/isf/drafts`` — list a capture's
  drafts; ``GET /api/isf/drafts/{name}`` (+ ``/versions``) — read one.
* ``POST /api/isf/drafts/{name}/{set,import,retract,diff,validate,export}`` — edit,
  compare, validate and export a draft.

Jobs reuse the image router's runner (``app.pipeline.image_task_runner``): progress over
``/ws/tasks/{task_id}``, the producer payload as the ``image_result`` artifact. Read paths
(``image_path``, ``isf_path``, ``against_isf``, ``ground_truth``, ``type_hints_isf``) go
through the opt-in read sandbox; every path the server WRITES (``case_dir`` of a write,
``out_path``) is contained like the case router's.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import Field

from memdiver.api.routers._common import StrictModel
from memdiver.api.routers.image import _case_target, _contained, _submit
from memdiver.app import tools_isf
from memdiver.app.tools_code_evidence import code_evidence_result
from memdiver.app.tools_isf import DEFAULT_AUTHOR, DEFAULT_LIMIT

router = APIRouter()


class ProbeRequest(StrictModel):
    image_path: str
    probe: str
    arch: str = "auto"
    params: Optional[Dict[str, Any]] = None
    case_dir: Optional[str] = None
    draft: Optional[str] = None
    author: str = DEFAULT_AUTHOR
    async_: bool = Field(default=False, alias="async")


class TryRequest(StrictModel):
    image_path: str
    case_dir: Optional[str] = None
    draft: Optional[str] = None
    version: Optional[str] = None
    isf_path: Optional[str] = None
    plugin: str = "linux.pslist"
    ground_truth: Optional[str] = None
    timeout_s: float = 120.0
    min_recall: float = 0.95
    min_precision: float = 0.95
    author: str = "agent"
    async_: bool = Field(default=False, alias="async")


class CodeEvidenceRequest(StrictModel):
    image_path: str
    function: str
    arch: Optional[str] = None
    max_bytes: int = 4096
    isf: Optional[str] = None
    base: Optional[str] = None
    async_: bool = Field(default=False, alias="async")


class CreateRequest(StrictModel):
    case_dir: str
    capture_id: str
    name: str
    arch: str
    author: str = "human"
    banner: Optional[str] = None
    base_metadata: Optional[Dict[str, Any]] = None


class _DraftRef(StrictModel):
    case_dir: str
    capture_id: str


class SetRequest(_DraftRef):
    op: str
    args: Dict[str, Any] = Field(default_factory=dict)
    source: str = "manual"
    tier: str = "manual"
    evidence: List[str] = Field(default_factory=list)
    author: str = "human"
    witnesses: int = 1


class ImportRequest(_DraftRef):
    isf_path: str
    only: Optional[Dict[str, List[str]]] = None
    source: str = "isf_import"
    tier: str = "imported"
    evidence: List[str] = Field(default_factory=list)
    author: str = "human"


class RetractRequest(_DraftRef):
    entry_id: str
    author: str = "human"
    reason: str = ""


class DiffRequest(_DraftRef):
    against_version: Optional[str] = None
    against_isf: Optional[str] = None
    only: Optional[Dict[str, List[str]]] = None
    limit: int = DEFAULT_LIMIT


class ValidateRequest(_DraftRef):
    check_schema: bool = False
    limit: int = DEFAULT_LIMIT


class ExportRequest(_DraftRef):
    version: Optional[str] = None
    out_path: Optional[str] = None


def _job_or_inline(job: str, async_: bool, args: Dict[str, Any], producer):
    """Inline payload, or the image-job handle when ``async_``."""
    if async_:
        return _submit(job, args)
    return producer(**args).payload


def _write_case(case_dir: Optional[str]) -> Optional[str]:
    """Every ISF route, read or write, files a case the same way image/yara do: a bare
    name stays a name (``cases_root()/<name>``), a path must lie inside a write root."""
    return _case_target(case_dir)


def _parse_only(only: Optional[str]) -> Optional[Dict[str, List[str]]]:
    """``only`` arrives as a JSON object in a query string."""
    if only is None:
        return None
    try:
        parsed = json.loads(only)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"only is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="only must be a JSON object")
    return parsed


@router.post("/probe")
def probe(req: ProbeRequest):
    """Run one probe inline, or as a job with ``async: true``."""
    args = {"image_path": req.image_path, "probe": req.probe, "arch": req.arch,
            "params": req.params, "case_dir": _write_case(req.case_dir),
            "draft": req.draft, "author": req.author}
    return _job_or_inline("isf_probe", req.async_, args, tools_isf.isf_probe_result)


@router.post("/try")
def try_isf(req: TryRequest):
    """Try a draft / ISF file on the image, inline or as a job with ``async: true``."""
    args = {"image_path": req.image_path, "case_dir": _write_case(req.case_dir),
            "draft": req.draft, "version": req.version, "isf_path": req.isf_path,
            "plugin": req.plugin, "ground_truth": req.ground_truth,
            "timeout_s": req.timeout_s, "min_recall": req.min_recall,
            "min_precision": req.min_precision, "author": req.author}
    return _job_or_inline("isf_try", req.async_, args, tools_isf.isf_try_result)


@router.post("/code-evidence")
def code_evidence(req: CodeEvidenceRequest):
    """Struct fields a kernel function touches (code evidence), inline or as a job with
    ``async: true`` (session setup on a multi-GB image takes ~35 s)."""
    args = {"image_path": req.image_path, "function": req.function, "arch": req.arch,
            "max_bytes": req.max_bytes, "base": req.base,
            "params": {"isf": req.isf} if req.isf else None}
    return _job_or_inline("code_evidence", req.async_, args,
                          code_evidence_result)


@router.post("/drafts")
def create_draft(req: CreateRequest):
    """Create an empty draft (its first, ``created`` entry)."""
    return tools_isf.isf_draft_create_result(
        _write_case(req.case_dir), req.capture_id, req.name, req.arch,
        author=req.author, banner=req.banner, base_metadata=req.base_metadata).payload


@router.get("/drafts")
def list_drafts(case_dir: str, capture_id: str):
    """The drafts of one capture."""
    return tools_isf.isf_draft_list_result(_write_case(case_dir), capture_id).payload


@router.get("/drafts/{name}")
def get_draft(name: str, case_dir: str, capture_id: str, version: Optional[str] = None,
              only: Optional[str] = None, include_origins: bool = False,
              limit: int = DEFAULT_LIMIT, search: Optional[str] = None, offset: int = 0):
    """Materialized summary; ``only`` is a JSON ``{section: [names]}`` for item rows;
    ``search`` (name substring) and ``offset``/``limit`` page each section."""
    return tools_isf.isf_draft_get_result(
        _write_case(case_dir), capture_id, name, only=_parse_only(only), version=version,
        include_origins=include_origins, limit=limit, search=search,
        offset=offset).payload


@router.get("/drafts/{name}/versions")
def draft_versions(name: str, case_dir: str, capture_id: str, limit: int = DEFAULT_LIMIT):
    """The version history of a draft."""
    return tools_isf.isf_draft_versions_result(_write_case(case_dir), capture_id, name, limit=limit).payload


@router.post("/drafts/{name}/set")
def set_draft(name: str, req: SetRequest):
    """One draft operation (symbol|struct|field|base_type|enum|remove)."""
    return tools_isf.isf_draft_set_result(
        _write_case(req.case_dir), req.capture_id, name, req.op, req.args,
        source=req.source, tier=req.tier, evidence=req.evidence, author=req.author,
        witnesses=req.witnesses).payload


@router.post("/drafts/{name}/import")
def import_draft(name: str, req: ImportRequest):
    """Import (a subset of) an ISF file into the draft."""
    return tools_isf.isf_draft_import_result(
        _write_case(req.case_dir), req.capture_id, name, req.isf_path, only=req.only,
        source=req.source, tier=req.tier, evidence=req.evidence, author=req.author).payload


@router.post("/drafts/{name}/retract")
def retract_draft_entry(name: str, req: RetractRequest):
    """Retract one entry of the draft (the history keeps it)."""
    return tools_isf.isf_draft_retract_result(
        _write_case(req.case_dir), req.capture_id, name, req.entry_id,
        author=req.author, reason=req.reason).payload


@router.post("/drafts/{name}/diff")
def diff_draft(name: str, req: DiffRequest):
    """Draft vs an earlier version or an ISF file."""
    return tools_isf.isf_draft_diff_result(
        _write_case(req.case_dir), req.capture_id, name, against_version=req.against_version,
        against_isf=req.against_isf, only=req.only, limit=req.limit).payload


@router.post("/drafts/{name}/validate")
def validate_draft(name: str, req: ValidateRequest):
    """Validate the draft and report Volatility plugin readiness."""
    return tools_isf.isf_draft_validate_result(
        _write_case(req.case_dir), req.capture_id, name, check_schema=req.check_schema,
        limit=req.limit).payload


@router.post("/drafts/{name}/export")
def export_draft(name: str, req: ExportRequest):
    """Write the draft as an ISF file (default: inside the case)."""
    return tools_isf.isf_draft_export_result(
        _write_case(req.case_dir), req.capture_id, name, version=req.version,
        out_path=_contained(req.out_path)).payload
