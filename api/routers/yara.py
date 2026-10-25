"""YARA editor router — check a rule, scan one dump's captured bytes (``yara.*``).

The web face of :mod:`memdiver.app.tools_yara`:

* ``POST /api/yara/check`` — compile a rule; a rule that does not compile is a 200 with
  ``valid: false`` and ``errors: [{line, message}]``.
* ``POST /api/yara/scan``  — scan the CAPTURED bytes of one dump (optionally a window of
  it) with the rule. ``coverage`` / ``truncated`` / ``complete`` qualify the rows.
  SYNCHRONOUS while the bytes to read stay within ``SYNC_MAX_BYTES``; a bigger scan, or
  ``async: true``, submits a JOB and returns ``{"task_id", "status"}``. Progress streams
  over ``/ws/tasks/{task_id}``; the result is ``GET /api/tasks/{id}/result``.
* ``GET /api/yara/rules`` · ``GET|PUT|DELETE /api/yara/rules/{name}`` — stored rules in the
  per-user library or a case (``scope``, ``case_dir``); check and scan accept ``rule_name``
  (+ ``case_dir``) in place of ``rule_source``.

Distinct from ``/api/scan/yara`` (a corpus census over N dumps with no window, no capture
gaps and no virtual addresses). Reads (``dump_path``) go through the opt-in read sandbox;
a case rule WRITE (``case_dir``) is contained like the case router's. The library lives in
the MemDiver home, so it takes no client path.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers.image import _case_target
from memdiver.app import tools_keyfinders, tools_yara, tools_yara_rules

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.yara_task_runner.run_yara_job"
#: A scan reading at most this many captured bytes is answered inline.
SYNC_MAX_BYTES = 64 * 1024 * 1024


class _Strict(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


class CheckRequest(_Strict):
    rule_source: Optional[str] = None
    rule_name: Optional[str] = None
    case_dir: Optional[str] = None


class ScanRequest(_Strict):
    dump_path: str
    rule_source: Optional[str] = None
    rule_name: Optional[str] = None
    case_dir: Optional[str] = None
    view: Optional[str] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    limit: int = tools_yara.DEFAULT_LIMIT
    timeout_s: int = tools_yara.DEFAULT_TIMEOUT_S
    async_: bool = Field(default=False, alias="async")


@router.post("/check")
def check_rule(req: CheckRequest):
    """Compile the rule and report its names, or the failing line."""
    return tools_yara.yara_check_result(
        req.rule_source, req.rule_name, _case_target(req.case_dir)).payload


def _scan_kwargs(req: ScanRequest) -> Dict[str, Any]:
    return {"dump_path": req.dump_path, "rule_source": req.rule_source, "view": req.view,
            "offset": req.offset, "length": req.length, "limit": req.limit,
            "timeout_s": req.timeout_s, "rule_name": req.rule_name,
            "case_dir": _case_target(req.case_dir)}


def _is_long_scan(req: ScanRequest) -> bool:
    return req.async_ or tools_keyfinders._scan_size(
        req.dump_path, req.view, req.offset, req.length) > SYNC_MAX_BYTES


def _submit_scan(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    manager = task_manager_or_503()
    record = manager.submit(
        kind="yara",
        params={"args": kwargs, "task_root": str(manager.artifact_store.root)},
        runner_dotted=_RUNNER, stage_names=["yara"])
    return {"task_id": record.task_id, "status": record.status.value}


@router.post("/scan")
def scan_dump(req: ScanRequest):
    """Scan inline, or as a job for a large capture / ``async: true``."""
    kwargs = _scan_kwargs(req)
    if _is_long_scan(req):
        return _submit_scan(kwargs)
    return tools_yara.yara_scan_dump_result(**kwargs).payload


class RulePutRequest(_Strict):
    rule_source: str
    scope: Optional[str] = None
    case_dir: Optional[str] = None


@router.get("/rules")
def list_rules(case_dir: Optional[str] = None):
    """Stored rules of the library and, with ``case_dir``, of the case (metadata only)."""
    return tools_yara_rules.yara_rule_list_result(_case_target(case_dir)).payload


@router.get("/rules/{name}")
def get_rule(name: str, case_dir: Optional[str] = None, scope: Optional[str] = None):
    """One stored rule; ``scope`` library|case|auto (default auto: the case wins)."""
    return tools_yara_rules.yara_rule_get_result(
        name, _case_target(case_dir), scope).payload


@router.put("/rules/{name}")
def put_rule(name: str, req: RulePutRequest):
    """Store a rule in the library or a case, then compile-check it (a bad draft is saved)."""
    return tools_yara_rules.yara_rule_put_result(
        name, req.rule_source, req.scope, _case_target(req.case_dir)).payload


@router.delete("/rules/{name}")
def delete_rule(name: str, scope: Optional[str] = None,
                case_dir: Optional[str] = None):
    """Remove a rule from its scope; its last source stays in the scope's history."""
    return tools_yara_rules.yara_rule_delete_result(
        name, scope, _case_target(case_dir)).payload
