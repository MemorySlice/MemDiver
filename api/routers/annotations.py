"""Annotations router — the versioned analysis record of a capture.

The web face of the ``annotations.*`` capabilities; every route is a thin
adapter over its shared producer in :mod:`memdiver.app.tools_annotations`:

* ``GET  /api/annotations``           — current (or all) entries of a capture.
* ``POST /api/annotations/add``       — append a new entry.
* ``POST /api/annotations/supersede`` — replace an entry (fields inherited).
* ``POST /api/annotations/retract``   — withdraw an entry.

``case_dir`` is REQUIRED (the Case abstraction with a default arrives with
T1.8). Reads go through the opt-in read-path sandbox (``case_dir`` is in
``READ_PATH_KEYS``). WRITES are always contained: the case directory must live
inside the upload directory or the MemDiver home (``~/.memdiver``), exactly the
always-on write policy the export endpoints apply. Errors use the modern
contract: a producer's ``CapabilityError`` reaches the global handler.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.config import get_settings
from memdiver.api.path_safety import ensure_within, write_denial_detail
from memdiver.app import tools_annotations
from memdiver.core.constants import memdiver_home

router = APIRouter()


class _CaseRequest(BaseModel):
    # Unknown fields are an error, not silently dropped: a misspelled field name
    # would otherwise turn into a default value with a 200 (cf. the
    # aligned-window anchor_path/dump_path drift bug).
    model_config = ConfigDict(extra="forbid")

    case_dir: str
    capture_id: str
    author: str = "human"


class AddRequest(_CaseRequest):
    kind: str = "annotation"
    locations: List[Dict[str, Any]] = Field(default_factory=list)
    label: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)
    support: List[Dict[str, str]] = Field(default_factory=list)
    length: Optional[int] = None


class SupersedeRequest(_CaseRequest):
    entry_id: str
    kind: Optional[str] = None
    locations: Optional[List[Dict[str, Any]]] = None
    label: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    support: Optional[List[Dict[str, str]]] = None
    length: Optional[int] = None


class RetractRequest(_CaseRequest):
    entry_id: str
    reason: str = ""


def _write_roots() -> List[Path]:
    # Delegates to the shared helper (also used by the MCP write guard).
    from memdiver.api.read_roots import write_roots

    return write_roots()
    # Historical inline computation, kept for reference:
    # roots = [memdiver_home()]
    # upload_dir = get_settings().upload_dir
    # if upload_dir is not None:
    #     roots.append(Path(upload_dir))
    # return roots


def contained_case_dir(case_dir: str) -> str:
    """Return ``case_dir`` resolved, or raise 403 if no write root contains it."""
    candidate = Path(case_dir).expanduser()
    for root in _write_roots():
        try:
            return str(ensure_within(root, candidate))
        except ValueError:
            continue
    raise HTTPException(
        status_code=403,
        detail=write_denial_detail(
            "case_dir / out_path", case_dir, _write_roots(), "out/result"))


@router.get("")
def list_annotations(case_dir: str, capture_id: str, kind: Optional[str] = None,
                     include_superseded: bool = False):
    """Current entries of ``capture_id`` (all of them with ``include_superseded``)."""
    return tools_annotations.annotations_list_result(
        case_dir, capture_id, kind, include_superseded).payload


@router.post("/add")
def add_annotation(req: AddRequest):
    """Append one entry to the capture's analysis record."""
    return tools_annotations.annotations_add_result(
        contained_case_dir(req.case_dir), req.capture_id, req.kind, req.author,
        req.locations, req.label, req.payload, req.support, req.length).payload


@router.post("/supersede")
def supersede_annotation(req: SupersedeRequest):
    """Append an entry replacing ``entry_id``; omitted fields are inherited."""
    changes = req.model_dump(exclude_none=True, include=set(
        tools_annotations.SUPERSEDABLE_FIELDS))
    return tools_annotations.annotations_supersede_result(
        contained_case_dir(req.case_dir), req.capture_id, req.entry_id, req.author,
        **changes).payload


@router.post("/retract")
def retract_annotation(req: RetractRequest):
    """Withdraw ``entry_id`` by appending a retraction entry."""
    return tools_annotations.annotations_retract_result(
        contained_case_dir(req.case_dir), req.capture_id, req.entry_id, req.author,
        req.reason).payload
