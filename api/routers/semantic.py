"""Semantic router -- layout proposal and artifact-model build (``semantic.*``).

The web face of :mod:`memdiver.app.tools_semantic`:

* ``POST /api/semantic/propose-layout`` -- field-boundary hypotheses around a
  verified anchor, learned from N dumps (optionally filed in a case record).
* ``POST /api/semantic/model-build`` -- the same, built into an artifact model
  written to a NEW ``.json`` at ``out_path``.

Dump existence is checked by the producer (a missing file is a 404); every path
the server WRITES (``case_dir``, ``out_path``) is contained like the case
router's. A ``CapabilityError`` goes through the app's global handler, so there
is deliberately no ``try/except`` here.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.models import KeylogAnchorFields, MixedCohortFields
from memdiver.api.path_policy import admit_read_path
from memdiver.api.routers.image import _case_target, _contained
from memdiver.app import tools_semantic
from memdiver.app.composition import build_tool_session
from memdiver.core.service_errors import CapabilityError, ErrorCategory

router = APIRouter()


class ProposeLayoutRequest(KeylogAnchorFields, MixedCohortFields):
    """Exactly ONE of ``needles`` (``{dump_path: hex}``) or ``anchors``
    (``[{dump_path, va}]`` / ``[{dump_path, offset}]``)."""

    model_config = ConfigDict(extra="forbid")

    dump_paths: Optional[List[str]] = None
    needles: Optional[Dict[str, str]] = None
    anchors: Optional[List[Dict[str, Any]]] = None
    occurrence: int = Field(default=0, ge=0)
    delta_start: int = -2048
    length: int = Field(default=6144, ge=1)
    anchor_length: Optional[int] = Field(default=None, ge=1)
    related: Optional[Dict[str, Dict[str, str]]] = None
    pointer_quorum: Optional[int] = Field(default=None, ge=1)
    heap: bool = True
    case_dir: Optional[str] = None
    author: str = tools_semantic.DEFAULT_AUTHOR
    # "summary" | "full" (validated by the producer). Same default on every
    # surface; the web client asks for "full" explicitly because its panel shows
    # each field's evidence/alternatives.
    detail: str = "summary"


class ModelBuildRequest(ProposeLayoutRequest):
    name: str
    meanings: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    applicability: Optional[Dict[str, Any]] = None
    prefilter_length: int = Field(default=64, ge=1)
    out_path: str


class ModelExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_path: str
    out_path: str
    plugin_name: Optional[str] = None


class ModelValidateRequest(BaseModel):
    """``held_out``: ``[{dump_path, keylog_path | expected}]``, one source each."""

    model_config = ConfigDict(extra="forbid")

    model_path: str
    held_out: List[Dict[str, Any]]
    labels: Optional[List[str]] = None
    plugin_path: Optional[str] = None
    out_path: Optional[str] = None
    min_run: int = Field(default=64, ge=1)
    keylog: Optional[Dict[str, Any]] = None


def _trusted_plugin_path(plugin_path: Optional[str]) -> Optional[str]:
    """A ``plugin_path`` the server will EXEC: inside the read sandbox (403 when
    outside) and, like oracles, never group/world-writable (D7 posture)."""
    if not plugin_path:
        return None
    resolved = admit_read_path(plugin_path)
    for target in (resolved, resolved.parent):
        try:
            mode = Path(target).stat().st_mode
        except OSError:
            continue  # a missing file is reported by the producer as a 404
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CapabilityError(
                f"refusing to execute a plugin from a group/world-writable path: {target}",
                category=ErrorCategory.INVALID_INPUT, code="semantic.plugin_untrusted")
    return str(resolved)


def _learn_kwargs(req: ProposeLayoutRequest) -> Dict[str, Any]:
    return dict(
        dump_paths=req.dump_paths, needles=req.needles, anchors=req.anchors,
        occurrence=req.occurrence, delta_start=req.delta_start, length=req.length,
        anchor_length=req.anchor_length, related=req.related,
        pointer_quorum=req.pointer_quorum, heap=req.heap, mixed_ok=req.mixed_ok,
        case_dir=_case_target(req.case_dir), author=req.author,
        keylog=req.keylog, anchor_label=req.anchor_label,
        related_labels=req.related_labels, detail=req.detail)


@router.post("/propose-layout")
def propose_layout(req: ProposeLayoutRequest):
    """Field-boundary proposal around each dump's own verified anchor."""
    return tools_semantic.propose_layout_result(
        build_tool_session(), **_learn_kwargs(req)).payload


@router.post("/model-build")
def model_build(req: ModelBuildRequest):
    """Build the artifact model from the proposal and write it to ``out_path``."""
    return tools_semantic.artifact_model_build_result(
        build_tool_session(), **_learn_kwargs(req), name=req.name,
        meanings=req.meanings, relationships=req.relationships,
        applicability=req.applicability, prefilter_length=req.prefilter_length,
        out_path=_contained(req.out_path)).payload


@router.post("/model-export")
def model_export(req: ModelExportRequest):
    """Export the model JSON at ``model_path`` as a plugin written to ``out_path``."""
    return tools_semantic.artifact_model_export_result(
        build_tool_session(), model_path=req.model_path,
        out_path=_contained(req.out_path), plugin_name=req.plugin_name).payload


@router.post("/model-validate")
def model_validate(req: ModelValidateRequest):
    """Score the model's plugin on held-out captures (synchronous; no task WS)."""
    return tools_semantic.artifact_model_validate_result(
        build_tool_session(), model_path=req.model_path, held_out=req.held_out,
        labels=req.labels, plugin_path=_trusted_plugin_path(req.plugin_path),
        out_path=_contained(req.out_path) if req.out_path else None,
        min_run=req.min_run, keylog=req.keylog).payload
