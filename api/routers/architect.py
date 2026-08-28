"""Architect router — static checking, pattern generation, and export."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from memdiver.architect.json_exporter import JsonExporter
from memdiver.architect.pattern_generator import PatternGenerator
from memdiver.architect.static_checker import StaticChecker
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from memdiver.architect.yara_exporter import (
    YaraExporter,
    key_locator_from_pattern,
)

logger = logging.getLogger("memdiver.api.routers.architect")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CheckStaticRequest(BaseModel):
    """Request body for static byte checking across dumps."""

    dump_paths: list[str]
    offset: int
    length: int


class GeneratePatternRequest(BaseModel):
    """Request body for wildcard pattern generation."""

    reference_hex: str
    static_mask: list[bool]
    name: str = "unnamed"
    min_static_ratio: float = 0.3


class ExportRequest(BaseModel):
    """Request body for pattern export (YARA or JSON)."""

    pattern: dict
    format: str = "yara"
    rule_name: Optional[str] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/check-static")
def check_static(req: CheckStaticRequest):
    """Check which bytes are static across multiple dump files."""
    paths = []
    for p in req.dump_paths:
        path = Path(p)
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"File not found: {p}")
        paths.append(path)

    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 dump paths")

    static_mask, reference = StaticChecker.check(paths, req.offset, req.length)
    ratio = StaticChecker.static_ratio(static_mask)
    anchors = PatternGenerator.find_anchors(static_mask)

    return {
        "static_mask": static_mask,
        "reference_hex": reference.hex(),
        "static_ratio": round(ratio, 4),
        "anchors": [{"start": s, "length": l} for s, l in anchors],
    }


@router.post("/generate-pattern")
def generate_pattern(req: GeneratePatternRequest):
    """Generate a wildcard byte pattern from reference bytes and mask."""
    try:
        reference = bytes.fromhex(req.reference_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid hex: {exc}") from exc

    pattern = PatternGenerator.generate(
        reference, req.static_mask, req.name, req.min_static_ratio,
    )
    if pattern is None:
        raise HTTPException(
            status_code=400,
            detail="Insufficient static bytes for pattern generation",
        )
    return pattern


@router.post("/export")
def export_pattern(req: ExportRequest):
    """Export a pattern as YARA rule or JSON signature."""
    fmt = req.format.lower()

    # The key locator is whatever the *posted pattern* already carries: this
    # endpoint receives a finished pattern dict, never the hit or the
    # consensus slab it came from, so there is nothing else here from which
    # the key's position could be derived. A pattern produced by
    # ``emit-plugin`` / the experiment orchestrator carries
    # ``key_offset``/``key_length``; one straight out of
    # ``/architect/generate-pattern`` does not, and then the metas are
    # correctly omitted rather than invented.
    key_offset, key_length = key_locator_from_pattern(req.pattern)

    # ``req.pattern`` is a free-form client-supplied dict, so a malformed
    # ``wildcard_pattern`` is a BAD REQUEST, not a server fault. Before the
    # exporter validated its byte string, a pattern using the wrong key names
    # silently produced ``$key = {  }`` -- a rule that returned HTTP 200 and
    # then failed to compile on the analyst's machine. Mirrors the 400 that
    # ``/generate-pattern`` raises for an unusable pattern.
    try:
        return _render_export(req, fmt, key_offset, key_length)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _render_export(req: "ExportRequest", fmt: str,
                   key_offset, key_length) -> Dict[str, Any]:
    """Render the requested artifact. Raises ``ValueError`` on a bad pattern."""
    if fmt == "yara":
        content = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
            key_offset=key_offset, key_length=key_length,
        )
    elif fmt == "json":
        sig = JsonExporter.export(
            req.pattern, description=req.description or "",
        )
        content = JsonExporter.to_string(sig)
    elif fmt in ("volatility3", "vol3"):
        yara_rule = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
            key_offset=key_offset, key_length=key_length,
        )
        content = Volatility3Exporter.export(
            req.pattern, plugin_name=req.rule_name,
            description=req.description, yara_rule=yara_rule,
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown format: {req.format}. Use 'yara', 'json', or 'volatility3'.",
        )

    return {"format": fmt, "content": content}
