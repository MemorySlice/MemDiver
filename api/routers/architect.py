"""Architect router — static checking, pattern generation, and export."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from architect.json_exporter import JsonExporter
from architect.pattern_generator import PatternGenerator
from architect.static_checker import StaticChecker
from architect.volatility3_exporter import Volatility3Exporter
from architect.yara_exporter import YaraExporter

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

    if fmt == "yara":
        content = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
        )
    elif fmt == "json":
        sig = JsonExporter.export(
            req.pattern, description=req.description or "",
        )
        content = JsonExporter.to_string(sig)
    elif fmt in ("volatility3", "vol3"):
        yara_rule = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
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
