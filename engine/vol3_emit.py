"""Vol3 plugin emission from brute-force hits.

Takes a hit + its neighborhood variance (the 128-byte window around a
successful candidate that ``brute-force`` already sliced from the
Welford state) and produces a Python Volatility3 plugin via the
existing architect.Volatility3Exporter.

The static anchor comes from bytes *around* the hit, not the hit
itself — the key region is ~100% volatile by construction and cannot
yield an anchor. The surrounding struct fields (pointers, flags,
length prefixes) are what make the plugin searchable on an unrelated
dump.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from architect.pattern_generator import PatternGenerator
from architect.volatility3_exporter import Volatility3Exporter
from architect.yara_exporter import YaraExporter
from core.variance import POINTER_MAX
from engine.progress import (
    ProgressEvent,
    ProgressFn,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.vol3_emit")

# Default variance threshold for plugin static-mask generation.
#
# The consensus system classifies bytes as STRUCTURAL (≤200),
# POINTER (200–3000), or KEY_CANDIDATE (>3000).  POINTER-class bytes
# (heap pointers, GC state, counters) vary between sessions by
# definition — they should NOT be pattern anchors.
#
# A threshold of 2000 keeps the lower-variance POINTER bytes (type
# metadata, function pointers — consistent within the same binary
# build) while excluding session-variable heap state (var 2000–3000).
# This was empirically validated: threshold 3000 → 0 cross-session
# matches; threshold 2000 → correct matches.  Users can override
# via ``--variance-threshold`` on ``emit-plugin``.
PLUGIN_STATIC_THRESHOLD = 2000.0


def _static_mask_from_variance(
    variance: List[float],
    threshold: float = PLUGIN_STATIC_THRESHOLD,
) -> List[bool]:
    """True where variance is low enough that the byte isn't a KEY_CANDIDATE."""
    return [float(v) <= threshold for v in variance]


def _build_vtypes(
    name: str, fields: List[dict], total_size: int,
) -> dict:
    """Generate Volatility3-compatible vtypes from inferred fields."""
    vtype_fields: dict = {}
    for f in fields:
        vtype_fields[f["label"]] = [
            f["offset"],
            ["Array", {"count": f["length"], "target": "unsigned char"}],
        ]
    return {name: [total_size, vtype_fields]}


def _log_structure_summary(fields: List[dict], name: str) -> None:
    """Print human-readable structure analysis to stderr."""
    static = [f for f in fields if f["type"] == "static"]
    dynamic = [f for f in fields if f["type"] == "dynamic"]
    key = next((f for f in fields if f["type"] == "key_material"), None)
    total_static = sum(f["length"] for f in static)
    total = sum(f["length"] for f in fields)
    if static:
        logger.info(
            "Structure '%s': %d static anchor(s) (%d/%d bytes, %.0f%%)",
            name, len(static), total_static, total,
            100 * total_static / total if total else 0,
        )
        for f in static:
            logger.info(
                "  +%d..+%d  %s  (%d bytes, var=%.1f)",
                f["offset"], f["offset"] + f["length"],
                f["label"], f["length"], f["mean_variance"],
            )
    else:
        logger.warning(
            "Structure '%s': NO stable structural fields in neighborhood. "
            "YARA pattern relies on byte-level matching only. Consider "
            "widening neighborhood or adding more consensus dumps.", name,
        )
    if key:
        logger.info(
            "  +%d..+%d  key_material (%d bytes, var=%.1f)",
            key["offset"], key["offset"] + key["length"],
            key["length"], key["mean_variance"],
        )


def emit_plugin_for_hit(
    hit: dict,
    reference_data: bytes,
    name: str,
    output_path: Path,
    *,
    description: Optional[str] = None,
    min_static_ratio: float = 0.3,
    variance_threshold: Optional[float] = None,
    progress_callback: ProgressFn = noop_progress,
) -> Path:
    """Emit a vol3 plugin anchored on the neighborhood around a brute-force hit."""
    safe_emit(
        progress_callback,
        ProgressEvent(stage="emit_plugin:load", pct=0.0, msg=f"plugin={name}"),
    )
    nb_start = int(hit["neighborhood_start"])
    nb_variance: List[float] = hit.get("neighborhood_variance") or []
    if not nb_variance:
        raise ValueError(
            f"hit at offset 0x{int(hit['offset']):x} has no neighborhood "
            f"variance; re-run brute-force with --state so the Welford "
            f"slice is attached"
        )
    nb_end = nb_start + len(nb_variance)
    if nb_end > len(reference_data):
        raise ValueError(
            f"neighborhood [{nb_start}:{nb_end}] exceeds reference dump "
            f"length {len(reference_data)}"
        )
    window = reference_data[nb_start:nb_end]
    thresh = variance_threshold if variance_threshold is not None else PLUGIN_STATIC_THRESHOLD
    static_mask = _static_mask_from_variance(nb_variance, threshold=thresh)

    # Compute key position within the neighborhood window.
    key_offset_in_window = int(hit["offset"]) - nb_start
    key_length = int(hit["length"])

    # Infer field structure from the variance profile.
    fields = PatternGenerator.infer_fields(
        nb_variance, key_offset_in_window, key_length, threshold=thresh,
    )
    vtypes = _build_vtypes(name, fields, len(window))
    _log_structure_summary(fields, name)

    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="emit_plugin:render",
            pct=0.5,
            msg=f"window={len(window)} static={sum(static_mask)}",
        ),
    )
    pattern = PatternGenerator.generate(
        window, static_mask, name=name, min_static_ratio=min_static_ratio,
    )
    if pattern is None:
        static_ratio = sum(static_mask) / len(static_mask) if static_mask else 0.0
        raise RuntimeError(
            f"insufficient static bytes in neighborhood for {name}: "
            f"{static_ratio:.1%} static (need >= {min_static_ratio:.1%}). "
            f"Widen the neighborhood pad or run with more dumps so the "
            f"consensus matrix settles on more invariant bytes."
        )

    # Attach key position + structure metadata for the template.
    pattern["key_offset"] = key_offset_in_window
    pattern["key_length"] = key_length
    pattern["vtypes"] = vtypes
    pattern["fields"] = fields

    yara_rule = YaraExporter.export(pattern)
    source = Volatility3Exporter.export(
        pattern,
        plugin_name=name,
        description=description,
        yara_rule=yara_rule,
    )
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(source)
    logger.info("wrote vol3 plugin %s (%d bytes)", output_path, len(source))
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="emit_plugin:write",
            pct=1.0,
            msg=f"wrote {output_path.name}",
            extra={"path": str(output_path), "size": len(source)},
        ),
    )
    return output_path


def extract_inferred_fields(
    hit: dict,
    variance_threshold: Optional[float] = None,
) -> List[dict]:
    """Derive inferred field structure from a hit's neighborhood variance.

    Lightweight wrapper around ``PatternGenerator.infer_fields()`` that
    resolves key offset and threshold from the hit dict.  Used by the
    pipeline runner to attach field metadata without importing internals.
    """
    nb_variance = hit.get("neighborhood_variance", [])
    if not nb_variance:
        return []
    nb_start = int(hit.get("neighborhood_start", hit["offset"]))
    key_off = int(hit["offset"]) - nb_start
    key_len = int(hit["length"])
    thresh = variance_threshold if variance_threshold is not None else PLUGIN_STATIC_THRESHOLD
    return PatternGenerator.infer_fields(
        nb_variance, key_off, key_len, threshold=thresh,
    )


def emit_plugin_from_hits_file(
    hits_path: Path,
    reference_data: bytes,
    name: str,
    output_path: Path,
    *,
    hit_index: int = 0,
    description: Optional[str] = None,
    variance_threshold: Optional[float] = None,
) -> Path:
    """Load hits.json, pick one hit, emit its vol3 plugin."""
    payload = json.loads(Path(hits_path).read_text())
    hits = payload.get("hits", [])
    if not hits:
        raise ValueError(f"{hits_path}: no hits to emit plugin from")
    if hit_index < 0 or hit_index >= len(hits):
        raise ValueError(
            f"{hits_path}: requested hit {hit_index} but only "
            f"{len(hits)} present"
        )
    return emit_plugin_for_hit(
        hits[hit_index], reference_data, name, output_path,
        description=description,
        variance_threshold=variance_threshold,
    )
