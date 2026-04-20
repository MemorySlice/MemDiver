"""Structure overlay for annotating hex viewer with field boundaries.

Given raw memory data and a StructureDef, produces FieldOverlay objects
that map each field to its absolute offset, parsed value, and validation
status. Also provides best_match_structure to try all structures in a
library and return the best-scoring match.

Supports variable-length fields via `FieldDef.size_choices` (probe largest
first) and cumulative-offset layouts via `StructureDef.auto_offsets`.
"""

import logging
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

from core.structure_defs import (
    FieldDef,
    FieldType,
    StructureDef,
    _check_constraints,
    _parse_field,
)
from core.structure_library import StructureLibrary

logger = logging.getLogger("memdiver.structure_overlay")


@dataclass
class FieldOverlay:
    """Annotation for a single field within an overlaid structure."""
    offset: int           # absolute offset in the dump
    length: int
    field_name: str
    parsed_value: Any
    display: str          # human-readable representation
    valid: bool           # whether constraints passed
    resolved_size: Optional[int] = None  # set only when field had size_choices


def _format_value(value: Any, field_type: FieldType) -> str:
    """Format a parsed value for display."""
    if value is None:
        return "<out of bounds>"
    if isinstance(value, bytes):
        if len(value) <= 8:
            return value.hex()
        return f"{value[:8].hex()}... ({len(value)} bytes)"
    if isinstance(value, int):
        return f"0x{value:x} ({value})"
    return str(value)


def _resolve_field_size(
    data: bytes, field_def: FieldDef, offset_in_struct: int,
) -> int:
    """Return the resolved size for a field, probing size_choices if present.

    Probes each candidate (largest first). Picks the first size whose parsed
    value passes the field's constraints AND whose tail bytes (past the
    next-smaller candidate) are not all zero — this tail-zero heuristic
    distinguishes a truly larger secret from a smaller secret followed by
    zero padding. Falls back to `field_def.size` if none pass.
    """
    if not field_def.size_choices:
        return field_def.size

    sorted_choices = sorted(field_def.size_choices, reverse=True)

    for idx, candidate in enumerate(sorted_choices):
        if offset_in_struct + candidate > len(data):
            continue
        probe_field = replace(field_def, offset=offset_in_struct, size=candidate)
        value = _parse_field(data, probe_field)
        if value is None:
            continue
        if field_def.constraints and not _check_constraints(value, field_def.constraints):
            continue
        # Tail-zero check: if there's a smaller candidate and bytes past that
        # smaller boundary are all zero, reject this larger size.
        if idx + 1 < len(sorted_choices) and isinstance(value, (bytes, bytearray)):
            smaller = sorted_choices[idx + 1]
            tail = value[smaller:]
            if tail and not any(tail):
                continue
        return candidate

    return field_def.size


def _compute_default_size(struct_def: StructureDef) -> int:
    """Default total size for a struct (sum of field sizes if auto_offsets)."""
    if struct_def.auto_offsets:
        return sum(f.size for f in struct_def.fields)
    return struct_def.total_size


def compute_max_size(struct_def: StructureDef) -> int:
    """Maximum possible total size (using largest size_choice for each field)."""
    total = 0
    for f in struct_def.fields:
        total += max(f.size_choices) if f.size_choices else f.size
    if struct_def.auto_offsets:
        return total
    return max(struct_def.total_size, total)


def overlay_structure(
    data: bytes,
    base_offset: int,
    struct_def: StructureDef,
) -> Tuple[List[FieldOverlay], int]:
    """Apply a structure definition to raw data, producing field overlays.

    Returns:
        (overlays, resolved_total_size). When auto_offsets is True, field
        offsets are computed cumulatively. For fields with size_choices, the
        resolved size is picked by probing (largest first).
    """
    overlays: List[FieldOverlay] = []
    cursor = 0

    for field_def in struct_def.fields:
        if struct_def.auto_offsets:
            offset_in_struct = cursor
        else:
            offset_in_struct = field_def.offset

        resolved_size = _resolve_field_size(data, field_def, offset_in_struct)
        resolved_field = replace(
            field_def, offset=offset_in_struct, size=resolved_size,
        )
        value = _parse_field(data, resolved_field)
        valid = True
        if field_def.constraints:
            valid = _check_constraints(value, field_def.constraints)

        overlays.append(FieldOverlay(
            offset=base_offset + offset_in_struct,
            length=resolved_size,
            field_name=field_def.name,
            parsed_value=value,
            display=_format_value(value, field_def.field_type),
            valid=valid,
            resolved_size=resolved_size if field_def.size_choices else None,
        ))
        cursor = offset_in_struct + resolved_size

    if struct_def.auto_offsets:
        total = cursor
    else:
        total = struct_def.total_size
    return overlays, total


def variant_label(
    struct_def: StructureDef, resolved_sizes: Dict[str, int],
) -> str:
    """Human-readable variant tag based on resolved sizes (e.g. "SHA-256")."""
    total = sum(resolved_sizes.values()) if resolved_sizes else _compute_default_size(struct_def)
    hash_names = {20: "SHA-1", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512"}
    if total in hash_names:
        return hash_names[total]
    aes_names = {16: "AES-128", 24: "AES-192"}
    if total in aes_names:
        return aes_names[total]
    return f"{total} bytes"


def serialize_overlay_result(
    struct_def: StructureDef,
    overlays: List[FieldOverlay],
    total_size: int,
) -> Dict[str, Any]:
    """Build the common response payload shared by apply_structure and identify_structure."""
    resolved_sizes = {
        o.field_name: o.length for o in overlays
        if struct_def.field_by_name(o.field_name).size_choices
    }
    variant = variant_label(struct_def, resolved_sizes) if resolved_sizes else None
    return {
        "name": struct_def.name,
        "protocol": struct_def.protocol,
        "total_size": total_size,
        "variant": variant,
        "stability": struct_def.stability,
        "library": struct_def.library,
        "fields": [
            {
                "name": o.field_name,
                "offset": o.offset,
                "length": o.length,
                "resolved_size": o.length,
                "display": o.display,
                "valid": o.valid,
            }
            for o in overlays
        ],
    }


def best_match_structure(
    data: bytes,
    offset: int,
    library: StructureLibrary,
    protocol: str = "",
) -> Optional[Tuple[StructureDef, List[FieldOverlay], float]]:
    """Try all structures in library, return best match with confidence.

    Probes variable-length fields and picks the variant with highest score
    (tiebreaker: largest total size).
    """
    candidates = library.list_by_protocol(protocol) if protocol else library.list_all()

    best: Optional[Tuple[StructureDef, List[FieldOverlay], float]] = None
    best_score = 0.0
    best_size = 0

    for struct_def in candidates:
        constrained_count = sum(1 for f in struct_def.fields if f.constraints)
        if not constrained_count:
            continue
        if offset + _compute_default_size(struct_def) > len(data):
            continue

        read_size = min(compute_max_size(struct_def), len(data) - offset)
        chunk = data[offset:offset + read_size]
        overlays, total_size = overlay_structure(chunk, offset, struct_def)
        passing = sum(
            1 for ov in overlays
            if ov.valid and struct_def.field_by_name(ov.field_name).constraints
        )
        score = passing / constrained_count

        better_score = score > best_score
        better_tiebreak = best is not None and score == best_score and total_size > best_size
        if better_score or better_tiebreak:
            best_score = score
            best_size = total_size
            best = (struct_def, overlays, round(score, 4))

    return best
