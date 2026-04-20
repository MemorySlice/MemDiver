"""Data structure definitions for describing memory layouts.

Provides types for defining fixed-layout structures found in memory dumps.
Unlike byte patterns (which match sequences), structure definitions describe
the semantic layout of memory regions with typed fields and constraints.
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("memdiver.structure_defs")


class FieldType(Enum):
    """Supported field types for structure definitions."""
    UINT8 = "uint8"
    UINT16_LE = "uint16_le"
    UINT16_BE = "uint16_be"
    UINT32_LE = "uint32_le"
    UINT32_BE = "uint32_be"
    UINT64_LE = "uint64_le"
    UINT64_BE = "uint64_be"
    BYTES = "bytes"
    POINTER = "pointer"
    UTF8_STRING = "utf8_string"


# Map FieldType to struct format + size
_FIELD_FORMATS: Dict[FieldType, Tuple[str, int]] = {
    FieldType.UINT8: ("B", 1),
    FieldType.UINT16_LE: ("<H", 2),
    FieldType.UINT16_BE: (">H", 2),
    FieldType.UINT32_LE: ("<I", 4),
    FieldType.UINT32_BE: (">I", 4),
    FieldType.UINT64_LE: ("<Q", 8),
    FieldType.UINT64_BE: (">Q", 8),
    FieldType.POINTER: ("<Q", 8),  # default 64-bit LE
}


@dataclass(frozen=True)
class FieldDef:
    """Definition of a single field within a structure."""
    name: str
    field_type: FieldType
    offset: int           # relative offset within structure
    size: int             # in bytes (default if no size_choices match)
    description: str = ""
    constraints: Dict[str, Any] = field(default_factory=dict)
    # constraints examples: {"min": 0, "max": 255}, {"equals": 0x0303}
    size_choices: Tuple[int, ...] = ()
    # If non-empty, overlay will probe these sizes (descending order recommended)
    # and select the first that passes constraints.


@dataclass(frozen=True)
class StructureDef:
    """Definition of a fixed-layout data structure in memory."""
    name: str
    total_size: int
    fields: Tuple[FieldDef, ...]
    protocol: str = ""    # e.g. "TLS", "SSH", "" for generic
    description: str = ""
    tags: Tuple[str, ...] = ()
    library: Optional[str] = None          # e.g. "boringssl"
    library_version: Optional[str] = None  # e.g. "1.x"
    stability: str = "stable"              # "stable" | "experimental" | "deprecated"
    auto_offsets: bool = False             # recompute offsets from cumulative field sizes

    def field_by_name(self, name: str) -> Optional[FieldDef]:
        """Look up a field by name."""
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def validate_data(self, data: bytes) -> Dict[str, bool]:
        """Check each field's constraints against actual data.

        Returns dict mapping field name to whether constraints passed.
        """
        results = {}
        for f in self.fields:
            if not f.constraints:
                results[f.name] = True
                continue
            value = _parse_field(data, f)
            results[f.name] = _check_constraints(value, f.constraints)
        return results


def _parse_field(data: bytes, field_def: FieldDef) -> Any:
    """Parse a single field from raw data."""
    start = field_def.offset
    end = start + field_def.size
    if end > len(data):
        return None

    chunk = data[start:end]

    if field_def.field_type in _FIELD_FORMATS:
        fmt, expected_size = _FIELD_FORMATS[field_def.field_type]
        if field_def.size == expected_size:
            return struct.unpack(fmt, chunk)[0]
        return int.from_bytes(chunk, "little")

    if field_def.field_type == FieldType.BYTES:
        return chunk

    if field_def.field_type == FieldType.UTF8_STRING:
        return chunk.rstrip(b"\x00").decode("utf-8", errors="replace")

    return chunk


def _check_constraints(value: Any, constraints: Dict[str, Any]) -> bool:
    """Check a parsed value against constraint rules."""
    if value is None:
        return False
    for key, expected in constraints.items():
        if key == "min" and value < expected:
            return False
        if key == "max" and value > expected:
            return False
        if key == "equals" and value != expected:
            return False
        if key == "not_zero" and expected:
            if isinstance(value, (bytes, bytearray)):
                if not any(value):
                    return False
            elif value == 0:
                return False
        if key == "byte_equals" and isinstance(value, (bytes, bytearray)):
            for off_str, expected_byte in expected.items():
                idx = int(off_str)
                if idx >= len(value) or value[idx] != expected_byte:
                    return False
        if key == "byte_in" and isinstance(value, (bytes, bytearray)):
            for off_str, allowed in expected.items():
                idx = int(off_str)
                if idx >= len(value) or value[idx] not in allowed:
                    return False
    return True


def parse_structure(data: bytes, struct_def: StructureDef) -> Dict[str, Any]:
    """Parse raw bytes according to a StructureDef.

    Returns dict mapping field_name to parsed value.
    """
    result = {}
    for f in struct_def.fields:
        result[f.name] = _parse_field(data, f)
    return result
