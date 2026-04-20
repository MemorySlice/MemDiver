"""JSON schema validation for user-defined structure definitions."""

from __future__ import annotations
import json
import re
from typing import Tuple, List
from core.structure_defs import StructureDef, FieldDef, FieldType

MAX_TOTAL_SIZE = 65536  # 64KB max structure size
VALID_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
VALID_CONSTRAINTS = {"min", "max", "equals", "not_zero"}


def validate_structure_json(data: dict) -> Tuple[bool, List[str]]:
    """Validate a JSON structure definition. Returns (valid, error_messages)."""
    errors: List[str] = []

    # Required fields
    if "name" not in data:
        errors.append("Missing required field: name")
    elif not isinstance(data["name"], str) or not VALID_NAME_RE.match(data["name"]):
        errors.append("Invalid name: must be alphanumeric/underscore, 1-64 chars")

    if "total_size" not in data:
        errors.append("Missing required field: total_size")
    elif not isinstance(data["total_size"], int) or data["total_size"] <= 0:
        errors.append("total_size must be a positive integer")
    elif data["total_size"] > MAX_TOTAL_SIZE:
        errors.append(f"total_size exceeds maximum ({MAX_TOTAL_SIZE})")

    if "fields" not in data or not isinstance(data["fields"], list):
        errors.append("Missing or invalid fields array")
        return len(errors) == 0, errors

    # Validate each field
    valid_types = {ft.value for ft in FieldType}
    total_size = data.get("total_size", 0)
    seen_names: set = set()
    for i, field in enumerate(data["fields"]):
        prefix = f"fields[{i}]"
        if not isinstance(field, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        for req in ("name", "field_type", "offset", "size"):
            if req not in field:
                errors.append(f"{prefix}: missing {req}")
        if "name" in field:
            if not isinstance(field["name"], str) or not VALID_NAME_RE.match(field["name"]):
                errors.append(f"{prefix}: invalid field name '{field.get('name')}'")
            elif field["name"] in seen_names:
                errors.append(f"{prefix}: duplicate field name '{field['name']}'")
            else:
                seen_names.add(field["name"])
        if "field_type" in field and field["field_type"] not in valid_types:
            errors.append(f"{prefix}: unknown field_type '{field['field_type']}'")
        if "offset" in field and (not isinstance(field["offset"], int) or field["offset"] < 0):
            errors.append(f"{prefix}: offset must be non-negative int")
        if "size" in field and (not isinstance(field["size"], int) or field["size"] <= 0):
            errors.append(f"{prefix}: size must be positive int")
        # Check field fits within total_size
        if (isinstance(total_size, int) and total_size > 0
                and "offset" in field and isinstance(field["offset"], int)
                and "size" in field and isinstance(field["size"], int)):
            if field["offset"] + field["size"] > total_size:
                errors.append(f"{prefix}: field exceeds total_size (offset {field['offset']} + size {field['size']} > {total_size})")
        if "constraints" in field:
            if not isinstance(field["constraints"], dict):
                errors.append(f"{prefix}: constraints must be a dict")
            else:
                for k in field["constraints"]:
                    if k not in VALID_CONSTRAINTS:
                        errors.append(f"{prefix}: unknown constraint '{k}'")

    return len(errors) == 0, errors


def json_to_structure_def(data: dict) -> StructureDef:
    """Convert a validated JSON dict to a StructureDef instance."""
    fields = []
    for f in data.get("fields", []):
        fields.append(FieldDef(
            name=f["name"],
            field_type=FieldType(f["field_type"]),
            offset=f["offset"],
            size=f["size"],
            description=f.get("description", ""),
            constraints=f.get("constraints", {}),
        ))

    return StructureDef(
        name=data["name"],
        total_size=data["total_size"],
        protocol=data.get("protocol", ""),
        description=data.get("description", ""),
        tags=tuple(data.get("tags", [])),
        fields=tuple(fields),
    )


def structure_def_to_json(sd: StructureDef) -> dict:
    """Convert a StructureDef back to a JSON-serializable dict."""
    return {
        "name": sd.name,
        "total_size": sd.total_size,
        "protocol": sd.protocol,
        "description": sd.description,
        "tags": list(sd.tags),
        "fields": [
            {
                "name": f.name,
                "field_type": f.field_type.value,
                "offset": f.offset,
                "size": f.size,
                "description": f.description,
                "constraints": dict(f.constraints) if f.constraints else {},
            }
            for f in sd.fields
        ],
    }
