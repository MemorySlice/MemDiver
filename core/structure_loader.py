"""Load and save user-defined structure definitions."""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import List

from core.structure_defs import StructureDef
from core.structure_schema import validate_structure_json, json_to_structure_def, structure_def_to_json

logger = logging.getLogger("memdiver.structure_loader")

DEFAULT_USER_DIR = Path.home() / ".memdiver" / "structures"


def load_user_structures(directory: Path = DEFAULT_USER_DIR) -> List[StructureDef]:
    """Load all .json structure definitions from directory."""
    if not directory.is_dir():
        return []

    results: List[StructureDef] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            valid, errors = validate_structure_json(data)
            if not valid:
                logger.warning("Skipping %s: %s", path.name, "; ".join(errors))
                continue
            results.append(json_to_structure_def(data))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load %s: %s", path.name, exc)

    return results


def save_user_structure(struct_def: StructureDef, directory: Path = DEFAULT_USER_DIR) -> Path:
    """Save a structure definition as JSON. Returns the output path."""
    directory.mkdir(parents=True, exist_ok=True)
    data = structure_def_to_json(struct_def)
    path = directory / f"{struct_def.name}.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path
