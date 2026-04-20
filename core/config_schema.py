"""Config schema validation for MemDiver configuration files."""

import logging
from typing import Any, Dict, List, Tuple

from core.constants import UI_MODES

logger = logging.getLogger("memdiver.config_schema")

# Schema definition: each field has type, optional allowed values, min/max for ints
CONFIG_SCHEMA = {
    "dataset_root": {"type": str},
    "keylog_filename": {"type": str},
    "logging": {
        "type": dict,
        "children": {
            "level": {
                "type": str,
                "allowed": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            },
            "file": {"type": str, "nullable": True},
        },
    },
    "analysis": {
        "type": dict,
        "children": {
            "max_runs": {"type": int, "min": 1, "max": 1000},
            "context_bytes": {"type": int, "min": 0, "max": 65536},
            "default_algorithm": {"type": str},
        },
    },
    "ui": {
        "type": dict,
        "children": {
            "default_mode": {"type": str, "allowed": list(UI_MODES)},
            "hex_bytes_per_row": {"type": int, "min": 1, "max": 64},
            "max_hex_rows": {"type": int, "min": 1, "max": 10000},
        },
    },
}


def _validate_field(
    key: str, value: Any, spec: Dict[str, Any], path: str, errors: List[str]
) -> None:
    """Validate a single field against its specification."""
    full_path = f"{path}.{key}" if path else key

    if value is None:
        if spec.get("nullable", False):
            return
        errors.append(f"{full_path}: expected {spec['type'].__name__}, got None")
        return

    expected_type = spec["type"]
    if not isinstance(value, expected_type):
        errors.append(
            f"{full_path}: expected {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )
        return

    if "allowed" in spec and value not in spec["allowed"]:
        errors.append(
            f"{full_path}: '{value}' not in allowed values {spec['allowed']}"
        )

    if isinstance(value, int):
        if "min" in spec and value < spec["min"]:
            errors.append(f"{full_path}: {value} below minimum {spec['min']}")
        if "max" in spec and value > spec["max"]:
            errors.append(f"{full_path}: {value} above maximum {spec['max']}")

    if expected_type is dict and "children" in spec:
        _validate_section(value, spec["children"], full_path, errors)


def _validate_section(
    cfg: Dict[str, Any],
    schema: Dict[str, Any],
    path: str,
    errors: List[str],
) -> None:
    """Validate a config section against its schema, recursively."""
    for key, spec in schema.items():
        if key in cfg:
            _validate_field(key, cfg[key], spec, path, errors)

    known_keys = set(schema.keys())
    for key in cfg:
        if key not in known_keys:
            full_path = f"{path}.{key}" if path else key
            logger.warning("Unknown config key: %s", full_path)


def validate_config(cfg: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate a configuration dictionary against the MemDiver schema.

    Unknown keys produce warnings (logged) but not errors,
    for forward-compatibility with newer config versions.

    Args:
        cfg: Configuration dictionary to validate.

    Returns:
        Tuple of (is_valid, error_messages).
    """
    errors: List[str] = []
    _validate_section(cfg, CONFIG_SCHEMA, "", errors)
    if errors:
        for err in errors:
            logger.error("Config validation error: %s", err)
    return len(errors) == 0, errors
