"""Tests for core.config_schema module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config_schema import validate_config


def _valid_config():
    return {
        "dataset_root": "/tmp/data",
        "keylog_filename": "keylog.csv",
        "logging": {"level": "INFO", "file": None},
        "analysis": {
            "max_runs": 10,
            "context_bytes": 256,
            "default_algorithm": "exact_match",
        },
        "ui": {
            "default_mode": "testing",
            "hex_bytes_per_row": 16,
            "max_hex_rows": 64,
        },
    }


def test_valid_config_passes():
    valid, errors = validate_config(_valid_config())
    assert valid
    assert errors == []


def test_empty_config_passes():
    valid, errors = validate_config({})
    assert valid
    assert errors == []


def test_type_error_caught():
    cfg = _valid_config()
    cfg["dataset_root"] = 123
    valid, errors = validate_config(cfg)
    assert not valid
    assert any("expected str" in e for e in errors)


def test_range_violation_caught():
    cfg = _valid_config()
    cfg["analysis"]["max_runs"] = 0
    valid, errors = validate_config(cfg)
    assert not valid
    assert any("below minimum" in e for e in errors)


def test_range_above_maximum():
    cfg = _valid_config()
    cfg["analysis"]["max_runs"] = 9999
    valid, errors = validate_config(cfg)
    assert not valid
    assert any("above maximum" in e for e in errors)


def test_allowed_values_violation():
    cfg = _valid_config()
    cfg["logging"]["level"] = "TRACE"
    valid, errors = validate_config(cfg)
    assert not valid
    assert any("not in allowed values" in e for e in errors)


def test_unknown_keys_do_not_error():
    cfg = _valid_config()
    cfg["future_feature"] = True
    valid, errors = validate_config(cfg)
    assert valid
    assert errors == []


def test_nested_validation():
    cfg = _valid_config()
    cfg["ui"]["default_mode"] = "invalid_mode"
    valid, errors = validate_config(cfg)
    assert not valid
    assert any("ui.default_mode" in e for e in errors)


def test_nullable_field_accepts_none():
    cfg = _valid_config()
    cfg["logging"]["file"] = None
    valid, errors = validate_config(cfg)
    assert valid
