"""Tests for engine.oracle — BYO oracle loader."""

import os
import stat
import tempfile
from pathlib import Path

import pytest

from engine.oracle import (
    OracleLoadError,
    load_oracle,
    load_oracle_config,
)


def _write(path: Path, content: str, mode: int = 0o644) -> Path:
    path.write_text(content)
    os.chmod(path, mode)
    return path


def test_shape1_stateless_function(tmp_path):
    src = _write(tmp_path / "o.py", "def verify(c): return c == b'yes'\n")
    verify = load_oracle(src)
    assert verify(b"yes") is True
    assert verify(b"no") is False


def test_shape2_stateful_factory(tmp_path):
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    return O(cfg['target'])\n"
        "class O:\n"
        "    def __init__(self, t): self.t = t\n"
        "    def verify(self, c): return c == self.t\n",
    )
    verify = load_oracle(src, {"target": b"hit"})
    assert verify(b"hit") is True
    assert verify(b"miss") is False


def test_shape2_preferred_over_shape1(tmp_path):
    """When both exports exist, build_oracle wins (explicit over implicit)."""
    src = _write(
        tmp_path / "o.py",
        "def verify(c): return True\n"
        "def build_oracle(cfg):\n"
        "    return O()\n"
        "class O:\n"
        "    def verify(self, c): return False\n",
    )
    verify = load_oracle(src, {})
    assert verify(b"anything") is False


def test_missing_exports_raises(tmp_path):
    src = _write(tmp_path / "o.py", "x = 1\n")
    with pytest.raises(OracleLoadError, match="must export"):
        load_oracle(src)


def test_build_oracle_without_verify_raises(tmp_path):
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg): return object()\n",
    )
    with pytest.raises(OracleLoadError, match="no verify"):
        load_oracle(src)


def test_refuses_world_writable_file(tmp_path):
    src = _write(tmp_path / "o.py", "def verify(c): return True\n", mode=0o666)
    with pytest.raises(OracleLoadError, match="world-writable"):
        load_oracle(src)


def test_missing_file_raises(tmp_path):
    with pytest.raises(OracleLoadError, match="not found"):
        load_oracle(tmp_path / "nonexistent.py")


def test_import_error_wrapped(tmp_path):
    src = _write(tmp_path / "o.py", "raise RuntimeError('boom')\n")
    with pytest.raises(OracleLoadError, match="failed to import"):
        load_oracle(src)


def test_load_config_missing_returns_empty_for_none():
    assert load_oracle_config(None) == {}


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(OracleLoadError, match="not found"):
        load_oracle_config(tmp_path / "missing.toml")


def test_load_config_toml_roundtrip(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text('target = "foo"\nnumber = 42\n')
    out = load_oracle_config(cfg)
    assert out == {"target": "foo", "number": 42}
