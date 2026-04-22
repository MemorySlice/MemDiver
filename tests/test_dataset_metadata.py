"""Tests for :mod:`core.dataset_metadata`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataset_metadata import DatasetMeta, DumpRef, load_run_meta
from tests._paths import SKIP_REASON, dataset_root


def _write_meta(run_dir: Path, payload: dict) -> Path:
    meta_path = run_dir / "meta.json"
    meta_path.write_text(json.dumps(payload))
    return meta_path


def test_load_run_meta_basic(tmp_path: Path) -> None:
    """A minimal, well-formed meta.json round-trips through load_run_meta."""
    payload = {
        "run_id": 1,
        "cipher": "aes",
        "password": "pw",
        "master_key_hex": "0011aabb",
        "aslr_base": "0x400000",
        "pid": 42,
        "dumps": {
            "gcore": {"path": "run_x/gcore.core", "size": 100},
            "memslicer": {"path": "run_x/memslicer.msl", "size": 50},
        },
    }
    _write_meta(tmp_path, payload)

    meta = load_run_meta(tmp_path)

    assert isinstance(meta, DatasetMeta)
    assert meta.cipher == "aes"
    assert meta.pid == 42
    assert meta.aslr_base == 0x400000
    assert meta.master_key == bytes.fromhex("0011aabb")
    assert "gcore" in meta.dumps and "msl" in meta.dumps
    assert isinstance(meta.dumps["gcore"], DumpRef)
    assert meta.dumps["gcore"].size == 100


def test_load_run_meta_missing(tmp_path: Path) -> None:
    """Absence of meta.json yields None, not an exception."""
    assert load_run_meta(tmp_path) is None


def test_load_run_meta_malformed(tmp_path: Path) -> None:
    """Malformed JSON logs a warning and returns None."""
    (tmp_path / "meta.json").write_text("{not valid json")

    assert load_run_meta(tmp_path) is None


def test_load_run_meta_ignores_unknown_fields(tmp_path: Path) -> None:
    """Unknown top-level keys must not raise."""
    _write_meta(tmp_path, {
        "run_id": 2,
        "cipher": "chacha",
        "password": "",
        "master_key_hex": "",
        "aslr_base": 0,
        "pid": 0,
        "dumps": {},
        "future_field": {"nested": True},
        "elapsed_seconds": 1.23,
    })

    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.cipher == "chacha"


def test_load_run_meta_aslr_accepts_int_and_hex(tmp_path: Path) -> None:
    """``aslr_base`` can be a hex string or a raw integer."""
    _write_meta(tmp_path, {"aslr_base": 4194304})
    assert load_run_meta(tmp_path).aslr_base == 4194304  # type: ignore[union-attr]


def test_load_run_meta_real_dataset() -> None:
    """Smoke-test against the real dataset when present."""
    root = dataset_root()
    if root is None:
        pytest.skip(SKIP_REASON)
    run_dir = (
        root / "dataset_memory_slice" / "gocryptfs"
        / "dataset_gocryptfs" / "run_0001"
    )
    if not run_dir.is_dir():
        pytest.skip("Real dataset structure not present at expected path")

    meta = load_run_meta(run_dir)
    assert meta is not None
    assert meta.pid > 0
    assert meta.aslr_base == 0x400000
    assert "gcore" in meta.dumps
