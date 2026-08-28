"""Tests for :mod:`core.dataset_metadata`."""

from __future__ import annotations

import json
from pathlib import Path

from memdiver.core.dataset_metadata import DatasetMeta, DumpRef, _decode_hex, load_run_meta
from tests._paths import dataset_file


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


def test_decode_hex_even_length_and_prefix() -> None:
    """Even-length hex decodes, with optional ``0x`` prefix."""
    assert _decode_hex("deadbeef") == b"\xde\xad\xbe\xef"
    assert _decode_hex("0xDEADBEEF") == b"\xde\xad\xbe\xef"
    assert _decode_hex("") == b""


def test_decode_hex_rejects_odd_length() -> None:
    """Odd-length hex is rejected rather than nibble-misaligned by padding.

    ``"abc"`` must NOT decode to ``b"\\x0a\\xbc"`` (front-pad) — that would
    silently shift every nibble. It returns empty bytes instead.
    """
    assert _decode_hex("abc") == b""
    assert _decode_hex("0xabc") == b""


def test_load_run_meta_real_dataset() -> None:
    """Smoke-test against the dataset run dir (real capture or synthetic)."""
    run_dir = dataset_file(
        "dataset_memory_slice/gocryptfs/dataset_gocryptfs/run_0001"
    )

    meta = load_run_meta(run_dir)
    assert meta is not None
    assert meta.pid > 0
    assert meta.aslr_base == 0x400000
    assert "gcore" in meta.dumps


def test_load_run_meta_capture_absent_stays_none(tmp_path: Path) -> None:
    """No ``capture`` key (every corpus today) leaves the field ``None``."""
    _write_meta(tmp_path, {"cipher": "aes", "dumps": {}})
    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.capture is None


def test_load_run_meta_capture_parsed_when_present(tmp_path: Path) -> None:
    """Forward-compat: a declared capture path is carried through verbatim."""
    _write_meta(tmp_path, {"capture": "run_data/traffic.pcap", "dumps": {}})
    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.capture == "run_data/traffic.pcap"


def test_dataset_meta_capture_defaults_to_none() -> None:
    """The dataclass default keeps existing constructors working unchanged."""
    meta = DatasetMeta(
        run_id="r", cipher="", password="", master_key_hex="",
        master_key=b"", aslr_base=0, pid=0,
    )
    assert meta.capture is None
