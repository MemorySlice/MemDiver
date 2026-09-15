"""Tests for :mod:`core.dataset_metadata`."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from memdiver.core.dataset_metadata import (
    DatasetMeta,
    DumpRef,
    _decode_hex,
    load_run_meta,
    resolve_declared_subpath,
)
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


# -- vault_cipher_dir ---------------------------------------------------------
#
# The gocryptfs corpus names the vault whose master key its dumps carry. The
# declaration is corpus-authored data, so it passes the same traversal guard
# ``capture`` does.


def test_load_run_meta_vault_cipher_dir_absent_stays_none(tmp_path: Path) -> None:
    """A corpus that ships no vault leaves the field ``None``, not ``""``."""
    _write_meta(tmp_path, {"cipher": "aes", "dumps": {}})
    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.vault_cipher_dir is None


def test_load_run_meta_vault_cipher_dir_parsed_when_present(tmp_path: Path) -> None:
    """The declared directory is carried through verbatim."""
    _write_meta(tmp_path, {"vault_cipher_dir": "run_0001/cipher", "dumps": {}})
    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.vault_cipher_dir == "run_0001/cipher"


def test_dataset_meta_vault_cipher_dir_defaults_to_none() -> None:
    """The dataclass default keeps existing constructors working unchanged."""
    meta = DatasetMeta(
        run_id="r", cipher="", password="", master_key_hex="",
        master_key=b"", aslr_base=0, pid=0,
    )
    assert meta.vault_cipher_dir is None
    assert meta.vault_dir() is None


def test_vault_dir_resolves_against_the_run_directory(tmp_path: Path) -> None:
    """``source_path`` is the meta.json, so the vault hangs off its parent."""
    (tmp_path / "cipher").mkdir()
    _write_meta(tmp_path, {"vault_cipher_dir": "cipher", "dumps": {}})

    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.vault_dir() == tmp_path / "cipher"


def test_vault_dir_resolves_the_dataset_root_relative_spelling(tmp_path: Path) -> None:
    """The real corpus writes ``run_0001/cipher`` -- relative to the DATASET ROOT.

    Regression guard. ``vault_cipher_dir`` is written exactly like the ``dumps``
    entries beside it (``run_0001/gcore.core``), so a run-dir-only resolver looks
    for ``run_0001/run_0001/cipher``, finds nothing, and returns ``None`` for
    every run in the shipped dataset -- a feature that silently does nothing on
    real data while every synthetic test using the bare ``cipher`` form passes.
    """
    run_dir = tmp_path / "run_0001"
    (run_dir / "cipher").mkdir(parents=True)
    _write_meta(run_dir, {"vault_cipher_dir": "run_0001/cipher", "dumps": {}})

    meta = load_run_meta(run_dir)
    assert meta is not None
    assert meta.vault_dir() == run_dir / "cipher"


def test_vault_dir_is_none_when_the_directory_was_never_shipped(tmp_path: Path) -> None:
    """A declaration pointing at nothing is "no vault", not a dangling path."""
    _write_meta(tmp_path, {"vault_cipher_dir": "cipher", "dumps": {}})

    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.vault_dir() is None


def test_vault_dir_is_none_when_the_declaration_names_a_file(tmp_path: Path) -> None:
    """Only a directory can be a vault; a regular file is rejected."""
    (tmp_path / "cipher").write_bytes(b"not a directory")
    _write_meta(tmp_path, {"vault_cipher_dir": "cipher", "dumps": {}})

    meta = load_run_meta(tmp_path)
    assert meta is not None
    assert meta.vault_dir() is None


def test_vault_dir_rejects_an_absolute_declaration(tmp_path, caplog) -> None:
    """Corpus data may not point the scanner outside the run dir."""
    outside = tmp_path / "outside"
    outside.mkdir()
    run_dir = tmp_path / "run_0001"
    run_dir.mkdir()
    _write_meta(run_dir, {"vault_cipher_dir": str(outside), "dumps": {}})

    meta = load_run_meta(run_dir)
    assert meta is not None
    with caplog.at_level(logging.WARNING, logger="memdiver.core.dataset_metadata"):
        assert meta.vault_dir() is None
    assert "vault_cipher_dir" in caplog.text


def test_vault_dir_rejects_a_parent_traversal(tmp_path, caplog) -> None:
    """``..`` components are rejected rather than escaping the run dir."""
    (tmp_path / "outside").mkdir()
    run_dir = tmp_path / "run_0001"
    run_dir.mkdir()
    _write_meta(run_dir, {"vault_cipher_dir": "../outside", "dumps": {}})

    meta = load_run_meta(run_dir)
    assert meta is not None
    with caplog.at_level(logging.WARNING, logger="memdiver.core.dataset_metadata"):
        assert meta.vault_dir() is None
    assert "../outside" in caplog.text


def test_resolve_declared_subpath_is_the_guard_capture_uses(tmp_path: Path) -> None:
    """One guard, two keys: the capture path resolves through it identically."""
    assert resolve_declared_subpath(tmp_path, "a/b.pcap", kind="capture") == (
        tmp_path / "a" / "b.pcap"
    )
    assert resolve_declared_subpath(tmp_path, None, kind="capture") is None
    assert resolve_declared_subpath(tmp_path, "", kind="capture") is None
    assert resolve_declared_subpath(tmp_path, "/etc/passwd", kind="capture") is None
    assert resolve_declared_subpath(tmp_path, "../x", kind="capture") is None
