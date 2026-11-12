"""``msl.verify`` (``vol3plugins/msl/verify.py``): chain + extension-segment verdicts.

Covers the verdict words (``valid`` / ``tampered`` / ``not verified``), the precision of the
tamper report (the chain breaks at the block AFTER the modified one), the stdlib SHA-256 and
SHA-512/256 chains with neither MemDiver nor ``blake3`` importable, and an encrypted capture.
"""

import sys

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins import msl_layer  # noqa: E402
from memdiver.vol3plugins.msl import verify  # noqa: E402
from tests.test_vol3plugins_msl_layer import _file_context, plain_slice  # noqa: E402,F401
from tests.test_vol3plugins_msl_slim import (  # noqa: E402
    _rechain, plain_rows, rich_slice, run_plugin, sample_msls, write_rich_slice)  # noqa: F401
from tests.test_vol3plugins_msl_slim import SAMPLE_GZ  # noqa: E402,F401

SAMPLES_DIR = SAMPLE_GZ[0].parent if SAMPLE_GZ else None


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def _rows(path, **config):
    return plain_rows(run_plugin(verify.Verify, path, **config)[0])


def _verdict(rows):
    return [r for r in rows if r[3] == "verdict"][0]


def _bare(monkeypatch):
    """No MemDiver and no blake3 in vol's Python (the layer then opens with msl_slim)."""
    monkeypatch.setitem(sys.modules, "memdiver", None)
    monkeypatch.setitem(sys.modules, "blake3", None)


def test_untouched_capture_is_valid_with_one_row_per_block(rich_slice):
    rows = _rows(rich_slice[0])
    blocks = [r for r in rows if r[0] == "block"]
    # provenance, index, 2 module entries, 2 threads, region, 5 hints, EoC
    assert len(blocks) == 1 + 1 + 2 + 2 + 1 + 5 + 1
    assert {r[5] for r in blocks} == {"ok"}
    assert _verdict(rows)[5] == "valid"
    summary = {r[3]: r[5] for r in rows if r[0] == "summary"}
    assert summary["hash chain"] == "ok" and summary["EoC FileHash"] == "ok"
    assert summary["block count"] == "ok"


def test_block_rows_name_types_and_offsets(rich_slice):
    rows = [r for r in _rows(rich_slice[0]) if r[0] == "block"]
    assert [r[1] for r in rows] == list(range(len(rows)))
    assert rows[0][2] == 64  # block 0 follows the 64-byte header
    assert rows[0][3] == "IMPORT_PROVENANCE" and rows[-1][3] == "END_OF_CAPTURE"
    assert "MEMORY_REGION" in {r[3] for r in rows} and "KEY_HINT" in {r[3] for r in rows}


def test_tampered_sample_is_reported_at_the_block_after_the_modified_one(sample_msls):
    rows = _rows(sample_msls["gocryptfs_aes_tampered.msl"])
    broken = [r for r in rows if r[5] == "link broken"]
    assert len(broken) == 1
    assert broken[0][3] == "VAS_MAP"  # the block after the modified MEMORY_REGION
    assert "block 13 (MEMORY_REGION at 0xC50)" in broken[0][6]
    verdict = _verdict(rows)
    assert verdict[5] == "tampered"
    summary = {r[3]: r[5] for r in rows if r[0] == "summary"}
    assert summary["hash chain"] == "tampered" and summary["EoC FileHash"] == "tampered"


def test_untampered_sample_is_valid(sample_msls):
    assert _verdict(_rows(sample_msls["gocryptfs_aes.msl"]))[5] == "valid"


@pytest.mark.parametrize("algo", [1, 2], ids=["sha256", "sha512_256"])
def test_stdlib_chains_verify_with_neither_memdiver_nor_blake3(rich_slice, monkeypatch, algo):
    rechained = _rechain(rich_slice[0], algo)
    _bare(monkeypatch)
    rows = _rows(rechained)
    assert _verdict(rows)[5] == "valid"
    assert {r[5] for r in rows if r[0] == "block"} == {"ok"}


def test_stdlib_chain_tamper_is_detected_bare(rich_slice, monkeypatch):
    rechained = _rechain(rich_slice[0], 1)
    raw = bytearray(rechained.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    rechained.write_bytes(raw)
    _bare(monkeypatch)
    assert _verdict(_rows(rechained))[5] == "tampered"


def test_blake3_without_blake3_says_needs_memdiver(rich_slice, monkeypatch):
    _bare(monkeypatch)
    rows = _rows(rich_slice[0])
    assert len(rows) == 1
    assert rows[0][3] == "verdict" and rows[0][5] == "not verified"
    assert "needs memdiver (BLAKE3" in rows[0][6] and "pip install memdiver" in rows[0][6]


def test_blake3_chain_with_memdiver_but_no_blake3_package_says_install_blake3(
        rich_slice, monkeypatch):
    monkeypatch.setitem(sys.modules, "blake3", None)
    rows = _rows(rich_slice[0])
    assert _verdict(rows)[5] == "not verified" and "pip install blake3" in _verdict(rows)[6]


def test_extension_segments_get_rows_and_a_bad_one_is_tampered(tmp_path):
    path = tmp_path / "ext.msl"
    write_rich_slice(path, extension=True)
    rows = _rows(path)
    segments = [r for r in rows if r[0] == "segment"]
    assert len(segments) == 1 and segments[0][5] == "verified"
    assert _verdict(rows)[5] == "valid"
    raw = bytearray(path.read_bytes())
    raw[int(segments[0][2]) + 0x50 + 3] ^= 0x01
    path.write_bytes(raw)
    msl_layer.close_slices()
    bad = _rows(path)
    assert [r[5] for r in bad if r[0] == "segment"] == ["FAILED"]
    assert _verdict(bad)[5] == "tampered"


def test_encrypted_capture_is_verified_by_memdiver(tmp_path, monkeypatch):
    from pathlib import Path

    samples = Path(SAMPLES_DIR)
    monkeypatch.setenv(msl_layer.KEY_FILE_ENV, str(samples / "gocryptfs_aes_encrypted.msl.key"))
    rows = _rows(samples / "gocryptfs_aes_encrypted.msl")
    assert _verdict(rows)[5] == "valid"
    assert not [r for r in rows if r[0] == "block"]  # per-block rows are plaintext-only


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    ctx = _file_context(plain_slice[0])
    ctx.config["plugins.P.primary"] = "FileLayer"
    rows = []
    verify.Verify(ctx, "plugins.P").run().populate(
        lambda node, acc: rows.append(node.values) or acc, None)
    assert rows == [] and "not an MSL capture layer" in caplog.text


def test_block_type_names_match_memdiver():
    from memdiver.msl.enums import BlockType

    for code, name in verify.BLOCK_TYPE_NAMES.items():
        assert BlockType(code).name == name
    assert verify.block_type_name(0x7777) == "0x7777"
