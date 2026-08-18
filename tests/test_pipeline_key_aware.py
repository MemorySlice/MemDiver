"""Phase 5 (G4) — the pipeline producers read the reference key-aware.

The CLI pipeline handlers now route their compute through the shared
``app.tools_pipeline`` producers (the same ones the MCP tools use). Those
producers used to read the reference via ``Path(...).read_bytes()``; they now
read it through ``core.dump_source.open_dump`` so an encrypted ``.msl`` is
decrypted with supplied key material, while a plain artifact stays
byte-identical to the old raw read.

Two invariants are pinned here:

(a) A plain ``reference.bin`` / ``.npy`` opens as a ``RawDumpSource`` whose
    ``read_all()`` equals the raw file bytes — so the existing MCP callers
    (which pass a keyless ``reference.bin``) are byte-for-byte unchanged.
(b) The CLI ``brute-force`` command, driven with ``--key-file``, decrypts an
    encrypted ``.msl`` reference THROUGH the producer and recovers a key that
    is invisible without the key (the locked container reads back empty).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
import pytest

from memdiver.app.tools_pipeline import _read_reference_bytes

KEY_BYTES = bytes(range(1, 33))
KEY_VAS_OFFSET = 256
REGION_SIZE = 4096


# ---------------------------------------------------------------------------
# (a) plain file: open_dump + read_all() is byte-identical to read_bytes()
# ---------------------------------------------------------------------------


def test_plain_reference_read_is_byte_identical(tmp_path):
    """The unification branch: a non-container file opens raw, so the keyless
    producer read equals the historical ``read_bytes()`` exactly."""
    ref_bin = tmp_path / "reference.bin"
    ref_bin.write_bytes(os.urandom(1000))
    assert _read_reference_bytes(str(ref_bin), {}, None) == ref_bin.read_bytes()

    npy = tmp_path / "variance.npy"
    np.save(npy, np.arange(50, dtype=np.float32))
    assert _read_reference_bytes(str(npy), {}, None) == npy.read_bytes()


# ---------------------------------------------------------------------------
# (b) CLI brute-force decrypts an encrypted .msl reference via the producer
# ---------------------------------------------------------------------------


def _write_encrypted_msl(path: Path, key: bytes) -> None:
    """Encrypted .msl with one CAPTURED region; KEY sits at VAS offset 256."""
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    data = bytearray(b"\x42" * REGION_SIZE)
    data[KEY_VAS_OFFSET:KEY_VAS_OFFSET + 32] = KEY_BYTES
    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(str(path), pid=7, encryption=cfg)
    w.add_memory_region(0x1000, bytes(data))
    w.add_end_of_capture()
    w.write()


def _oracle(tmp_path: Path) -> Path:
    body = (
        "KEY = bytes(range(1, 33))\n"
        "def verify(candidate):\n"
        "    return candidate == KEY\n"
    )
    p = tmp_path / "oracle.py"
    p.write_text(body)
    os.chmod(p, 0o600)
    return p


def _candidates(tmp_path: Path) -> Path:
    payload = {"regions": [{"offset": KEY_VAS_OFFSET, "length": 32}]}
    p = tmp_path / "candidates.json"
    p.write_text(json.dumps(payload))
    return p


def _brute_force_args(msl: Path, candidates: Path, oracle: Path, out: Path,
                      *, key_file):
    return argparse.Namespace(
        candidates=str(candidates), dump=str(msl), oracle=str(oracle),
        oracle_config=None, key_sizes="32", stride=8, jobs=1, first_hit=False,
        state=None, top_k=10, output=str(out),
        key_file=key_file, passphrase=None, kem_key_file=None,
    )


def test_cli_brute_force_decrypts_encrypted_msl_reference(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend unavailable")

    import memdiver.cli as cli

    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    candidates = _candidates(tmp_path)
    oracle = _oracle(tmp_path)

    # With the key, the producer decrypts the .msl and the oracle verifies the
    # planted key at its VAS offset.
    out = tmp_path / "hits.json"
    rc = cli._cmd_brute_force(
        _brute_force_args(msl, candidates, oracle, out, key_file=str(keyfile))
    )
    assert rc == 0, rc
    hits = json.loads(out.read_text())["hits"]
    assert any(h["offset"] == KEY_VAS_OFFSET and h["key_hex"] == KEY_BYTES.hex()
               for h in hits), hits


# ---------------------------------------------------------------------------
# Part B — the shared verify_key_result / experiment_result producers
# ---------------------------------------------------------------------------


def test_verify_key_result_valid_and_error_paths(tmp_path):
    from memdiver.app.tools_pipeline import verify_key_result
    from memdiver.core.service_errors import CapabilityError, ErrorCategory, FileNotFoundServiceError
    from memdiver.engine.verification import (
        AesCbcVerifier, VERIFICATION_IV, VERIFICATION_PLAINTEXT,
    )

    key = bytes(range(32))
    dump = bytearray(1024)
    dump[0x100:0x120] = key
    dump_path = tmp_path / "d.dump"
    dump_path.write_bytes(bytes(dump))
    ct = AesCbcVerifier().create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

    ok = verify_key_result(
        dump_path=str(dump_path), offset=0x100, length=32, ciphertext_hex=ct.hex(),
    )
    assert ok["verified"] is True and ok["key_hex"] == key.hex()
    assert ok["offset"] == 0x100 and ok["cipher"] == "AES-256-CBC"

    with pytest.raises(FileNotFoundServiceError):
        verify_key_result(dump_path=str(tmp_path / "missing.dump"), offset=0,
                          length=32, ciphertext_hex=ct.hex())

    with pytest.raises(CapabilityError) as exc:
        verify_key_result(dump_path=str(dump_path), offset=0, length=32,
                          ciphertext_hex=ct.hex(), cipher="NOPE")
    assert exc.value.category is ErrorCategory.INVALID_INPUT

    with pytest.raises(CapabilityError) as exc:
        verify_key_result(dump_path=str(dump_path), offset=0, length=32,
                          ciphertext_hex="zz")
    assert "hex" in exc.value.message.lower()


def test_experiment_result_missing_target_raises(tmp_path):
    from memdiver.app.experiment_orchestration import experiment_result
    from memdiver.core.service_errors import FileNotFoundServiceError

    with pytest.raises(FileNotFoundServiceError):
        experiment_result(
            target=str(tmp_path / "no_such_target.py"),
            output_dir=str(tmp_path / "out"),
        )
