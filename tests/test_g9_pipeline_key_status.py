"""G9 regression: pipeline producers surface a locked encrypted dump.

The four pipeline producers in :mod:`memdiver.app.tools_pipeline` open
potentially-encrypted ``.msl`` dumps. An encrypted ``.msl`` opened without a
usable key does NOT raise on read — it reads back empty (size 0). Before the
G9 fix, that empty read was misattributed:

* ``consensus``      -> "empty or mismatched dumps"      (PRECONDITION)
* ``export_pattern`` -> "No KEY_CANDIDATE regions found" (NoVolatileRegionsError)
* ``n_sweep``        -> silent bogus negative (first_hit_n=None)
* ``auto_floor``     -> bogus verdict on empty reference

Each producer now checks :meth:`KeyStatus.from_source` on the opened source(s)
BEFORE that empty/negative handling and raises
:class:`EncryptedDumpLockedError` (a ``CapabilityError`` subclass, code
``encrypted_dump_locked``). A genuinely-empty-but-DECRYPTED input must STILL
yield the existing empty-result error — the last test guards against
over-triggering.

The encrypted-``.msl`` fixture mirrors ``tests/test_architecture_invariants``
and skips when the AES-256-GCM backend is absent.
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pytest

from memdiver.app import tools_pipeline
from memdiver.core.service_errors import CapabilityError, EncryptedDumpLockedError


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096) -> None:
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(str(path), pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


@pytest.fixture
def locked_msl(tmp_path):
    """Two encrypted ``.msl`` files; producers open them WITHOUT a key => locked."""
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    a = tmp_path / "a.msl"
    b = tmp_path / "b.msl"
    _write_encrypted_msl(a, key)
    _write_encrypted_msl(b, key)
    return str(a), str(b)


def test_consensus_locked_raises_encrypted_dump_locked(tmp_path, locked_msl):
    a, b = locked_msl
    with pytest.raises(EncryptedDumpLockedError) as excinfo:
        tools_pipeline.consensus(dump_paths=[a, b], output_dir=str(tmp_path / "out"))
    assert excinfo.value.code == "encrypted_dump_locked"
    # NOT the old misattributed empty-variance message.
    assert "empty or mismatched" not in str(excinfo.value)


def test_export_pattern_locked_raises_encrypted_dump_locked(tmp_path, locked_msl):
    a, b = locked_msl
    with pytest.raises(EncryptedDumpLockedError) as excinfo:
        tools_pipeline.export_pattern(dump_paths=[a, b], output_dir=str(tmp_path / "out"))
    assert excinfo.value.code == "encrypted_dump_locked"
    # NOT the old misattributed no-regions message.
    assert "No KEY_CANDIDATE" not in str(excinfo.value)


def test_n_sweep_locked_raises_encrypted_dump_locked(tmp_path, locked_msl):
    a, b = locked_msl
    # The lock is detected while opening sources, before the oracle is loaded,
    # so no valid oracle is required to prove the fix (old behaviour was a
    # silent first_hit_n=None negative).
    with pytest.raises(EncryptedDumpLockedError) as excinfo:
        tools_pipeline.n_sweep(
            source_paths=[a, b],
            oracle_path=str(tmp_path / "unused_oracle.py"),
            output_dir=str(tmp_path / "out"),
            n_values=[2],
        )
    assert excinfo.value.code == "encrypted_dump_locked"


def test_auto_floor_locked_raises_encrypted_dump_locked(tmp_path, locked_msl):
    a, _b = locked_msl
    variance_path = tmp_path / "variance.npy"
    np.save(variance_path, np.zeros(64, dtype=np.float32))
    # The reference dump is locked; the lock is detected right after loading the
    # variance and before the oracle is loaded, so no valid oracle is required.
    with pytest.raises(EncryptedDumpLockedError) as excinfo:
        tools_pipeline.auto_floor(
            variance_path=str(variance_path),
            reference_path=a,
            oracle_path=str(tmp_path / "unused_oracle.py"),
            output_dir=str(tmp_path / "out"),
            num_dumps=2,
        )
    assert excinfo.value.code == "encrypted_dump_locked"


def test_consensus_empty_decrypted_keeps_existing_error(tmp_path):
    """Guard against over-triggering: a genuinely empty-but-DECRYPTED input
    must still raise the existing empty-result CapabilityError, NOT the new
    EncryptedDumpLockedError. Two empty plaintext dumps have no key state
    (decrypted=True) yet produce a size-0 consensus."""
    a = tmp_path / "a.dump"
    b = tmp_path / "b.dump"
    a.write_bytes(b"")
    b.write_bytes(b"")
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.consensus(dump_paths=[str(a), str(b)], output_dir=str(tmp_path / "out"))
    assert not isinstance(excinfo.value, EncryptedDumpLockedError)
    assert "empty or mismatched" in str(excinfo.value)
