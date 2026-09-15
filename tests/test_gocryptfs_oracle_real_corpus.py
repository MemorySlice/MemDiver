"""Real-corpus verification of the bundled gocryptfs oracle.

Why this module exists
----------------------
``docs/oracle/examples/gocryptfs.py`` is the Shape-2 oracle MemDiver ships and
the paper's §7 case study depends on -- yet until now nothing in the repo had
ever seen it return ``True``. Every "real sample" in ``tests/test_api_oracles.py``
is ``_fake_gocryptfs_sample`` = ``bytes(range(64))``: enough bytes for
``build_oracle`` to construct an instance, never enough to exercise ``verify()``.

That left the three things the oracle can actually get wrong completely
uncovered:

* the HKDF info string ``b"AES-GCM file content encryption"``,
* the block-0 AAD layout ``block_num(8 big-endian) || file_id(16)``,
* the ``version(2) || file_id(16)`` header offsets that locate the nonce.

A mistake in any of them makes ``verify()`` return ``False`` for *every*
candidate forever -- which is indistinguishable from "the master key is not in
this dump". That is precisely the failure mode that would silently invalidate
the case study, so it has to be pinned against real ciphertext.

These tests take a real gocryptfs vault file from the capture corpus and the
master key that run's ``meta.json`` recorded, and require the oracle to accept
that key and reject near-misses. A pass can only happen when the KDF, the AAD
and the offsets are all correct simultaneously.

Running them
------------
Point ``MEMDIVER_FIXTURE_ROOT`` at a capture-corpus root holding gocryptfs runs
(each run directory carrying a ``meta.json`` and a vault ``cipher/`` directory).
Runs are located by globbing for ``meta.json``, so both the flat
``<root>/gocryptfs/run_0001`` layout used by other fixture-backed tests and the
nested ``<root>/gocryptfs/dataset_gocryptfs/run_0001`` layout of the full corpus
work unchanged. Without the corpus -- or without the ``cryptography`` package --
everything here skips rather than fails.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

import pytest

from memdiver.core.dataset_metadata import DatasetMeta, load_run_meta
from memdiver.engine.oracle import load_oracle

# The oracle derives the content key with HKDF and decrypts with AES-GCM.
pytest.importorskip(
    "cryptography", reason="the gocryptfs oracle requires `pip install cryptography`"
)


# Tests requiring a real captured dataset look under ``MEMDIVER_FIXTURE_ROOT``.
# Set the env var to your local dataset root, or run the gocryptfs experiment
# harness to generate captures. If the env var is unset or no runs are found,
# these tests are skipped via the @pytest.mark.skipif marks below.
_FIXTURE_ROOT = Path(
    os.environ.get(
        "MEMDIVER_FIXTURE_ROOT",
        str(Path(__file__).parent / "fixtures" / "datasets"),
    )
)

_ORACLE_PATH = (
    Path(__file__).parent.parent / "docs" / "oracle" / "examples" / "gocryptfs.py"
)

# gocryptfs writes exactly these two metadata files into a vault's ciphertext
# directory; every other entry is an encrypted content file.
_VAULT_METADATA_FILENAMES = {"gocryptfs.conf", "gocryptfs.diriv"}

_MASTER_KEY_LENGTH = 32


def _find_vault_sample(run_dir: Path) -> Optional[Path]:
    """Return one encrypted content file from ``run_dir``'s vault, if present.

    The vault directory is found by looking for the ``gocryptfs.conf`` that
    marks it, rather than by assuming it is named ``cipher/``.
    """
    for conf in sorted(run_dir.rglob("gocryptfs.conf")):
        for entry in sorted(conf.parent.iterdir()):
            if entry.is_file() and entry.name not in _VAULT_METADATA_FILENAMES:
                return entry
    return None


def _find_run_with_cipher(cipher: str) -> Optional[Tuple[DatasetMeta, Path]]:
    """First run using ``cipher`` that also carries a usable vault sample.

    Runs are discovered by globbing for ``meta.json`` so no directory layout is
    baked in, and the metadata is parsed by the product's own
    :func:`load_run_meta` rather than by hand.
    """
    if not _FIXTURE_ROOT.is_dir():
        return None
    for meta_path in sorted(_FIXTURE_ROOT.rglob("meta.json")):
        run_dir = meta_path.parent
        meta = load_run_meta(run_dir)
        if meta is None or meta.cipher != cipher or not meta.master_key_hex:
            continue
        sample = _find_vault_sample(run_dir)
        if sample is not None:
            return meta, sample
    return None


_AES_RUN = _find_run_with_cipher("aes")
_XCHACHA_RUN = _find_run_with_cipher("xchacha")

_requires_aes_run = pytest.mark.skipif(
    _AES_RUN is None,
    reason=f"no gocryptfs aes run with a vault sample under {_FIXTURE_ROOT}",
)
_requires_xchacha_run = pytest.mark.skipif(
    _XCHACHA_RUN is None,
    reason=f"no gocryptfs xchacha run with a vault sample under {_FIXTURE_ROOT}",
)


def _build_verify(sample: Path):
    """Load the bundled oracle through the product's own loader.

    ``sandbox=False`` skips the subprocess pre-flight replay only; the
    in-process import + ``build_oracle`` path exercised here is the same code
    the CLI/MCP/web surfaces run.
    """
    return load_oracle(
        _ORACLE_PATH, {"sample_ciphertext": str(sample)}, sandbox=False
    )


@_requires_aes_run
def test_oracle_accepts_the_recorded_master_key():
    """The headline assertion: the real key decrypts the real ciphertext.

    This is the first test in the repo to make ``verify()`` return True, and it
    can only pass when the HKDF info string, the block-0 AAD and the header
    offsets are all simultaneously correct.
    """
    meta, sample = _AES_RUN
    verify = _build_verify(sample)

    assert verify(bytes.fromhex(meta.master_key_hex)) is True


@_requires_aes_run
def test_oracle_rejects_the_master_key_with_one_bit_flipped():
    """A near-miss must fail: proves the GCM tag is really being checked.

    Without this, a ``verify()`` that returned True unconditionally -- or that
    ignored the tag -- would still pass the acceptance test above.
    """
    meta, sample = _AES_RUN
    verify = _build_verify(sample)

    key = bytearray(bytes.fromhex(meta.master_key_hex))
    key[0] ^= 0x01
    assert verify(bytes(key)) is False


@_requires_aes_run
def test_oracle_rejects_a_wrong_length_candidate():
    """A truncated candidate is rejected by the length guard, not by an error.

    Sweeps feed the oracle arbitrary byte windows, so a non-32-byte candidate
    has to return False cleanly rather than raise.
    """
    meta, sample = _AES_RUN
    verify = _build_verify(sample)

    truncated = bytes.fromhex(meta.master_key_hex)[:16]
    assert len(truncated) != _MASTER_KEY_LENGTH
    assert verify(truncated) is False


@_requires_xchacha_run
def test_oracle_rejects_a_correct_key_from_an_xchacha_vault():
    """Pins the documented cipher-mode mismatch -- expected, not a bug.

    The key asserted here is the *correct* master key for this run: it is the
    one its own ``meta.json`` recorded. It still fails, because the bundled
    oracle only implements the AES-GCM content cipher, and this vault was
    written with gocryptfs's XChaCha20-Poly1305 mode (different KDF info string
    and AEAD). The oracle therefore cannot distinguish "wrong key" from
    "unsupported cipher mode" -- which is exactly why the paper reports
    XChaCha20 runs as INCONCLUSIVE rather than as failures.

    Locking this in means a future contributor who adds XChaCha20 support must
    come here and update the expectation deliberately, instead of discovering
    the silent-False behaviour in the middle of a case study.
    """
    meta, sample = _XCHACHA_RUN
    verify = _build_verify(sample)

    assert verify(bytes.fromhex(meta.master_key_hex)) is False
