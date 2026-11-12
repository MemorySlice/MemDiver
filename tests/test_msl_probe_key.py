"""``msl.reader.probe_key`` / ``MslReader.probe_key``: a key checked on block 0 only.

The preflight of a background synthesis job must refuse a missing or wrong
container key on the request thread WITHOUT the whole-file AEAD tag pass. The
probe derives the content key once (the legacy weak-Argon2id retry kept) and
decrypts only the first cipher bytes, which must be the block magic.

Pinned here: it agrees with a full open on every key outcome, it never runs
``verify_tag_streaming`` nor builds a ``DecryptedView``, and its documented
LIMIT -- a container tampered beyond block 0's magic still probes VALID.
"""

from __future__ import annotations

import gzip
import os
import shutil
from pathlib import Path

import pytest

from memdiver.msl import crypto
from memdiver.msl import reader as reader_mod
from memdiver.msl.aead_seek import TAG_LEN
from memdiver.msl.enums import EncAlgo, KdfType, KeyEncap, TagStatus
from memdiver.msl.reader import MslReader, probe_key
from memdiver.msl.types import MslAuthError, MslCryptoError, MslParseError
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

pytest.importorskip("cryptography")

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
ENCRYPTED = SAMPLES / "gocryptfs_aes_encrypted.msl"
PLAIN_GZ = SAMPLES / "gocryptfs_aes.msl.gz"
needs_samples = pytest.mark.skipif(not ENCRYPTED.exists() or not PLAIN_GZ.exists(),
                                   reason="samples/ not present")
PASSPHRASE = b"correct horse"
WEAK = (1, 8, 1)


def _sample_key() -> bytes:
    return (SAMPLES / "gocryptfs_aes_encrypted.msl.key").read_bytes()


def _full_status(path: Path, **km) -> TagStatus:
    with MslReader(path, **km) as reader:
        return reader.tag_status


def _copy(tmp_path: Path, name: str = "copy.msl") -> Path:
    return Path(shutil.copyfile(ENCRYPTED, tmp_path / name))


def _flip(path: Path, offset: int) -> Path:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    return path


def _bounds(path: Path, **km) -> tuple:
    """``(ciphertext start, ciphertext end)`` of a container the key opens."""
    with MslReader(path, **km) as reader:
        return reader._ciphertext_start(), reader.post_tag_offset - TAG_LEN


def _write(path: Path, cfg: MslEncryptionConfig) -> Path:
    writer = MslWriter(path, pid=7, encryption=cfg)
    writer.add_memory_region(0x1000, b"\xab" * 4096)
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def kdf_calls(monkeypatch):
    """Every content-key derivation of the reader (looked up in ``msl.reader``)."""
    calls = []
    real = reader_mod.derive_cek_consumer

    def counting(**kwargs):
        calls.append(kwargs["enforce_minimum"])
        return real(**kwargs)
    monkeypatch.setattr(reader_mod, "derive_cek_consumer", counting)
    return calls


class _RefusedView:
    """Stands in for ``DecryptedView`` (``close()`` isinstance-checks it): never built."""

    def __init__(self, *_a, **_k):
        raise AssertionError("probe_key must not build a DecryptedView")


@pytest.fixture
def no_full_pass(monkeypatch):
    """Fail the test if the probe runs the whole-file tag pass or builds a view."""
    def refuse(*_a, **_k):
        raise AssertionError("probe_key must not run the full AEAD pass")
    monkeypatch.setattr(reader_mod, "verify_tag_streaming", refuse)
    monkeypatch.setattr(reader_mod, "DecryptedView", _RefusedView)


# -- the sample container -----------------------------------------------------------

@needs_samples
def test_right_key_is_valid_with_one_derivation_and_no_full_pass(kdf_calls, no_full_pass):
    assert probe_key(ENCRYPTED, key=_sample_key()) is TagStatus.VALID
    assert kdf_calls == [False]


@needs_samples
def test_wrong_key_is_corrupted(no_full_pass):
    assert probe_key(ENCRYPTED, key=bytes(31) + b"\x01") is TagStatus.CORRUPTED


@needs_samples
def test_no_key_is_missing_key_without_a_derivation(kdf_calls, no_full_pass):
    assert probe_key(ENCRYPTED) is TagStatus.MISSING_KEY
    assert kdf_calls == []


@needs_samples
def test_plaintext_msl_is_not_encrypted(tmp_path, kdf_calls):
    plain = tmp_path / "plain.msl"
    with gzip.open(PLAIN_GZ, "rb") as src, open(plain, "wb") as dst:
        shutil.copyfileobj(src, dst)
    assert probe_key(plain, key=_sample_key()) is TagStatus.NOT_ENCRYPTED
    assert _full_status(plain) is TagStatus.NOT_ENCRYPTED
    assert kdf_calls == []


@needs_samples
def test_a_flip_near_the_end_still_probes_valid_the_documented_limit(tmp_path):
    copy = _copy(tmp_path)
    _flip(copy, _bounds(copy, key=_sample_key())[1] - 1)  # last ciphertext byte
    assert probe_key(copy, key=_sample_key()) is TagStatus.VALID
    assert _full_status(copy, key=_sample_key()) is TagStatus.CORRUPTED


@needs_samples
def test_a_flip_in_block0_magic_is_caught(tmp_path):
    copy = _copy(tmp_path)
    _flip(copy, _bounds(copy, key=_sample_key())[0])
    assert probe_key(copy, key=_sample_key()) is TagStatus.CORRUPTED


@needs_samples
@pytest.mark.parametrize("keep", [-1, -TAG_LEN - 1, 128 + 4, 128])
def test_a_truncated_container_is_corrupted(tmp_path, keep, no_full_pass):
    data = ENCRYPTED.read_bytes()
    copy = tmp_path / "short.msl"
    copy.write_bytes(data[:keep] if keep > 0 else data[:len(data) + keep])
    assert probe_key(copy, key=_sample_key()) is TagStatus.CORRUPTED


@needs_samples
def test_the_reader_is_left_closed_and_an_open_reader_answers_its_status():
    reader = MslReader(ENCRYPTED, key=_sample_key())
    assert reader.probe_key() is TagStatus.VALID
    assert reader._mmap is None and reader._file is None
    with MslReader(ENCRYPTED, key=bytes(32)) as opened:
        assert opened.probe_key() is opened.tag_status is TagStatus.CORRUPTED
        assert opened._mmap is not None  # an opened reader is not closed by the probe


@needs_samples
def test_the_content_key_is_wiped(monkeypatch):
    seen = []
    real = reader_mod.SeekableDecryptor

    def spy(algo, key, nonce):
        seen.append(key)
        return real(algo, key, nonce)
    monkeypatch.setattr(reader_mod, "SeekableDecryptor", spy)
    assert probe_key(ENCRYPTED, key=_sample_key()) is TagStatus.VALID
    (cek,) = seen
    assert isinstance(cek, bytearray) and not any(cek)
    assert _sample_key() != bytes(32)  # the caller's key itself is untouched


# -- other key forms, the same answer as a full open ---------------------------------------

@pytest.mark.parametrize("algo", [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305],
                         ids=lambda a: a.name)
def test_raw_key_containers_agree_with_a_full_open(tmp_path, algo, no_full_pass):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    key = os.urandom(32)
    path = _write(tmp_path / "raw.msl", MslEncryptionConfig(enc_algo=algo, raw_key=key))
    assert probe_key(path, key=key) is TagStatus.VALID
    assert probe_key(path, key=os.urandom(32)) is TagStatus.CORRUPTED
    assert probe_key(path) is TagStatus.MISSING_KEY


def test_x25519_container_agrees_with_a_full_open(tmp_path):
    if not crypto.kem_is_available(KeyEncap.X25519):
        pytest.skip("X25519 not available")
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519)
    _, other = crypto.kem_generate_keypair(KeyEncap.X25519)
    path = _write(tmp_path / "kem.msl",
                  MslEncryptionConfig(key_encap=KeyEncap.X25519, recipient_public=pub))
    for km, status in (({"kem_private_key": priv}, TagStatus.VALID),
                       ({"kem_private_key": other}, TagStatus.CORRUPTED),
                       ({"key": os.urandom(32)}, TagStatus.MISSING_KEY)):
        assert probe_key(path, **km) is status == _full_status(path, **km)


def test_a_short_raw_key_is_missing_key_like_a_full_open(tmp_path):
    """``MslCryptoError`` (a 31-byte raw key) maps to MISSING_KEY, as in ``open``."""
    key = os.urandom(32)
    path = _write(tmp_path / "raw.msl", MslEncryptionConfig(raw_key=key))
    assert probe_key(path, key=key[:31]) is TagStatus.MISSING_KEY
    assert _full_status(path, key=key[:31]) is TagStatus.MISSING_KEY


def test_an_unknown_cipher_byte_is_corrupted_like_a_full_open(tmp_path):
    key = os.urandom(32)
    path = _write(tmp_path / "bad_algo.msl", MslEncryptionConfig(raw_key=key))
    data = bytearray(path.read_bytes())
    data[0x40] = 0x7E  # EncAlgo byte: not a defined value
    path.write_bytes(bytes(data))
    assert probe_key(path, key=key) is TagStatus.CORRUPTED == _full_status(path, key=key)


def test_a_tampered_header_is_not_detected_the_documented_limit(tmp_path):
    key = os.urandom(32)
    path = _write(tmp_path / "hdr.msl", MslEncryptionConfig(raw_key=key))
    _flip(path, 0x34)  # a PID byte: only the AEAD tag (AAD) covers it
    assert probe_key(path, key=key) is TagStatus.VALID
    assert _full_status(path, key=key) is TagStatus.CORRUPTED


def test_header_errors_raise_like_a_full_open(tmp_path):
    tiny = tmp_path / "tiny.msl"
    tiny.write_bytes(b"MEMSLICE")
    with pytest.raises(MslParseError, match="too small"):
        probe_key(tiny)
    with pytest.raises(MslParseError, match="too small"):
        MslReader(tiny).open()


def test_failure_status_maps_like_setup_decryption():
    assert MslReader._failure_status(MslCryptoError("x")) is TagStatus.MISSING_KEY
    assert MslReader._failure_status(MslAuthError("x")) is TagStatus.CORRUPTED
    assert MslReader._failure_status(ValueError("x")) is TagStatus.CORRUPTED


# -- passphrase (Argon2id), incl. the legacy weak-parameter retry --------------------------

needs_argon2 = pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID),
                                  reason="argon2-cffi not installed")


def _weak_header_cfg() -> MslEncryptionConfig:
    """Header stores WEAK params; the CEK is derived with clamped ones (old MemDiver)."""
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE)
    cfg.kdf_time, cfg.kdf_memory, cfg.kdf_lanes = WEAK
    return cfg


@needs_argon2
def test_passphrase_container(tmp_path, kdf_calls, no_full_pass):
    path = _write(tmp_path / "pass.msl",
                  MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE))
    assert probe_key(path, passphrase=PASSPHRASE) is TagStatus.VALID
    assert probe_key(path, passphrase=b"wrong") is TagStatus.CORRUPTED
    assert probe_key(path) is TagStatus.MISSING_KEY
    assert kdf_calls == [False, False]  # strong params: no retry on a wrong passphrase


@needs_argon2
def test_legacy_weak_param_container_is_valid_via_the_clamped_retry(tmp_path, kdf_calls):
    path = _write(tmp_path / "legacy.msl", _weak_header_cfg())
    assert probe_key(path, passphrase=PASSPHRASE) is TagStatus.VALID
    assert kdf_calls == [False, True]
    assert _full_status(path, passphrase=PASSPHRASE) is TagStatus.VALID
    kdf_calls.clear()
    assert probe_key(path, passphrase=b"wrong") is TagStatus.CORRUPTED
    assert kdf_calls == [False, True]  # retried once, then refused


@needs_argon2
def test_exact_weak_param_container_needs_no_retry(tmp_path, monkeypatch, kdf_calls):
    with monkeypatch.context() as m:
        m.setattr(crypto, "clamp_argon2id_params", lambda t, mem, lanes: (t, mem, lanes))
        path = _write(tmp_path / "exact.msl", _weak_header_cfg())
    assert probe_key(path, passphrase=PASSPHRASE) is TagStatus.VALID
    assert kdf_calls == [False]
