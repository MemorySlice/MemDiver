"""Header ``CipherLen`` (spec 1.1.1 §3.2 Table 5, §10.2, §10.7).

The AAD and the EoC FileHash cover the header with bytes 0x78-0x7F zeroed;
the primary tag sits right after ``CipherLen`` ciphertext bytes (or in the
last 16 bytes when ``CipherLen=0``), so data after the tag no longer breaks
authentication. Every case runs in both reader modes (one-shot and seek).
"""

import os
import struct

import pytest

from memdiver.msl import crypto
from memdiver.msl.aead_seek import ONESHOT_ENV, TAG_LEN
from memdiver.msl.enums import (CIPHER_LEN_OFFSET, FILE_HEADER_ENC_SIZE,
                                EncAlgo, TagStatus)
from memdiver.msl.integrity import verify_chain
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

_CIPHERS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]
_KEY = bytes(range(32))
_DATA = bytes(range(256)) * 32
_TRAILER = b"TRAILING-NON-MSL-DATA" * 5


@pytest.fixture(params=["oneshot", "seek"])
def mode(request, monkeypatch):
    if request.param == "oneshot":
        monkeypatch.setenv(ONESHOT_ENV, "1")
    else:
        monkeypatch.delenv(ONESHOT_ENV, raising=False)
    return request.param


@pytest.fixture(params=_CIPHERS, ids=lambda a: a.name)
def algo(request):
    if not crypto.cipher_is_available(request.param):
        pytest.skip(f"{request.param.name} backend not installed")
    return request.param


def _write(path, algo, *, streaming=False, nonce=None):
    cfg = MslEncryptionConfig(enc_algo=algo, raw_key=_KEY, nonce=nonce)
    w = MslWriter(path, pid=11, encryption=cfg)
    w.add_memory_region(0x4000, _DATA)
    w.add_end_of_capture()
    w.write_streaming() if streaming else w.write()
    return path


def _cipher_len(raw: bytes) -> int:
    return struct.unpack_from("<Q", raw, CIPHER_LEN_OFFSET)[0]


def _set_cipher_len(path, value: int) -> None:
    raw = bytearray(path.read_bytes())
    struct.pack_into("<Q", raw, CIPHER_LEN_OFFSET, value)
    path.write_bytes(bytes(raw))


def _open_ok(path):
    """Open with the key; assert VALID + intact FileHash; return the facts."""
    with MslReader(path, key=_KEY) as r:
        assert r.tag_status is TagStatus.VALID
        report = verify_chain(r)
        assert report.valid and report.file_hash_ok is True
        regions = r.collect_regions()
        assert len(regions) == 1 and regions[0].base_addr == 0x4000
        return r.post_tag_offset, r._enc_params.cipher_len


def _status(path) -> TagStatus:
    with MslReader(path, key=_KEY) as r:
        if r.tag_status is not TagStatus.VALID:
            assert r._buf is None and r.post_tag_offset is None
        return r.tag_status


# ------------------------------------------------------------- helpers

def test_header_without_cipher_len_zeroes_only_the_field():
    header = bytes(range(128))
    zeroed = crypto.header_without_cipher_len(header)
    assert zeroed[:CIPHER_LEN_OFFSET] == header[:CIPHER_LEN_OFFSET]
    assert zeroed[CIPHER_LEN_OFFSET:CIPHER_LEN_OFFSET + 8] == b"\x00" * 8
    assert zeroed[CIPHER_LEN_OFFSET + 8:] == header[CIPHER_LEN_OFFSET + 8:]
    assert crypto.header_without_cipher_len(header[:64]) == header[:64]


def test_encryption_aad_appends_kem_ciphertext():
    header = b"\xFF" * 128
    aad = crypto.encryption_aad(header, b"KEM")
    assert aad == b"\xFF" * 0x78 + b"\x00" * 8 + b"KEM"


# -------------------------------------------------------------- writer

@pytest.mark.parametrize("streaming", [False, True], ids=["write", "streaming"])
def test_writer_records_final_cipher_len(tmp_path, algo, streaming):
    raw = _write(tmp_path / "f.msl", algo, streaming=streaming).read_bytes()
    assert _cipher_len(raw) == len(raw) - FILE_HEADER_ENC_SIZE - TAG_LEN
    assert _cipher_len(raw) != 0


def test_streaming_and_in_memory_agree_on_cipher_len(tmp_path, algo):
    nonce = os.urandom(24)
    a = _write(tmp_path / "a.msl", algo, nonce=nonce).read_bytes()
    b = _write(tmp_path / "b.msl", algo, nonce=nonce, streaming=True).read_bytes()
    assert _cipher_len(a) == _cipher_len(b)


# -------------------------------------------------------------- reader

def test_roundtrip_with_cipher_len(tmp_path, algo, mode):
    path = _write(tmp_path / "f.msl", algo)
    post_tag, cipher_len = _open_ok(path)
    assert cipher_len == path.stat().st_size - FILE_HEADER_ENC_SIZE - TAG_LEN
    assert post_tag == path.stat().st_size


def test_legacy_zero_cipher_len_still_readable(tmp_path, algo, mode):
    path = _write(tmp_path / "f.msl", algo)
    _set_cipher_len(path, 0)  # a 1.1.0 file: same AAD, tag at EOF-16
    post_tag, cipher_len = _open_ok(path)
    assert cipher_len == 0 and post_tag == path.stat().st_size


def test_trailing_data_after_tag_is_valid(tmp_path, algo, mode):
    path = _write(tmp_path / "f.msl", algo)
    size = path.stat().st_size
    with open(path, "ab") as f:
        f.write(_TRAILER)
    post_tag, _ = _open_ok(path)
    assert post_tag == size  # follow-up parses sealed segments from here


def test_trailing_data_without_cipher_len_fails(tmp_path, algo, mode):
    path = _write(tmp_path / "f.msl", algo)
    _set_cipher_len(path, 0)
    with open(path, "ab") as f:
        f.write(_TRAILER)
    assert _status(path) is TagStatus.CORRUPTED  # tag is taken at EOF-16


@pytest.mark.parametrize("delta", [-16, -1, 1])
def test_tampered_cipher_len_is_corrupted(tmp_path, algo, mode, delta):
    path = _write(tmp_path / "f.msl", algo)
    with open(path, "ab") as f:
        f.write(_TRAILER)  # keeps +1 in bounds
    _set_cipher_len(path, _cipher_len(path.read_bytes()) + delta)
    assert _status(path) is TagStatus.CORRUPTED


@pytest.mark.parametrize("excess", [1, 1 << 20, None], ids=["by1", "1MiB", "u64max"])
def test_out_of_bounds_cipher_len_is_corrupted(tmp_path, algo, mode, excess):
    path = _write(tmp_path / "f.msl", algo)
    limit = path.stat().st_size - FILE_HEADER_ENC_SIZE - TAG_LEN
    _set_cipher_len(path, (1 << 64) - 1 if excess is None else limit + excess)
    assert _status(path) is TagStatus.CORRUPTED
