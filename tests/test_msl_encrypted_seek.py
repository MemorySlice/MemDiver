"""Verify-once + seek decryption of encrypted .msl containers (msl/aead_seek.py).

The default reader path verifies the AEAD tag in one bounded streamed pass and
then decrypts plaintext ranges on demand. Every observable result must equal
the legacy one-shot path (``MEMDIVER_MSL_DECRYPT_ONESHOT=1``).
"""

import hashlib
import os
import random
import struct
import time
import tracemalloc

import pytest

from memdiver.core.msl_helpers import get_region_page_data
from memdiver.msl import crypto
from memdiver.msl.aead_seek import (CACHE_PAGE, ONESHOT_ENV, DecryptedView,
                                    MslSourceChangedError, SeekableDecryptor,
                                    _aes_ctr32, oneshot_requested,
                                    verify_tag_streaming)
from memdiver.msl.enums import EncAlgo, KdfType, KeyEncap, NodeKind, TagStatus
from memdiver.msl.reader import MslReader
from memdiver.msl.types import (MslAuthError, MslCryptoError,
                                MslPointerGraphEdge, MslPointerGraphNode)
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

_CIPHERS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]
_PASS = b"correct horse battery"


# --------------------------------------------------------------- fixtures

def _keying(kind):
    """(writer-config kwargs, reader kwargs) for one key-material form."""
    if kind == "raw":
        key = os.urandom(32)
        return dict(raw_key=key), dict(key=key)
    if kind == "passphrase":
        if not crypto.kdf_is_available(KdfType.ARGON2ID):
            pytest.skip("argon2-cffi not installed")
        return dict(kdf_type=KdfType.ARGON2ID, passphrase=_PASS), dict(passphrase=_PASS)
    mech = {"x25519": KeyEncap.X25519, "mlkem768": KeyEncap.ML_KEM_768,
            "hybrid": KeyEncap.X25519_ML_KEM_768}[kind]
    if not crypto.kem_is_available(mech):
        pytest.skip(f"{mech.name} not available")
    pub, priv = crypto.kem_generate_keypair(mech)
    return dict(key_encap=mech, recipient_public=pub), dict(kem_private_key=priv)


def _write(path, algo, writer_kw, regions):
    w = MslWriter(path, pid=42, encryption=MslEncryptionConfig(enc_algo=algo, **writer_kw))
    for base, data in regions:
        w.add_memory_region(base, data)
    w.add_key_hint(region_uuid=w.dump_uuid, offset=8, key_length=32,
                   key_type=0x0003, protocol=0x0002)
    w.add_end_of_capture()
    w.add_pointer_graph(
        [MslPointerGraphNode(node_kind=NodeKind.ADDRESS, value=0xDEAD, label="x")],
        [MslPointerGraphEdge(src_idx=0, dst_idx=0, edge_kind=1, metadata="self")])
    w.write()


def _regions():
    rng = random.Random(1234)
    return [(0x10000 * (i + 1), rng.randbytes(4096 * n))
            for i, n in enumerate((1, 3, 17, 64, 2))]


def _snapshot(reader):
    """Everything a consumer can observe through the public reader API."""
    regions = reader.collect_regions()
    return {
        "blocks": [(h, p) for h, p in reader.iter_blocks()],
        "raw_blocks": [(h, p) for h, p in reader.iter_blocks(merge_cont=False)],
        "region_data": [get_region_page_data(reader, r) for r in regions],
        "region_headers": [(r.base_addr, r.region_size) for r in reader.iter_region_headers()],
        "hints": reader.collect_key_hints(),
        "eoc": reader.collect_end_of_capture(),
        "pointer_graphs": reader.collect_pointer_graphs(),
        "buffer_length": reader.buffer_length,
        "runs": reader.captured_run_index(),
    }


def _oneshot_plaintext(path, reader_kw, monkeypatch):
    monkeypatch.setenv(ONESHOT_ENV, "1")
    try:
        with MslReader(path, **reader_kw) as r:
            assert isinstance(r._buf, bytes)
            return bytes(r._buf), _snapshot(r)
    finally:
        monkeypatch.delenv(ONESHOT_ENV)


@pytest.fixture
def no_oneshot(monkeypatch):
    monkeypatch.delenv(ONESHOT_ENV, raising=False)


# ----------------------------------------------------------- equivalence

@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
@pytest.mark.parametrize("kind", ["raw", "passphrase", "x25519", "mlkem768", "hybrid"])
def test_seek_path_matches_oneshot(tmp_path, monkeypatch, no_oneshot, algo, kind):
    writer_kw, reader_kw = _keying(kind)
    regions = _regions()
    path = tmp_path / "enc.msl"
    _write(path, algo, writer_kw, regions)

    plaintext, expected = _oneshot_plaintext(path, reader_kw, monkeypatch)
    assert not oneshot_requested()
    with MslReader(path, **reader_kw) as r:
        assert r.tag_status is TagStatus.VALID
        assert isinstance(r._buf, DecryptedView)
        assert _snapshot(r) == expected
        assert [d for _, d in regions] == expected["region_data"]
        # every captured run, page by page, through the zero-copy API
        for run in r.captured_run_index().runs:
            for off in range(0, run.avail, 4096):
                got = bytes(r.read_view(run.buf_offset + off, 4096))
                assert got == plaintext[run.buf_offset + off:run.buf_offset + off + 4096]
        assert r._rewrap_material().cek  # re-wrap still available


@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
def test_random_ranges_match_oneshot(tmp_path, monkeypatch, no_oneshot, algo):
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, algo, writer_kw, _regions())
    plaintext, _ = _oneshot_plaintext(path, reader_kw, monkeypatch)
    rng = random.Random(7)
    with MslReader(path, **reader_kw) as r:
        view = r._buf
        assert len(view) == len(plaintext)
        probes = [(0, 1), (len(plaintext) - 1, 1), (len(plaintext) - 5, 100),
                  (CACHE_PAGE - 3, 7), (CACHE_PAGE - 1, CACHE_PAGE + 2),
                  (15, 2), (63, 2), (0, len(plaintext))]
        probes += [(rng.randrange(len(plaintext)), rng.choice((1, 13, 64, 4097, 300_000)))
                   for _ in range(300)]
        for off, n in probes:
            assert view.read(off, n) == plaintext[off:off + n], (off, n)
            assert view[off:off + n] == plaintext[off:off + n]
            assert r.read_bytes(off, n) == plaintext[off:off + n]
        assert view[5] == plaintext[5] and view[-1] == plaintext[-1]
        assert view[10:2] == b"" and view[::4][:50] == plaintext[::4][:50]


@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
def test_seekable_decryptor_matches_aead(algo):
    key = os.urandom(32)
    nonce = crypto.nonce_for_cipher(algo, crypto.random_nonce(algo))
    data = os.urandom(70_001)
    ct = crypto.aead_encrypt(algo, key, nonce, b"aad", data)
    body, tag = ct[:-16], ct[-16:]
    verify_tag_streaming(algo, key, nonce, b"aad", body, tag, chunk=1000)
    dec = SeekableDecryptor(algo, bytearray(key), nonce)
    rng = random.Random(3)
    for _ in range(200):
        off = rng.randrange(len(data)) // dec.align * dec.align
        n = rng.randrange(1, 9000)
        assert dec.decrypt(body[off:off + n], off) == data[off:off + n]
    with pytest.raises(ValueError):
        dec.decrypt(body[1:10], 1)


def test_gcm_counter_inc32_wrap():
    """Across the 32-bit wrap the counter must roll to 0 without carrying
    into the nonce (GCM inc32), unlike a plain 128-bit CTR increment."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, nonce = os.urandom(32), os.urandom(12)
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    counters = [0xFFFFFFFE, 0xFFFFFFFF, 0, 1]
    keystream = ecb.update(b"".join(nonce + struct.pack(">I", c) for c in counters))
    data = os.urandom(64)
    expected = bytes(a ^ b for a, b in zip(data, keystream))
    assert _aes_ctr32(key, nonce, 0xFFFFFFFE, data) == expected
    assert _aes_ctr32(key, nonce, 0xFFFFFFFE, data[:40]) == expected[:40]


def test_decryptor_refuses_past_cipher_limit():
    dec = SeekableDecryptor(EncAlgo.XCHACHA20_POLY1305, bytearray(os.urandom(32)),
                            os.urandom(24))
    with pytest.raises(MslCryptoError):
        dec.decrypt(b"\x00" * 64, 64 * ((1 << 32) - 1))


# --------------------------------------------------------------- failures

def _tamper(path, pos):
    raw = bytearray(path.read_bytes())
    raw[pos] ^= 0x01
    path.write_bytes(bytes(raw))


@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
@pytest.mark.parametrize("where", ["ciphertext", "tag", "aad_header", "truncated"])
def test_tamper_fails_like_oneshot(tmp_path, monkeypatch, no_oneshot, algo, where):
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, algo, writer_kw, _regions())
    size = path.stat().st_size
    if where == "ciphertext":
        _tamper(path, 128 + 4000)
    elif where == "tag":
        _tamper(path, size - 3)
    elif where == "aad_header":
        _tamper(path, 0x30)  # os_type: authenticated header byte
    else:
        path.write_bytes(path.read_bytes()[:-1])

    outcomes = []
    for env in ("", "1"):
        if env:
            monkeypatch.setenv(ONESHOT_ENV, env)
        with MslReader(path, **reader_kw) as r:
            outcomes.append((r.tag_status, list(r.iter_blocks()), r._buf, r._rewrap))
    monkeypatch.delenv(ONESHOT_ENV)
    assert outcomes[0] == outcomes[1] == (TagStatus.CORRUPTED, [], None, None)


def test_wrong_key_and_missing_key(tmp_path, no_oneshot):
    writer_kw, _ = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, EncAlgo.AES_256_GCM, writer_kw, _regions())
    with MslReader(path, key=os.urandom(32)) as r:
        assert r.tag_status is TagStatus.CORRUPTED and r._buf is None
    with MslReader(path) as r:
        assert r.tag_status is TagStatus.MISSING_KEY and r._buf is None


@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
def test_file_changed_after_open_is_rejected(tmp_path, no_oneshot, algo):
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    regions = _regions()
    _write(path, algo, writer_kw, regions)
    with MslReader(path, **reader_kw) as r:
        r.collect_regions()
        time.sleep(0.01)
        with open(path, "r+b") as fh:   # same bytes, in place: metadata moves
            fh.seek(1000)
            byte = fh.read(1)
            fh.seek(1000)
            fh.write(byte)
        with pytest.raises(MslSourceChangedError, match="changed after"):
            r.read_bytes(0, len(r._buf))  # direct (uncached) decrypt
    with MslReader(path, **reader_kw) as r:  # reopen = re-verify: fine
        assert r.tag_status is TagStatus.VALID


def test_append_after_open_is_rejected(tmp_path, no_oneshot):
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, EncAlgo.AES_256_GCM, writer_kw, _regions())
    with MslReader(path, **reader_kw) as r:
        with open(path, "ab") as fh:
            fh.write(b"x")
        with pytest.raises(MslSourceChangedError):
            r.read_bytes(len(r._buf) - 10, 10)


def test_close_wipes_key_and_refuses_reads(tmp_path, no_oneshot):
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, EncAlgo.XCHACHA20_POLY1305, writer_kw, _regions())
    r = MslReader(path, **reader_kw)
    r.open()
    view, material = r._buf, r._rewrap_material()
    cek_buffer, subkey = material._cek, view._dec._key
    r.close()
    assert not any(cek_buffer) and not any(subkey)
    assert len(view) == 0
    with pytest.raises(MslCryptoError):
        view.read(0, 16)
    assert r.read_bytes(0, 16) == b"" and r.buffer_length == 0


def test_region_align_guard_still_refuses_closed_encrypted_reader(tmp_path, no_oneshot):
    from memdiver.core.region_align import _ReaderHandle
    writer_kw, reader_kw = _keying("raw")
    path = tmp_path / "enc.msl"
    _write(path, EncAlgo.AES_256_GCM, writer_kw, _regions())
    r = MslReader(path, **reader_kw)
    r.open()
    handle = _ReaderHandle(r)
    assert bytes(handle.view(0, 4)) == b"MSLC"
    r.close()
    with pytest.raises(RuntimeError, match="encrypted reader was closed"):
        handle.view(0, 4)


# ------------------------------------------------------------- RAM bound

_BIG_REGIONS, _BIG_REGION_SIZE = 32, 4 << 20   # 128 MiB of page data


def _pattern_source(seed):
    block = hashlib.shake_256(seed).digest(1 << 20)

    def read_chunk(offset, length):
        out = bytearray()
        while len(out) < length:
            pos = (offset + len(out)) % len(block)
            out += block[pos:pos + length - len(out)]
        return bytes(out)
    return read_chunk


@pytest.mark.parametrize("algo", _CIPHERS, ids=lambda a: a.name)
def test_128mib_encrypted_open_and_read_peak(tmp_path, monkeypatch, no_oneshot, algo):
    key = os.urandom(32)
    path = tmp_path / "big.msl"
    w = MslWriter(path, pid=1, encryption=MslEncryptionConfig(enc_algo=algo, raw_key=key))
    expected = []
    for i in range(_BIG_REGIONS):
        src = _pattern_source(b"region-%d" % i)
        w.add_memory_region_source(0x10000000 + i * (_BIG_REGION_SIZE + 0x1000),
                                   _BIG_REGION_SIZE, src)
        expected.append(hashlib.sha256(src(0, _BIG_REGION_SIZE)).digest())
    w.add_end_of_capture()
    w.write_streaming()
    with MslReader(path, key=key):  # warm imports outside the measurement
        pass

    tracemalloc.start()
    try:
        with MslReader(path, key=key) as r:
            assert r.tag_status is TagStatus.VALID
            got = []
            for region in r.iter_region_headers():
                map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
                base = region.block_header.payload_offset + 0x20 + map_bytes
                total = region.num_pages * region.page_size
                h = hashlib.sha256()
                for off in range(0, total, 1 << 20):
                    h.update(r.read_view(base + off, min(1 << 20, total - off)))
                got.append(h.digest())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert got == expected
    print(f"[encrypted-seek] {algo.name}: 128 MiB open+read tracemalloc peak "
          f"{peak / 2**20:.1f} MiB")
    assert peak <= 8 << 20
