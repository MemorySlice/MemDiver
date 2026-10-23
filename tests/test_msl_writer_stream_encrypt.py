"""Streaming encrypted write == in-memory encrypted write, at O(chunk) RAM."""

import tracemalloc

import pytest

from memdiver.msl import crypto
from memdiver.msl.enums import EncAlgo, KdfType, KeyEncap, TagStatus
from memdiver.msl.integrity import verify_chain
from memdiver.msl.reader import MslReader
from memdiver.msl.types import MslPointerGraphEdge, MslPointerGraphNode
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

PAGE = 4096
KEY = bytes(range(32))
ALGOS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]


def _source(data: bytes):
    view = memoryview(data)
    return lambda off, n: view[off:off + n]


def _populate(w: MslWriter, data: bytes) -> None:
    w.add_process_identity(ppid=1, exe_path="/bin/x", cmd_line="x")
    region = w.add_memory_region_source(0x10000, len(data), _source(data))
    w.add_key_hint(region, 0x40, 32, 0x0003, 0x0002, note="k")
    w.add_memory_region(0x900000, b"\x5a" * PAGE)
    w.add_pointer_graph([MslPointerGraphNode(1, 0x10040, "a")],
                        [MslPointerGraphEdge(0, 0, 1, "self")])
    w.add_end_of_capture(acq_end_ns=123)


def _write_both(tmp_path, cfg: MslEncryptionConfig, data: bytes):
    """Same writer state emitted by the streaming and the in-memory path."""
    w = MslWriter(tmp_path / "s.msl", encryption=cfg, timestamp_ns=1)
    _populate(w, data)
    w.write_streaming()
    streamed = (tmp_path / "s.msl").read_bytes()
    w._has_streamed_regions = False  # force the one-shot path on the same state
    w._blocks = [(t, bytes(b"".join(p.iter_pieces())) if hasattr(p, "iter_pieces")
                  else p, u, par, f) for (t, p, u, par, f) in w._blocks]
    w.write()
    return streamed, (tmp_path / "s.msl").read_bytes()


@pytest.mark.parametrize("algo", ALGOS)
def test_streaming_encrypted_equals_in_memory(tmp_path, algo):
    cfg = MslEncryptionConfig(enc_algo=algo, raw_key=KEY,
                              nonce=crypto.random_nonce(algo))  # test hook
    data = bytes(range(256)) * (3 * PAGE // 256)
    streamed, in_memory = _write_both(tmp_path, cfg, data)
    assert streamed == in_memory
    with MslReader(tmp_path / "s.msl", key=KEY) as r:
        assert r.tag_status is TagStatus.VALID
        report = verify_chain(r)
        assert report.valid, report.errors
        assert {g.base_addr for g in r.collect_regions()} == {0x10000, 0x900000}
        assert r.collect_pointer_graphs()
        # The pointer graph sits in a verified extension segment inside the
        # AEAD stream; header / EoC counts cover capture blocks only.
        assert len(report.segments) == 1 and report.segments[0].verified
        capture_blocks = len(list(r._iter_raw_block_headers()))
        # 2 regions + key hint + EoC (process identity is only emitted for
        # imported=False writers); the segment blocks are not counted.
        assert report.block_count == capture_blocks == 4
        assert r.file_header.block_count == 0
        assert r.collect_end_of_capture()[0].block_count == capture_blocks
        assert report.eoc_block_count == capture_blocks
        assert report.file_hash_ok is True
        assert report.trailing_bytes == 0


def test_streaming_encrypted_passphrase_roundtrip(tmp_path):
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=b"pw")
    w = MslWriter(tmp_path / "p.msl", encryption=cfg)
    _populate(w, bytes(2 * PAGE))
    w.write()  # streamed regions -> write_streaming()
    with MslReader(tmp_path / "p.msl", passphrase=b"pw") as r:
        assert r.tag_status is TagStatus.VALID
        report = verify_chain(r)
        assert report.valid and report.segments[0].verified
        assert len(r.collect_pointer_graphs()) == 1


@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519),
                    reason="X25519 requires cryptography")
def test_streaming_encrypted_x25519_roundtrip(tmp_path):
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519)
    cfg = MslEncryptionConfig(key_encap=KeyEncap.X25519, recipient_public=pub)
    w = MslWriter(tmp_path / "k.msl", encryption=cfg)
    _populate(w, bytes(PAGE))
    w.write_streaming()
    with MslReader(tmp_path / "k.msl", kem_private_key=priv) as r:
        assert r.tag_status is TagStatus.VALID
        report = verify_chain(r)
        assert report.valid and report.segments[0].verified
        assert len(r.collect_pointer_graphs()) == 1


@pytest.mark.parametrize("algo", ALGOS)
def test_streaming_encrypted_peak_memory_is_bounded(tmp_path, algo):
    size = 64 << 20
    data = bytes(size)
    w = MslWriter(tmp_path / "big.msl",
                  encryption=MslEncryptionConfig(enc_algo=algo, raw_key=KEY))
    w.add_memory_region_source(0, size, _source(data))
    w.add_end_of_capture()
    tracemalloc.start()
    try:
        w.write_streaming()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 << 20  # ~1 MiB seal slices, independent of the 64 MiB region
    assert (tmp_path / "big.msl").stat().st_size > size
