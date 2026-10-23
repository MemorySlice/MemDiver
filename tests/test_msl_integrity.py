"""Tests for MSL block chain integrity verification."""

import struct
import pytest
from uuid import UUID

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

from memdiver.msl.enums import BLOCK_MAGIC, FILE_MAGIC, BLOCK_HEADER_SIZE, FILE_HEADER_SIZE
from memdiver.msl.types import MslParseError


def _build_file_header():
    """Build a minimal valid MSL file header."""
    hdr = bytearray(FILE_HEADER_SIZE)
    hdr[0:8] = FILE_MAGIC
    hdr[8] = 0x01  # little-endian
    hdr[9] = FILE_HEADER_SIZE  # header_size
    struct.pack_into("<H", hdr, 0x0A, 0x0101)  # version 1.1
    hdr[0x18:0x28] = UUID(int=1).bytes  # dump_uuid
    return bytes(hdr)


def _build_block(block_type, payload, prev_hash=b'\x00' * 32):
    """Build a block with given type, payload, and prev_hash."""
    block_length = BLOCK_HEADER_SIZE + len(payload)
    hdr = bytearray(BLOCK_HEADER_SIZE)
    hdr[0:4] = BLOCK_MAGIC
    struct.pack_into("<H", hdr, 4, block_type)
    struct.pack_into("<H", hdr, 6, 0)  # flags
    struct.pack_into("<I", hdr, 8, block_length)
    struct.pack_into("<H", hdr, 0x0C, 1)  # payload_version
    hdr[0x10:0x20] = UUID(int=2).bytes  # block_uuid
    hdr[0x20:0x30] = UUID(int=0).bytes  # parent_uuid
    hdr[0x30:0x50] = prev_hash  # prev_hash
    return bytes(hdr) + payload


def _eoc_payload(file_hash=b'\x00' * 32, acq_end_ns=0, block_count=0):
    """48-byte End-of-Capture payload: FileHash(32) AcqEnd(8) BlockCount(4) Reserved(4)."""
    return struct.pack("<32sQII", file_hash, acq_end_ns, block_count, 0)


def _set_header_block_count(file_hdr: bytes, count: int) -> bytes:
    hdr = bytearray(file_hdr)
    struct.pack_into("<I", hdr, 0x39, count)
    return bytes(hdr)


@pytest.mark.skipif(not HAS_BLAKE3, reason="blake3 not installed")
def test_verify_chain_valid(tmp_path):
    """Valid chain with correct hashes passes."""
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    # Block 0: prev_hash = BLAKE3(file header, all HeaderSize bytes) (§4.4)
    block1 = _build_block(0x0001, b'\xAA' * 32,
                          prev_hash=blake3.blake3(file_hdr).digest())
    # Compute hash of block1 for block2's prev_hash
    h = blake3.blake3(block1)
    hash1 = h.digest()
    block2 = _build_block(0x0001, b'\xBB' * 32, prev_hash=hash1)

    msl_path = tmp_path / "valid.msl"
    msl_path.write_bytes(file_hdr + block1 + block2)

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert report.valid
    assert report.block_count == 2
    assert report.broken_at is None


@pytest.mark.skipif(not HAS_BLAKE3, reason="blake3 not installed")
def test_verify_chain_corrupted(tmp_path):
    """Corrupted prev_hash is detected."""
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    block1 = _build_block(0x0001, b'\xAA' * 32)
    # Use wrong prev_hash for block2
    block2 = _build_block(0x0001, b'\xBB' * 32, prev_hash=b'\xFF' * 32)

    msl_path = tmp_path / "corrupt.msl"
    msl_path.write_bytes(file_hdr + block1 + block2)

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert not report.valid
    assert report.block_count == 2
    assert report.broken_at is not None


def test_verify_chain_reader_not_opened():
    """An un-opened reader (``_buf is None``) is reported invalid.

    This mirrors the encrypted-without-a-key case where ``open()`` leaves
    ``_buf`` as None. ``verify_chain`` returns early before any hashing, so
    the path needs no blake3 backend.
    """
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    reader = MslReader("does-not-need-to-exist.msl")
    assert reader._buf is None
    report = verify_chain(reader)
    assert not report.valid
    assert report.block_count == 0
    assert report.broken_at is None
    assert any("not opened" in e for e in report.errors)


def test_verify_chain_bad_block_magic(tmp_path):
    """A block whose BLOCK_MAGIC is corrupted stops the walk cleanly.

    The magic mismatch is a plain loop-terminating condition (no error is
    recorded); verification simply stops before counting the block.
    """
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    block = bytearray(_build_block(0x0001, b'\xAA' * 32))
    block[0:4] = b'XXXX'  # flip the 4 BLOCK_MAGIC bytes

    msl_path = tmp_path / "bad_magic.msl"
    msl_path.write_bytes(file_hdr + bytes(block))

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert report.valid
    assert report.block_count == 0
    assert report.broken_at is None


def test_verify_chain_invalid_block_length(tmp_path):
    """A block_length below BLOCK_HEADER_SIZE is flagged and breaks the chain."""
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    block = bytearray(_build_block(0x0001, b'\xAA' * 32))
    # Shrink block_length (u32 at header offset 8) below the header size.
    struct.pack_into("<I", block, 8, BLOCK_HEADER_SIZE - 1)

    msl_path = tmp_path / "short_length.msl"
    msl_path.write_bytes(file_hdr + bytes(block))

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert not report.valid
    assert report.block_count == 0
    assert report.broken_at == FILE_HEADER_SIZE
    assert any("Invalid block length" in e for e in report.errors)


def test_verify_chain_truncated_block(tmp_path):
    """A block whose declared length runs past EOF is flagged as truncated."""
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    block = _build_block(0x0001, b'\xAA' * 32)
    # Keep the full header intact but drop trailing payload bytes so the
    # declared block_length exceeds the on-disk file size.
    truncated = block[:-16]

    msl_path = tmp_path / "truncated.msl"
    msl_path.write_bytes(file_hdr + truncated)

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert not report.valid
    assert report.block_count == 0
    assert report.broken_at == FILE_HEADER_SIZE
    assert any("Truncated block" in e for e in report.errors)


def _counts_only_capture_blocks(tmp_path, name, after_eoc: bytes):
    """Header + a lone EoC + *after_eoc*; return the report."""
    from memdiver.msl.enums import BlockType
    from memdiver.msl.hashing import hash_bytes
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    eoc_block = _build_block(BlockType.END_OF_CAPTURE, _eoc_payload(),
                             prev_hash=hash_bytes(file_hdr))
    msl_path = tmp_path / name
    msl_path.write_bytes(file_hdr + eoc_block + after_eoc)
    with MslReader(msl_path) as reader:
        return verify_chain(reader), eoc_block, reader.buffer_length


def test_verify_chain_counts_only_capture_blocks(tmp_path):
    """block_count stops at End-of-Capture (spec 4.5 / rule 13).

    A well-formed block that chains correctly off the EoC but is not closed
    by an End-of-Extension block is an *unterminated* extension segment
    (spec 4.6): never counted as a capture block, reported as a warning and
    as trailing bytes, and the file stays valid.
    """
    from memdiver.msl.hashing import hash_bytes

    file_hdr = _build_file_header()
    from memdiver.msl.enums import BlockType
    eoc_block = _build_block(BlockType.END_OF_CAPTURE, _eoc_payload(),
                             prev_hash=hash_bytes(file_hdr))
    trailing_block = _build_block(0x1100, b'\xBB' * 32,
                                  prev_hash=hash_bytes(eoc_block))
    report, _, _ = _counts_only_capture_blocks(tmp_path, "eoc.msl", trailing_block)
    assert report.valid, report.errors
    assert report.block_count == 1
    assert report.broken_at is None
    assert report.capture_ok
    assert len(report.segments) == 1
    seg = report.segments[0]
    assert not seg.terminated and not seg.verified
    assert seg.chain_ok  # the block does chain from H(EoC)
    assert seg.block_count == 1
    assert report.trailing_bytes == len(trailing_block)
    assert any("not terminated" in w for w in report.warnings)
    assert any("trailing" in w for w in report.warnings)


def test_hashing_fallback_produces_32_bytes():
    """Hashing produces a 32-byte digest regardless of backend.

    Both the writer and integrity paths go through msl.hashing.hash_bytes,
    which selects blake3 when available and falls back to sha256 at
    import time. Either backend yields a 32-byte digest, so verification
    stays consistent across installs — replacing the previous "hard-fail
    on missing blake3" contract which was inconsistent with the writer.
    """
    from memdiver.msl.hashing import hash_bytes
    digest = hash_bytes(b"integrity-fallback-test")
    assert len(digest) == 32
    assert digest == hash_bytes(b"integrity-fallback-test")


# -- Block 0 chains from the file header (spec §4.4) --


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _verify(path):
    from memdiver.msl.integrity import verify_chain
    from memdiver.msl.reader import MslReader
    with MslReader(path) as reader:
        return verify_chain(reader)


def test_block0_zero_prev_hash_tolerated_as_legacy(tmp_path):
    """A zero Block 0 PrevHash (pre-fix MemDiver writer) violates §4.4 but is
    tolerated: the file stays valid, flagged, with a warning."""
    file_hdr = _build_file_header()
    block0 = _build_block(0x0001, b'\xAA' * 32)  # zero prev_hash
    report = _verify(_write(tmp_path, "zero.msl", file_hdr + block0))
    assert report.valid
    assert report.legacy_unchained_header
    assert report.warnings and "legacy" in report.warnings[0]


def test_legacy_zero_block0_still_checks_later_links(tmp_path):
    """The legacy tolerance covers only the header link, not block links."""
    file_hdr = _build_file_header()
    block0 = _build_block(0x0001, b'\xAA' * 32)  # zero prev_hash
    block1 = _build_block(0x0001, b'\xBB' * 32, prev_hash=b'\x11' * 32)
    report = _verify(_write(tmp_path, "zero2.msl", file_hdr + block0 + block1))
    assert not report.valid
    assert report.legacy_unchained_header
    assert report.broken_at == FILE_HEADER_SIZE + len(block0)


def test_chained_header_is_not_flagged_legacy(tmp_path):
    from memdiver.msl.hashing import hash_bytes
    file_hdr = _build_file_header()
    block0 = _build_block(0x0001, b'\xAA' * 32, prev_hash=hash_bytes(file_hdr))
    report = _verify(_write(tmp_path, "chained.msl", file_hdr + block0))
    assert report.valid and not report.legacy_unchained_header
    assert report.warnings == []


def test_block0_detects_header_tampering(tmp_path):
    """Changing any header byte after writing breaks the Block 0 link."""
    from memdiver.msl.hashing import hash_bytes
    file_hdr = _build_file_header()
    block0 = _build_block(0x0001, b'\xAA' * 32, prev_hash=hash_bytes(file_hdr))
    tampered = bytearray(file_hdr)
    struct.pack_into("<I", tampered, 0x34, 4242)  # PID
    assert _verify(_write(tmp_path, "ok.msl", file_hdr + block0)).valid
    report = _verify(_write(tmp_path, "bad.msl", bytes(tampered) + block0))
    assert not report.valid
    assert report.broken_at == FILE_HEADER_SIZE


def test_chain_honors_sha256_hash_algo(tmp_path):
    """HashAlgo=0x01 (SHA-256) selects SHA-256 for every PrevHash link."""
    import hashlib
    from memdiver.msl.enums import HashAlgo
    hdr = bytearray(_build_file_header())
    hdr[0x3D] = HashAlgo.SHA256
    hdr = bytes(hdr)
    block0 = _build_block(0x0001, b'\xAA' * 32, prev_hash=hashlib.sha256(hdr).digest())
    block1 = _build_block(0x0001, b'\xBB' * 32, prev_hash=hashlib.sha256(block0).digest())
    report = _verify(_write(tmp_path, "sha.msl", hdr + block0 + block1))
    assert report.valid, report.errors
    assert report.block_count == 2


def test_unknown_hash_algo_reported(tmp_path):
    hdr = bytearray(_build_file_header())
    hdr[0x3D] = 0x7F
    report = _verify(_write(tmp_path, "unk.msl", bytes(hdr) + _build_block(1, b'\xAA' * 32)))
    assert not report.valid
    assert any("HashAlgo" in e for e in report.errors)


def test_chain_hasher_lookup():
    from memdiver.msl.enums import HashAlgo
    from memdiver.msl.hashing import hash_bytes
    from memdiver.msl.integrity import chain_hasher
    assert chain_hasher(HashAlgo.BLAKE3) is hash_bytes
    assert len(chain_hasher(HashAlgo.SHA512_256)(b"x")) == 32
    assert chain_hasher(0x7F) is None


@pytest.mark.parametrize("streaming", [False, True])
def test_memdiver_writer_block0_chains_from_header(tmp_path, streaming):
    """MslWriter (in-memory and streaming) seeds Block 0 with hash(header)."""
    from memdiver.msl.hashing import hash_bytes
    from memdiver.msl.writer import MslWriter
    path = tmp_path / f"w{int(streaming)}.msl"
    w = MslWriter(path)
    w.add_import_provenance(source_format=1, tool_name="test", orig_file_size=0)
    w.add_memory_region(0x10000, b"\x11" * 4096)
    w.add_end_of_capture()
    w.write_streaming() if streaming else w.write()
    raw = path.read_bytes()
    hs = raw[9]
    assert raw[hs + 0x30:hs + 0x50] == hash_bytes(raw[:hs])
    report = _verify(path)
    assert report.valid, report.errors
    assert report.block_count == 3


# -- EoC FileHash and BlockCount (spec 4.5, consumer rule 13) --


def _capture_file(file_hdr: bytes, eoc_payload: bytes):
    """Header, one capture block, then an EoC carrying *eoc_payload*."""
    from memdiver.msl.enums import BlockType
    from memdiver.msl.hashing import hash_bytes
    block0 = _build_block(0x0001, b'\xAA' * 32, prev_hash=hash_bytes(file_hdr))
    eoc = _build_block(BlockType.END_OF_CAPTURE, eoc_payload,
                       prev_hash=hash_bytes(block0))
    return file_hdr + block0 + eoc, block0


def _blake3(data: bytes) -> bytes:
    from memdiver.msl.hashing import hash_bytes
    return hash_bytes(data)


def test_eoc_zero_file_hash_is_warning_only(tmp_path):
    blob, _ = _capture_file(_build_file_header(), _eoc_payload())
    report = _verify(_write(tmp_path, "zero_fh.msl", blob))
    assert report.valid, report.errors
    assert report.file_hash_ok is None
    assert any("FileHash is zero" in w for w in report.warnings)
    assert report.block_count == 2


def test_eoc_correct_file_hash_verifies(tmp_path):
    file_hdr = _build_file_header()
    _, block0 = _capture_file(file_hdr, _eoc_payload())
    file_hash = _blake3(file_hdr + block0)  # every byte before the EoC block
    blob, _ = _capture_file(file_hdr, _eoc_payload(file_hash=file_hash))
    report = _verify(_write(tmp_path, "good_fh.msl", blob))
    assert report.valid, report.errors
    assert report.file_hash_ok is True
    assert report.warnings == []


def test_eoc_wrong_file_hash_is_error(tmp_path):
    blob, _ = _capture_file(_build_file_header(),
                            _eoc_payload(file_hash=b'\x5A' * 32))
    report = _verify(_write(tmp_path, "bad_fh.msl", blob))
    assert not report.valid
    assert report.file_hash_ok is False
    assert not report.capture_ok
    assert any("FileHash mismatch" in e for e in report.errors)
    assert report.broken_at is None  # the PrevHash chain itself is intact


def test_header_block_count_mismatch_is_error(tmp_path):
    file_hdr = _set_header_block_count(_build_file_header(), 5)
    blob, _ = _capture_file(file_hdr, _eoc_payload())
    report = _verify(_write(tmp_path, "hdr_count.msl", blob))
    assert not report.valid
    assert report.block_count == 2
    assert report.header_block_count == 5
    assert report.block_count_ok is False
    assert any("header BlockCount 5 != 2" in e for e in report.errors)


def test_eoc_block_count_mismatch_is_error(tmp_path):
    blob, _ = _capture_file(_build_file_header(), _eoc_payload(block_count=7))
    report = _verify(_write(tmp_path, "eoc_count.msl", blob))
    assert not report.valid
    assert report.eoc_block_count == 7
    assert report.block_count_ok is False
    assert any("EoC BlockCount 7 != 2" in e for e in report.errors)


def test_matching_block_counts_are_ok(tmp_path):
    file_hdr = _set_header_block_count(_build_file_header(), 2)
    blob, _ = _capture_file(file_hdr, _eoc_payload(block_count=2))
    report = _verify(_write(tmp_path, "counts_ok.msl", blob))
    assert report.valid, report.errors
    assert report.header_block_count == 2
    assert report.eoc_block_count == 2
    assert report.block_count_ok is True


# -- Extension segments written by MslWriter (spec 4.6) --


def _write_pointer_graph_file(path, encryption=None):
    from memdiver.msl.types import MslPointerGraphEdge, MslPointerGraphNode
    from memdiver.msl.writer import MslWriter
    w = MslWriter(path, encryption=encryption)
    w.add_memory_region(0x1000, b"\x11" * 4096)
    w.add_pointer_graph([MslPointerGraphNode(1, 0x1040, "n")],
                        [MslPointerGraphEdge(0, 0, 1, "self")])
    w.add_end_of_capture()
    w.write()
    return path


def test_writer_pointer_graph_segment_verified(tmp_path):
    report = _verify(_write_pointer_graph_file(tmp_path / "pg.msl"))
    assert report.valid, report.errors
    assert report.block_count == 2
    assert len(report.segments) == 1
    seg = report.segments[0]
    assert seg.verified, seg.errors
    assert seg.terminated and seg.chain_ok and seg.segment_hash_ok and seg.block_count_ok
    assert seg.block_count == 2
    assert report.verified_segments == [seg]
    assert report.trailing_bytes == 0
    assert report.warnings == []


def test_writer_pointer_graph_tampered_payload_fails_segment_hash(tmp_path):
    from memdiver.msl.reader import MslReader
    path = _write_pointer_graph_file(tmp_path / "pg_tamper.msl")
    with MslReader(path) as reader:
        pg_hdr = reader.scan_extension_segments()[0].headers[0]
        offset = pg_hdr.payload_offset + 4  # inside the graph payload
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    report = _verify(path)
    assert not report.valid
    assert report.capture_ok
    seg = report.segments[0]
    assert seg.terminated
    # The terminator's PrevHash was computed over the untampered block, so
    # both the chain link and the SegmentHash break.
    assert not seg.chain_ok
    assert seg.segment_hash_ok is False
    assert not seg.verified
    assert any("segment 0" in e and "SegmentHash" in e for e in report.errors)
    assert report.trailing_bytes == len(data) - seg.start


def test_writer_pointer_graph_truncated_terminator_is_trailing(tmp_path):
    from memdiver.msl.reader import MslReader
    path = _write_pointer_graph_file(tmp_path / "pg_trunc.msl")
    with MslReader(path) as reader:
        seg = reader.scan_extension_segments()[0]
        term_hdr = seg.headers[-1]
        ext_start = reader._extension_start()
    cut = term_hdr.file_offset + term_hdr.block_length // 2  # inside the 0x0FFE block
    data = path.read_bytes()[:cut]
    path.write_bytes(data)
    report = _verify(path)
    assert report.valid, report.errors
    assert report.capture_ok
    assert report.segments[0].terminated is False
    assert not report.segments[0].verified
    assert report.trailing_bytes == len(data) - ext_start
    assert any("not terminated" in w for w in report.warnings)
    assert any(f"{report.trailing_bytes} trailing" in w for w in report.warnings)


def test_encrypted_pointer_graph_segment_verified(tmp_path):
    from memdiver.msl.enums import TagStatus
    from memdiver.msl.integrity import verify_chain
    from memdiver.msl.reader import MslReader
    from memdiver.msl.writer import MslEncryptionConfig
    key = bytes(range(32))
    path = _write_pointer_graph_file(tmp_path / "pg_enc.msl",
                                     encryption=MslEncryptionConfig(raw_key=key))
    with MslReader(path, key=key) as reader:
        assert reader.tag_status == TagStatus.VALID
        report = verify_chain(reader)
        assert len(reader.collect_pointer_graphs()) == 1
    assert report.valid, report.errors
    assert report.header_block_count == 0  # never leaked in the clear header
    assert report.eoc_block_count == 2 == report.block_count
    assert report.file_hash_ok is True
    assert len(report.segments) == 1
    assert report.segments[0].verified, report.segments[0].errors
    assert report.trailing_bytes == 0
