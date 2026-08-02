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


@pytest.mark.skipif(not HAS_BLAKE3, reason="blake3 not installed")
def test_verify_chain_valid(tmp_path):
    """Valid chain with correct hashes passes."""
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    # Block 1: prev_hash = zeros
    block1 = _build_block(0x0001, b'\xAA' * 32)
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


def test_verify_chain_stops_at_end_of_capture(tmp_path):
    """The walk stops immediately after an END_OF_CAPTURE block.

    Anything beyond End-of-Capture is a MemDiver appendix that lives outside
    the chain by design (see the module docstring), so a well-formed block
    placed after it must never be counted even though it chains correctly.
    """
    from memdiver.msl.enums import BlockType
    from memdiver.msl.hashing import hash_bytes
    from memdiver.msl.reader import MslReader
    from memdiver.msl.integrity import verify_chain

    file_hdr = _build_file_header()
    eoc_block = _build_block(BlockType.END_OF_CAPTURE, b'\xAA' * 32)
    # A well-formed follow-on block that chains correctly off the EoC block.
    # If the loop didn't break at EoC, this would be walked and counted too.
    trailing_hash = hash_bytes(eoc_block)
    trailing_block = _build_block(0x0001, b'\xBB' * 32, prev_hash=trailing_hash)

    msl_path = tmp_path / "eoc.msl"
    msl_path.write_bytes(file_hdr + eoc_block + trailing_block)

    with MslReader(msl_path) as reader:
        report = verify_chain(reader)
    assert report.valid
    assert report.block_count == 1
    assert report.broken_at is None


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
