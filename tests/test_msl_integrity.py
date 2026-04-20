"""Tests for MSL block chain integrity verification."""

import struct
import pytest
from uuid import UUID

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

from msl.enums import BLOCK_MAGIC, FILE_MAGIC, BLOCK_HEADER_SIZE, FILE_HEADER_SIZE
from msl.types import MslParseError


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
    from msl.reader import MslReader
    from msl.integrity import verify_chain

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
    from msl.reader import MslReader
    from msl.integrity import verify_chain

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


def test_hashing_fallback_produces_32_bytes():
    """Hashing produces a 32-byte digest regardless of backend.

    Both the writer and integrity paths go through msl.hashing.hash_bytes,
    which selects blake3 when available and falls back to sha256 at
    import time. Either backend yields a 32-byte digest, so verification
    stays consistent across installs — replacing the previous "hard-fail
    on missing blake3" contract which was inconsistent with the writer.
    """
    from msl.hashing import hash_bytes
    digest = hash_bytes(b"integrity-fallback-test")
    assert len(digest) == 32
    assert digest == hash_bytes(b"integrity-fallback-test")
