"""Block chain integrity verification for MSL files."""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .enums import BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, HashAlgo
from .hashing import hash_bytes
from .types import MslParseError

logger = logging.getLogger("memdiver.msl.integrity")


@dataclass
class IntegrityReport:
    """Result of block chain verification."""
    valid: bool = True
    block_count: int = 0
    broken_at: Optional[int] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # True for files written by MemDiver before block 0 chained from the
    # header: block 0 carries a zero PrevHash, so the header is unprotected
    # but every block-to-block link is still checked.
    legacy_unchained_header: bool = False


_ZERO_HASH = b'\x00' * 32


def _sha512_256(data: bytes) -> bytes:
    return hashlib.new("sha512_256", data).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# HashAlgo (header 0x3D) selects the PrevHash function (spec Table 3 / §4.4).
_CHAIN_HASHERS = {
    HashAlgo.BLAKE3: hash_bytes,
    HashAlgo.SHA256: _sha256,
    HashAlgo.SHA512_256: _sha512_256,
}


def chain_hasher(hash_algo: int) -> Optional[Callable[[bytes], bytes]]:
    """Return the PrevHash function for *hash_algo*, or None if unknown."""
    try:
        return _CHAIN_HASHERS.get(HashAlgo(hash_algo))
    except ValueError:
        return None


def expected_block0_prev_hash(reader, hasher: Callable[[bytes], bytes]) -> bytes:
    """Block 0's PrevHash per spec §4.4: hash of all HeaderSize header bytes
    as stored on disk. Encrypted files mandate zeros (§10.6)."""
    if reader.file_header.encrypted:
        return _ZERO_HASH
    header_size = reader.file_header.header_size
    return hasher(bytes(reader._mmap[0:header_size]))


def verify_chain(reader) -> IntegrityReport:
    """Verify the block chain integrity of an open MslReader.

    Walks all in-chain blocks, computing blake3 hash of each block's raw
    bytes and comparing to the next block's prev_hash field. Stops after
    End-of-Capture: anything beyond EoC is a MemDiver appendix
    (POINTER_GRAPH 0x1003) that lives outside the chain by design and
    carries its own optional self-integrity hash.
    """
    report = IntegrityReport()
    buf = reader._buf
    if buf is None:
        report.valid = False
        report.errors.append("Reader not opened (or encrypted without a key)")
        return report

    # Encrypted files (spec §14.2 rule 16): skip PrevHash verification — all
    # PrevHash fields are zero by mandate (§10.6) and integrity is provided by
    # the AEAD tag, already verified at open() (reader.tag_status). We still
    # walk the decrypted blocks to count them.
    skip_prev_hash = bool(reader.file_header.encrypted)

    hasher = chain_hasher(reader.file_header.hash_algo)
    if hasher is None:
        report.valid = False
        report.errors.append(
            f"Unsupported HashAlgo 0x{reader.file_header.hash_algo:02X}")
        return report
    prev_hash = expected_block0_prev_hash(reader, hasher)
    offset = reader._buf_base
    file_size = len(buf)

    while offset + BLOCK_HEADER_SIZE <= file_size:
        if buf[offset:offset + 4] != BLOCK_MAGIC:
            break
        hdr = reader._parse_block_header(offset)
        if hdr.block_length < BLOCK_HEADER_SIZE:
            report.valid = False
            report.errors.append(f"Invalid block length at 0x{offset:X}")
            report.broken_at = offset
            break

        end = offset + hdr.block_length
        if end > file_size:
            report.valid = False
            report.errors.append(f"Truncated block at 0x{offset:X}")
            report.broken_at = offset
            break

        if (not skip_prev_hash and report.block_count == 0
                and hdr.prev_hash == _ZERO_HASH and prev_hash != _ZERO_HASH):
            # Pre-fix MemDiver files: tolerated, but the header is unverified.
            report.legacy_unchained_header = True
            report.warnings.append(
                "Block 0 PrevHash is zero (legacy MemDiver writer): the file "
                "header is not covered by the chain")
            prev_hash = _ZERO_HASH

        # Check prev_hash matches expected (plaintext files only)
        if not skip_prev_hash and hdr.prev_hash != prev_hash:
            report.valid = False
            report.errors.append(
                f"Hash mismatch at block 0x{offset:X}: "
                f"expected {prev_hash[:8].hex()}..., "
                f"got {hdr.prev_hash[:8].hex()}..."
            )
            if report.broken_at is None:
                report.broken_at = offset

        prev_hash = hasher(bytes(buf[offset:end]))
        report.block_count += 1
        offset = end
        if hdr.block_type == BlockType.END_OF_CAPTURE:
            break

    return report
