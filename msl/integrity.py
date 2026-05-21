"""Block chain integrity verification for MSL files."""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from .enums import BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType
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

    prev_hash = b'\x00' * 32  # first block has zero prev_hash
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

        prev_hash = hash_bytes(bytes(buf[offset:end]))
        report.block_count += 1
        offset = end
        if hdr.block_type == BlockType.END_OF_CAPTURE:
            break

    return report
