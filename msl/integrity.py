"""Block chain integrity verification for MSL files."""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from .enums import BLOCK_HEADER_SIZE, BLOCK_MAGIC
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

    Walks all blocks, computing blake3 hash of each block's raw bytes
    and comparing to the next block's prev_hash field.
    """
    report = IntegrityReport()
    buf = reader._mmap
    if buf is None:
        report.valid = False
        report.errors.append("Reader not opened")
        return report

    prev_hash = b'\x00' * 32  # first block has zero prev_hash
    offset = reader.file_header.header_size
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

        # Check prev_hash matches expected
        if hdr.prev_hash != prev_hash:
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

    return report
