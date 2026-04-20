"""Alignment-based candidate filtering for key detection.

AES-256 keys occupy 32 contiguous bytes at 16-byte aligned addresses.
Filtering candidates by alignment and density eliminates scattered
false positives from heap metadata, counters, and partial matches.
"""

import logging
from bisect import bisect_left
from typing import Set

logger = logging.getLogger("memdiver.core.alignment_filter")


def alignment_filter(
    candidates: Set[int],
    block_size: int = 32,
    alignment: int = 16,
    density_threshold: float = 0.75,
) -> Set[int]:
    """Filter candidates to aligned, dense blocks.

    Groups candidate byte offsets into block_size-byte blocks aligned
    to alignment boundaries. Keeps only blocks where candidate density
    meets the threshold.

    Args:
        candidates: Set of byte offsets flagged as key candidates.
        block_size: Expected key size in bytes (default: 32 for AES-256).
        alignment: Memory alignment in bytes (default: 16 for 64-bit malloc).
        density_threshold: Minimum fraction of bytes in block that must
            be candidates to keep the block (default: 0.75 = 24/32).

    Returns:
        Filtered set of candidate byte offsets from passing blocks.
    """
    if not candidates or block_size <= 0 or alignment <= 0:
        return set()

    # Build sorted list for efficient windowed scanning
    sorted_offsets = sorted(candidates)
    min_offset = sorted_offsets[0]
    max_offset = sorted_offsets[-1]

    # Collect all alignment-boundary block starts that could contain candidates
    first_start = (min_offset // alignment) * alignment
    last_start = (max_offset // alignment) * alignment

    # Evaluate each aligned window of block_size bytes
    result: Set[int] = set()
    min_count = int(block_size * density_threshold)
    block_start = first_start
    while block_start <= last_start:
        block_end = block_start + block_size
        lo = bisect_left(sorted_offsets, block_start)
        hi = bisect_left(sorted_offsets, block_end)
        count = hi - lo
        if count >= min_count:
            result.update(sorted_offsets[lo:hi])
            logger.debug(
                "Kept block at 0x%04x: %d/%d bytes (%.0f%%)",
                block_start, count, block_size,
                100 * count / block_size,
            )
        block_start += alignment

    return result
