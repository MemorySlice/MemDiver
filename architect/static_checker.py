"""StaticChecker - verify if a byte region is static across multiple dumps."""

import logging
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger("memdiver.architect.static_checker")


class StaticChecker:
    """Check whether a specific byte region is static across N dump files.

    A region is 'static' if the bytes at those positions are identical
    across all provided dumps. This is the first step in pattern creation:
    only static bytes can be used as exact match anchors.
    """

    @staticmethod
    def check(
        dump_paths: List[Path],
        offset: int,
        length: int,
    ) -> Tuple[List[bool], bytes]:
        """Check each byte position for staticness across dumps.

        Args:
            dump_paths: Paths to N dump files.
            offset: Start offset of the region.
            length: Length of the region in bytes.

        Returns:
            Tuple of (static_mask, reference_bytes) where:
            - static_mask: List of bools, True if byte is static across all dumps.
            - reference_bytes: Bytes from the first dump at this region.
        """
        if not dump_paths:
            return [], b""

        # Read the region from each dump
        regions = []
        for path in dump_paths:
            data = path.read_bytes()
            end = min(offset + length, len(data))
            if offset >= len(data):
                logger.warning("Offset %d beyond dump size %d: %s", offset, len(data), path.name)
                continue
            regions.append(data[offset:end])

        if not regions:
            return [], b""

        reference = regions[0]
        actual_len = len(reference)
        static_mask = [True] * actual_len

        for region in regions[1:]:
            for i in range(min(actual_len, len(region))):
                if region[i] != reference[i]:
                    static_mask[i] = False

        static_count = sum(static_mask)
        logger.info(
            "Static check: %d/%d bytes static across %d dumps (offset 0x%x)",
            static_count, actual_len, len(regions), offset,
        )
        return static_mask, reference

    @staticmethod
    def static_ratio(static_mask: List[bool]) -> float:
        """Compute the ratio of static bytes."""
        if not static_mask:
            return 0.0
        return sum(static_mask) / len(static_mask)
