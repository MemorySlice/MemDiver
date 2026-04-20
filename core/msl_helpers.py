"""Shared helpers for MSL region data extraction."""

import logging

logger = logging.getLogger("memdiver.core.msl_helpers")


def get_region_page_data(reader, region) -> bytes:
    """Extract raw captured page data bytes for a memory region.

    Args:
        reader: An opened MslReader instance.
        region: An MslMemoryRegion with block_header, page_size,
                num_pages, and page_states attributes.

    Returns:
        Raw bytes of all CAPTURED pages concatenated.
    """
    from msl.page_map import count_captured_pages

    hdr = region.block_header
    ps = region.page_size
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    off = hdr.payload_offset + 0x20 + map_bytes
    captured = count_captured_pages(region.page_states)
    return reader.read_bytes(off, captured * ps)
