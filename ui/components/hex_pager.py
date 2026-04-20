"""Pagination utilities for the hex viewer."""

import logging
import math

logger = logging.getLogger("memdiver.ui.components.hex_pager")


def compute_page(
    dump_size: int,
    page_num: int,
    rows_per_page: int = 64,
    bytes_per_row: int = 16,
) -> tuple:
    """Return (start_offset, end_offset) for the requested page.

    The end_offset is clamped to dump_size so the last page may be
    shorter than a full page.
    """
    page_size = rows_per_page * bytes_per_row
    start = page_num * page_size
    start = min(start, dump_size)
    end = start + page_size
    end = min(end, dump_size)
    logger.debug(
        "page %d: offsets %d-%d (dump_size=%d)", page_num, start, end, dump_size
    )
    return (start, end)


def total_pages(
    dump_size: int,
    rows_per_page: int = 64,
    bytes_per_row: int = 16,
) -> int:
    """Return total number of pages for a dump of given size."""
    if dump_size <= 0:
        return 0
    page_size = rows_per_page * bytes_per_row
    return math.ceil(dump_size / page_size)


def offset_to_page(
    offset: int,
    rows_per_page: int = 64,
    bytes_per_row: int = 16,
) -> int:
    """Given an offset, return which page it falls on."""
    page_size = rows_per_page * bytes_per_row
    if page_size == 0:
        return 0
    return offset // page_size
