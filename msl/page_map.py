"""PageStateMap decoder using run-length encoded intervals.

Decodes the 2-bit-per-page bitmap into compact PageInterval objects
instead of per-page lists. A 1GB region with all pages captured
produces 1 interval instead of 262,144 Python objects.
"""

import logging
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from .enums import PageState

logger = logging.getLogger("memdiver.msl.page_map")


@dataclass(frozen=True)
class PageInterval:
    """Run-length encoded page state interval."""
    start_page: int
    count: int
    state: PageState

    @property
    def end_page(self) -> int:
        return self.start_page + self.count


def decode_page_intervals(data: bytes, num_pages: int) -> List[PageInterval]:
    """Decode PageStateMap into RLE intervals. O(pages) time, O(runs) space.

    Fast path: if all bytes are zero (all CAPTURED), returns a single interval.
    """
    if num_pages == 0:
        return []
    needed_bytes = (num_pages + 3) // 4
    if len(data) >= needed_bytes and all(data[i] == 0 for i in range(needed_bytes)):
        return [PageInterval(0, num_pages, PageState.CAPTURED)]
    intervals: List[PageInterval] = []
    current_state = None
    run_start = 0
    for i in range(num_pages):
        byte_idx = i // 4
        shift = 6 - 2 * (i % 4)
        if byte_idx < len(data):
            bits = (data[byte_idx] >> shift) & 0x03
            state = PageState(bits)
        else:
            state = PageState.FAILED
        if state != current_state:
            if current_state is not None:
                intervals.append(PageInterval(run_start, i - run_start, current_state))
            current_state = state
            run_start = i
    if current_state is not None:
        intervals.append(PageInterval(run_start, num_pages - run_start, current_state))
    return intervals


def decode_page_state_map(data: bytes, num_pages: int) -> List[PageState]:
    """Decode into per-page list (backward compatibility).

    Prefer decode_page_intervals() for new code.
    """
    return [
        interval.state
        for interval in decode_page_intervals(data, num_pages)
        for _ in range(interval.count)
    ]


def iter_captured_ranges(
    page_states_or_intervals,
    page_data: bytes,
    base_addr: int,
    page_size: int,
) -> Iterator[Tuple[int, int, memoryview]]:
    """Yield (virtual_addr, length, data) for each contiguous captured run.

    Accepts either List[PageInterval] or List[PageState] for backward compat.
    """
    if not page_states_or_intervals:
        return
    if isinstance(page_states_or_intervals[0], PageInterval):
        yield from _iter_from_intervals(
            page_states_or_intervals, page_data, base_addr, page_size,
        )
    else:
        intervals = _states_to_intervals(page_states_or_intervals)
        yield from _iter_from_intervals(
            intervals, page_data, base_addr, page_size,
        )


def _iter_from_intervals(
    intervals: List[PageInterval],
    page_data: bytes,
    base_addr: int,
    page_size: int,
) -> Iterator[Tuple[int, int, memoryview]]:
    """Core iteration over intervals — clean and simple."""
    view = memoryview(page_data)
    data_offset = 0
    for iv in intervals:
        if iv.state == PageState.CAPTURED:
            vaddr = base_addr + iv.start_page * page_size
            length = iv.count * page_size
            yield (vaddr, length, view[data_offset:data_offset + length])
            data_offset += length


def _states_to_intervals(states: List[PageState]) -> List[PageInterval]:
    """Convert per-page states to intervals for backward compat callers."""
    if not states:
        return []
    intervals = []
    current, start = states[0], 0
    for i in range(1, len(states)):
        if states[i] != current:
            intervals.append(PageInterval(start, i - start, current))
            current, start = states[i], i
    intervals.append(PageInterval(start, len(states) - start, current))
    return intervals


def count_captured_pages(page_states_or_intervals) -> int:
    """Count captured pages from either representation."""
    if not page_states_or_intervals:
        return 0
    if isinstance(page_states_or_intervals[0], PageInterval):
        return sum(
            iv.count for iv in page_states_or_intervals
            if iv.state == PageState.CAPTURED
        )
    return sum(1 for s in page_states_or_intervals if s == PageState.CAPTURED)
