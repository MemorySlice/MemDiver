"""Per-dump page-state runs for the aligned window (MSL spec §7).

The side-by-side view shows every dump in the anchor's WINDOW INDEX space and
must never do VA arithmetic for a peer. So the tint each pane needs — which of
ITS bytes sit in FAILED / UNMAPPED / NOT_RESIDENT pages — is computed here, in
the same space as ``bytes_valid``: ``[[offset, length, state], ...]`` relative
to the window start, ascending, adjacent same-state runs merged.

Semantics mirror the single-dump ``"va"`` view (``getPageStateAt`` in
``frontend/src/stores/hex-store.ts``): explicit non-CAPTURED intervals carry
their own state, and a VA inside the dump's VA span that no region covers is
UNMAPPED. CAPTURED is never reported, and a byte with no correspondence in the
dump (outside every segment it is read in) is never reported either — that is
already an absence, not a page state.

Only an ``.msl`` read in its ``"va"`` view has page states to report: the
``"vas"`` stream contains CAPTURED pages only, and ``"raw"`` is the container.
"""

from __future__ import annotations

import bisect
import threading
import weakref
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: ``(va_start, va_end, state_name)`` — one non-CAPTURED VA run of a dump.
StateRun = Tuple[int, int, str]

#: Per-reader cache of the dump's non-CAPTURED VA table. Keyed on the pooled
#: ``MslReader`` (sources are fresh per request, readers are not) and
#: validated against the identity of its cached region list, so a reopened
#: reader — whose ``close()`` drops that list — rebuilds instead of serving a
#: stale table. A window request per scroll step therefore costs a bisect, not
#: a page-map walk.
_TABLE_CACHE: "weakref.WeakKeyDictionary[Any, Tuple[Any, Tuple[StateRun, ...]]]" = (
    weakref.WeakKeyDictionary()
)
_TABLE_LOCK = threading.Lock()


def _state_name(state: Any) -> Optional[str]:
    """Wire name of a non-CAPTURED PageState, or ``None`` for CAPTURED."""
    from memdiver.msl.enums import PageState

    if state == PageState.CAPTURED:
        return None
    if state == PageState.UNMAPPED:
        return "UNMAPPED"
    if state == PageState.NOT_RESIDENT:
        return "NOT_RESIDENT"
    return "FAILED"


def _region_intervals(region: Any) -> List[Any]:
    """The region's RLE page intervals, whichever form it was decoded in."""
    from memdiver.msl.page_map import _states_to_intervals

    return list(region.page_intervals or _states_to_intervals(region.page_states))


def _region_runs(region: Any) -> List[Tuple[int, int, Optional[str]]]:
    """``(va_start, va_end, state_or_None)`` for every interval of ``region``."""
    page = region.page_size
    out = []
    for iv in _region_intervals(region):
        start = region.base_addr + iv.start_page * page
        out.append((start, start + iv.count * page, _state_name(iv.state)))
    return out


def build_state_table(regions: Sequence[Any]) -> Tuple[StateRun, ...]:
    """Non-CAPTURED VA runs of a dump, inter-region gaps included as UNMAPPED.

    Gaps are only those INSIDE the VA span (between the first region start
    and the furthest region end), which is all the single view can show.
    """
    runs = sorted(
        (run for region in regions for run in _region_runs(region)),
        key=lambda run: run[0],
    )
    table: List[StateRun] = []
    covered_end: Optional[int] = None
    for start, end, state in runs:
        if covered_end is not None and start > covered_end:
            table.append((covered_end, start, "UNMAPPED"))
        if state is not None:
            table.append((start, end, state))
        covered_end = end if covered_end is None else max(covered_end, end)
    return tuple(table)


def cached_state_table(reader: Any) -> Tuple[StateRun, ...]:
    """:func:`build_state_table` for ``reader``, built once per open reader."""
    regions = reader.collect_regions()
    with _TABLE_LOCK:
        hit = _TABLE_CACHE.get(reader)
        if hit is not None and hit[0] is regions:
            return hit[1]
    table = build_state_table(regions)
    with _TABLE_LOCK:
        _TABLE_CACHE[reader] = (regions, table)
    return table


def _clip(
    table: Sequence[StateRun], starts: Sequence[int],
    va_start: int, length: int, window_offset: int,
) -> List[List[Any]]:
    """Runs of ``table`` overlapping ``[va_start, +length)``, in window space.

    ``starts`` is ``table``'s run starts, precomputed once with it.
    """
    va_end = va_start + length
    first = max(0, bisect.bisect_right(starts, va_start) - 1)
    out: List[List[Any]] = []
    for start, end, state in table[first:]:
        if start >= va_end:
            break
        lo, hi = max(start, va_start), min(end, va_end)
        if hi > lo:
            out.append([window_offset + lo - va_start, hi - lo, state])
    return out


def _subtract_valid(
    runs: List[List[Any]], valid: Sequence[Sequence[int]],
) -> List[List[Any]]:
    """Drop any byte ``bytes_valid`` claims: a captured byte has no tint.

    Defence in depth for overlapping regions, where one region's CAPTURED
    page can sit under another's FAILED interval.
    """
    out = runs
    for v_start, v_len in valid:
        v_end = v_start + v_len
        next_out: List[List[Any]] = []
        for start, length, state in out:
            end = start + length
            if end <= v_start or start >= v_end:
                next_out.append([start, length, state])
                continue
            if start < v_start:
                next_out.append([start, v_start - start, state])
            if end > v_end:
                next_out.append([v_end, end - v_end, state])
        out = next_out
    return out


def merge_runs(runs: List[List[Any]]) -> List[List[Any]]:
    """Sort runs and merge adjacent ones carrying the same state."""
    merged: List[List[Any]] = []
    for start, length, state in sorted(runs, key=lambda run: run[0]):
        last = merged[-1] if merged else None
        if last is not None and last[2] == state and last[0] + last[1] == start:
            last[1] += length
        else:
            merged.append([start, length, state])
    return merged


def has_page_states(source: Any, view: str) -> bool:
    """True when ``source`` read in ``view`` can carry non-CAPTURED bytes."""
    return view == "va" and getattr(source, "format_name", "") == "msl"


def window_page_state_runs(
    source: Any,
    span_start: Optional[int],
    segment_reads: Dict[int, Tuple[int, int]],
    valid: Sequence[Sequence[int]],
) -> List[List[Any]]:
    """One dump's page-state runs in window index space.

    :param source: The open ``.msl`` source, read in its ``"va"`` view.
    :param span_start: Base VA of that view (``va`` offset 0).
    :param segment_reads: ``{window_offset: (va_offset, length)}`` for every
        segment this dump has a correspondence in.
    :param valid: The dump's ``bytes_valid`` runs, ``[[start, len]]``.
    """
    if span_start is None or not segment_reads:
        return []
    table = cached_state_table(source.get_reader())
    starts = [run[0] for run in table]
    runs: List[List[Any]] = []
    for window_offset, (read_at, length) in segment_reads.items():
        runs.extend(_clip(
            table, starts, span_start + read_at, length, window_offset))
    return merge_runs(_subtract_valid(runs, valid))


# -- image views (.mdview) ----------------------------------------------------

#: Page size the workspace's page-state vocabulary is expressed in. The run
#: table of an image view is byte-granular; page counts are informational.
IMAGE_PAGE_SIZE = 4096

_IMAGE_STATE_NAMES = {"CAPTURED": "CAPTURED", "FAILED": "FAILED",
                      "NOT_RESIDENT": "NOT_RESIDENT"}


def image_page_states_payload(layer_runs: Sequence[Any]) -> Dict[str, Any]:
    """The ``/api/inspect/page-states`` payload of an image view.

    Same shape :func:`~memdiver.app.tools_inspect.page_states_result` emits for
    an ``.msl``, built from the view's run table: one region per run, FAILED /
    NOT_RESIDENT runs carrying their own state. Addresses outside every run are
    left out — the viewer reads a VA inside the span that no region covers as
    UNMAPPED, exactly as it does for an ``.msl``. ``vas_offset`` is stamped on
    CAPTURED runs in run order, which is the VAS stream order.
    """
    regions: List[Dict[str, Any]] = []
    vas_offset = total_pages = captured_pages = 0
    for run in sorted(layer_runs, key=lambda r: r.start):
        state = _IMAGE_STATE_NAMES.get(run.state.name, "FAILED")
        pages = -(-run.length // IMAGE_PAGE_SIZE)
        entry: Dict[str, Any] = {"va": run.start, "length": run.length,
                                 "state": state, "page_count": pages}
        if state == "CAPTURED":
            entry["vas_offset"] = vas_offset
            vas_offset += run.length
            captured_pages += pages
        total_pages += pages
        regions.append({"base_addr": run.start, "region_size": run.length,
                        "page_size": IMAGE_PAGE_SIZE, "intervals": [entry]})
    return {
        "regions": regions,
        "total_pages": total_pages,
        "captured_pages": captured_pages,
        "coverage": captured_pages / total_pages if total_pages else 0.0,
        "vas_size": vas_offset,
    }
