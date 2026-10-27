"""The dump scan planner shared by the key-finder, strings and YARA producers.

What to read from ONE dump, in which coordinates, window by window:

* :func:`build_plan` turns a dump + ``view`` / ``offset`` / ``length`` into a
  :class:`Plan` whose :class:`Segment` s are the VA-contiguous CAPTURED runs in
  scope (absent bytes are never read, so never invented as zeros).
* :func:`read_windows` reads one segment in bounded windows of ``WINDOW_BYTES``
  that overlap by ``WINDOW_OVERLAP``; :func:`owns` decides which window reports a
  match on a seam and :func:`owned_bytes` which bytes count as scanned.
* :func:`coverage` is the ``coverage`` dict every producer returns;
  :func:`regions_of` the VMA / region lookup its rows are enriched with.

The window constants are read from this module at call time, so tests shrink the
windows with ``monkeypatch.setattr(scan_plan, "WINDOW_BYTES", ...)``.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Bytes read and handed to the scanner at a time (a bounded working set).
WINDOW_BYTES = 32 * 1024 * 1024
#: Bytes two neighbouring windows share, so a hit on the seam is found once.
WINDOW_OVERLAP = 64 * 1024

#: ``check(source, view) -> chosen view`` (raises INVALID_INPUT), see :func:`check_view`.
ViewCheck = Callable[[Any, Optional[str]], str]


def invalid(message: str, code: str) -> CapabilityError:
    """An INVALID_INPUT :class:`CapabilityError` with *code*."""
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


# -- plan: what to read, in which coordinates -------------------------------------


class Segment(NamedTuple):
    """One VA-contiguous captured stretch: never scanned across its end."""

    addr: int            # address of byte 0 in the scanned view
    length: int
    vas: int             # offset of byte 0 in the stream ``read_range`` reads
    va: Optional[int]    # virtual address of byte 0 (``None`` for a flat file)
    lead: int = 0        # leading bytes read only to keep the stride grid absolute

    @property
    def floor(self) -> int:
        """First address a hit may start at (the requested offset)."""
        return self.addr + self.lead

    def clip(self, lo: int, hi: Optional[int], align: int = 1) -> Optional["Segment"]:
        """The part inside ``[lo, hi)``, its read start moved down to a multiple of ``align``.

        Finders walk a stride grid from the first byte they are given; starting the
        read at an ``align``-aligned address (never before this run's own start) keeps
        that grid absolute. The ``lead`` bytes are read but cannot produce hits.
        """
        start = max(self.addr, lo)
        end = self.addr + self.length if hi is None else min(self.addr + self.length, hi)
        if end <= start:
            return None
        read_from = max(self.addr, start - start % align)
        delta = read_from - self.addr
        return Segment(read_from, end - read_from, self.vas + delta,
                       None if self.va is None else self.va + delta, start - read_from)


@dataclass
class Plan:
    source: Any
    path: Path
    view: str
    read_view: str
    segments: List[Segment]
    capture_id: str
    pid: Optional[int]
    image_sha256: Optional[str]
    heap_view: str
    span_start: Optional[int]

    def location(self, addr: int) -> Location:
        if self.read_view == "raw":
            return Location(AddressSpace.FILE_OFFSET, addr, capture_id=self.capture_id)
        if self.source.format_name == "msl":
            space = AddressSpace.MSL_VA if self.view == "va" else AddressSpace.MSL_VAS
            return Location(space, addr, capture_id=self.capture_id)
        return self.source.location(addr)


def merged(runs: Sequence[Tuple[int, int, int]]) -> List[Tuple[int, int, int]]:
    """Captured ``(va, length, vas)`` runs, adjacent-in-both-coordinates joined."""
    out: List[Tuple[int, int, int]] = []
    for va, length, vas in sorted(r for r in runs if r[1] > 0):
        if out and out[-1][0] + out[-1][1] == va and out[-1][2] + out[-1][1] == vas:
            out[-1] = (out[-1][0], out[-1][1] + length, out[-1][2])
        else:
            out.append((va, length, vas))
    return out


def check_view(source: Any, view: Optional[str], producer: str = "key finders",
               code_prefix: str = "keyfinders", usable: str = "scannable") -> str:
    """The view to scan *source* in (``view`` or the format's default), else INVALID_INPUT.

    ``producer`` / ``code_prefix`` / ``usable`` word the errors for the calling producer.
    """
    packed = hasattr(source, "captured_runs")
    chosen = view or ("va" if packed else "raw")
    allowed = {"msl": ("va", "vas"), "image_view": ("va",)}.get(source.format_name)
    if not packed:
        allowed = ("raw",)
    if allowed is None:
        raise invalid(f"{producer} do not support {source.format_name!r} dumps",
                      f"{code_prefix}.unsupported_format")
    if chosen not in allowed:
        raise invalid(f"view {chosen!r} is not {usable} for a {source.format_name!r} "
                      f"dump; choose one of: {', '.join(allowed)}", f"{code_prefix}.bad_view")
    return chosen


def clipped(segments: Sequence[Segment], offset: Optional[int],
            length: Optional[int], align: int = 1) -> List[Segment]:
    """*segments* cut to ``[offset, offset + length)`` (``None``: from 0 / to the end)."""
    lo = offset or 0
    hi = None if length is None else lo + length
    return [c for c in (s.clip(lo, hi, align) for s in segments) if c is not None]


def segments_of(source: Any, view: str) -> List[Segment]:
    """Every captured run of *source* as a :class:`Segment`, ordered in *view*."""
    if not hasattr(source, "captured_runs"):
        return [Segment(0, int(source.size), 0, None)] if source.size else []
    runs = merged(source.captured_runs())
    key = (lambda r: r[2]) if view == "vas" else (lambda r: r[0])
    return [Segment(key(r), r[1], r[2], r[0]) for r in sorted(runs, key=key)]


def heap_view_of(source: Any, view: str) -> Tuple[str, Optional[int]]:
    """The view heap code maps offsets through, and its span start (va view only)."""
    from memdiver.core.dump_source import supported_views

    if not hasattr(source, "captured_runs"):
        return "raw", None
    span = source.va_span_start() if "va" in supported_views(source) else None
    return ("va", span) if view == "va" and span is not None else ("vas", None)


def build_plan(source: Any, path: Path, view: Optional[str], offset: Optional[int],
               length: Optional[int], align: int = 1,
               check: ViewCheck = check_view) -> Plan:
    """The :class:`Plan` for *source*; ``check`` picks / validates the view."""
    from memdiver.analysis.capture_id import capture_id_for

    chosen = check(source, view)
    heap_view, span = heap_view_of(source, chosen)
    descriptor = getattr(source, "descriptor", None)
    pid = descriptor.pid if descriptor is not None else source.metadata().get("pid")
    return Plan(
        source=source, path=path, view=chosen,
        read_view="raw" if not hasattr(source, "captured_runs") else "vas",
        segments=clipped(segments_of(source, chosen), offset, length, align),
        capture_id=capture_id_for(path), pid=pid,
        image_sha256=getattr(descriptor, "image_sha256", None),
        heap_view=heap_view, span_start=span)


def dump_file(dump_path: str) -> Path:
    """*dump_path* as an existing file, else INVALID_INPUT / NOT_FOUND."""
    if not dump_path or not str(dump_path).strip():
        raise invalid("dump_path is required", "dump_path_required")
    path = Path(dump_path).expanduser()
    if not path.is_file():
        raise CapabilityError(f"dump not found: {path}",
                              category=ErrorCategory.NOT_FOUND, code="dump_not_found")
    return path


def scan_size(dump_path: str, view: Optional[str] = None, offset: Optional[int] = None,
              length: Optional[int] = None, check: ViewCheck = check_view) -> int:
    """Captured bytes a scan would read (cheap: run tables only); used to pick sync/job."""
    from memdiver.core.dump_source import open_dump

    path = dump_file(dump_path)
    with open_dump(path) as source:
        chosen = check(source, view)
        return sum(s.length - s.lead
                   for s in clipped(segments_of(source, chosen), offset, length))


# -- regions ------------------------------------------------------------------


class Regions:
    """VMA / region lookup by virtual address (empty for flat files)."""

    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self._rows = sorted(rows, key=lambda r: r["start"])
        self._starts = [r["start"] for r in self._rows]

    def at(self, va: Optional[int]) -> Optional[Dict[str, Any]]:
        if va is None or not self._rows:
            return None
        i = bisect.bisect_right(self._starts, va) - 1
        return self._rows[i] if i >= 0 and va < self._rows[i]["end"] else None


def perms(protection: Any) -> Optional[str]:
    """``rwx``-style text of an MSL protection bit-set (r=1, w=2, x=4); text passes through."""
    if protection is None or isinstance(protection, str):
        return protection
    return "".join(c if protection & bit else "-" for c, bit in (("r", 1), ("w", 2), ("x", 4)))


def msl_regions(source: Any, path: Path) -> List[Dict[str, Any]]:
    """The VAS map's regions; the captured-region headers when the dump has no VAS map.

    Read from *source*'s already-open reader (the effective VAS map, as
    ``inspect.vas`` reports it); *path* is kept for existing callers only.
    """
    reader = source.get_reader()
    vas_map = reader.effective_vas_map()
    entries = vas_map.entries if vas_map is not None else []
    if entries:
        return [{"start": e.base_addr, "end": e.base_addr + e.region_size,
                 "perms": perms(e.protection), "path": e.mapped_path or None,
                 "type": e.region_type} for e in entries]
    return [{"start": r.base_addr, "end": r.base_addr + r.region_size,
             "perms": perms(r.protection), "path": None, "type": r.region_type}
            for r in reader.collect_regions()]


def vma_regions(source: Any) -> List[Dict[str, Any]]:
    return [{"start": v.start, "end": v.end, "perms": perms(v.protection),
             "path": v.name or None, "type": "heap" if v.is_heap else None}
            for v in source.vmas()]


def regions_of(plan: Plan) -> Regions:
    if plan.source.format_name == "msl":
        return Regions(msl_regions(plan.source, plan.path))
    if hasattr(plan.source, "vmas"):
        return Regions(vma_regions(plan.source))
    return Regions([])


# -- read windows -------------------------------------------------------------


def windows(seg: Segment) -> List[int]:
    """Run-relative start of every read window of *seg*; together they tile it exactly.

    A window is needed only while the one before it ends short of the run's end:
    window ``w`` follows one that ends at ``w + WINDOW_OVERLAP``, so the starts
    stop below ``length - WINDOW_OVERLAP``. The first window whose end reaches
    the run's end is thus the last one (:func:`window_want` says so), and no
    window re-reads a tail the previous one already covered. An empty run has none.
    """
    if seg.length <= 0:
        return []
    step = WINDOW_BYTES - WINDOW_OVERLAP
    return list(range(0, max(seg.length - WINDOW_OVERLAP, 1), step))


def window_want(seg: Any, window: int) -> Tuple[int, bool]:
    """``(bytes to read, is this the run's last window)`` for the window at *window*."""
    want = min(WINDOW_BYTES, seg.length - window)
    return want, window + want >= seg.length


def owned_bytes(read: int, last: bool) -> int:
    """Bytes of a window read of *read* bytes that count as scanned (the overlap is the next's)."""
    return read if last else min(WINDOW_BYTES - WINDOW_OVERLAP, read)


class Window(NamedTuple):
    """One read window of a captured run."""

    offset: int     # window start, relative to the run
    data: bytes     # what came back (never padded: may be shorter than asked)
    last: bool      # the run's final window
    short: bool     # the read returned fewer bytes than asked


def read_windows(plan: Any, seg: Any,
                 before_read: Optional[Callable[[], None]] = None) -> Iterator[Window]:
    """Read *seg* window by window, lazily (a caller that stops early reads no further).

    ``before_read()`` runs before each window is read (e.g. a cancel poll that raises).
    """
    for window in windows(seg):
        if before_read is not None:
            before_read()
        want, last = window_want(seg, window)
        data = plan.source.read_range(seg.vas + window, want, plan.read_view)
        yield Window(window, data, last, len(data) < want)


def owns(offset: int, window: int, last: bool) -> bool:
    """Does the read window starting at *window* own a match starting at *offset*?

    Consecutive windows overlap by ``WINDOW_OVERLAP``; the ownership boundary sits
    in the middle of that overlap, ``guard`` bytes before the first window's end.
    Every match thus starts with at least ``guard`` bytes of data after it in its
    owning window (so a key schedule or string that crosses the seam is seen whole,
    and merge-based finders such as ``entropy_window`` have context) and is reported
    by exactly one window. A match that outruns even that is clipped at its
    owner's end, and its tail - which starts at the next window's offset 0, inside
    the guard - is never reported again.
    """
    guard = WINDOW_OVERLAP // 2
    step = WINDOW_BYTES - WINDOW_OVERLAP
    return (window == 0 or offset >= guard) and (last or offset < step + guard)


# -- coverage -----------------------------------------------------------------


def gap_stats(segments: Sequence[Segment]) -> Tuple[int, int]:
    """(gaps, gap bytes) between consecutive scanned segments, in virtual addresses."""
    ordered = sorted((s.va, s.length) for s in segments if s.va is not None)
    gaps = [b_va - (a_va + a_len) for (a_va, a_len), (b_va, _) in zip(ordered, ordered[1:])]
    return len(gaps), sum(gaps)


def coverage(plan: Plan, scan: Any, offset: Optional[int],
             length: Optional[int]) -> Dict[str, Any]:
    """The ``coverage`` dict; *scan* is any tally with ``bytes_scanned`` / ``runs_scanned``
    / ``short_reads`` (the key finders', strings' and YARA producers' all qualify)."""
    gaps, gap_bytes = gap_stats(plan.segments)
    return {"view": plan.view, "requested_offset": offset or 0,
            "requested_length": length,
            "captured_bytes": sum(s.length - s.lead for s in plan.segments),
            "bytes_scanned": scan.bytes_scanned, "runs_scanned": scan.runs_scanned,
            "gaps_skipped": gaps, "gap_bytes": gap_bytes,
            "short_reads": scan.short_reads}


def incomplete_reason(truncated: bool, short_reads: int) -> Optional[str]:
    """Why a scan is not ``complete``: ``truncated`` (limit), ``short_reads``, or ``None``."""
    if truncated:
        return "truncated"
    return "short_reads" if short_reads else None


__all__ = ["WINDOW_BYTES", "WINDOW_OVERLAP", "Plan", "Regions", "Segment", "ViewCheck",
           "Window", "build_plan", "check_view", "clipped", "coverage", "dump_file",
           "gap_stats", "heap_view_of", "incomplete_reason", "invalid", "merged",
           "msl_regions", "owned_bytes", "owns", "perms", "read_windows", "regions_of",
           "scan_size", "segments_of", "vma_regions", "window_want", "windows"]
