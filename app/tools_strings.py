"""Strings table producer: every string of the CAPTURED bytes, one row each.

The ``strings.table`` capability. It reuses :func:`memdiver.core.strings.extract_strings`
(ASCII / UTF-8) and its UTF-16LE sibling per captured run, with the same scan plan
(:mod:`memdiver.app.tools_keyfinders`) the key finders use:

* **P2, every address carries its coordinate system.** A row's ``addr`` is in the
  scanned ``view`` and names its ``space`` plus a full ``location`` dict.
* **P3, coverage is part of the answer; absent bytes are never zeros.** Only
  CAPTURED runs are read, one VA-contiguous run at a time, so a string is never
  joined across a capture gap. ``coverage`` reports what was scanned; a ``limit``
  that cuts the result sets ``truncated`` and stops the scan.
* **Interpretations live in the case.** With ``case_dir`` the rows become the
  ``strings`` table; the ``strings_iocs`` saved query
  (:mod:`memdiver.analysis.queries.strings`) then extracts IOC columns in DuckDB.

Rows also carry ``iocs`` (the IOC kinds that match, from the same patterns) so a
surface can badge them without a case. The badges are computed from the STORED
(possibly cut) ``value``, so they always agree with what the ``strings_iocs`` query
extracts from the case table: an IOC beyond the cut is not badged (``value_truncated``
tells the reader the row is partial). A ``value`` longer than
:data:`MAX_VALUE_CHARS` is cut and says so (``value_truncated``); ``length``
stays the true character count. A string longer than the window overlap that
straddles two read windows is reported clipped (``coverage.clipped_strings``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from memdiver.app import tools_keyfinders as _scan
from memdiver.core.service_errors import CapabilityError
from memdiver.core.service_result import ServiceResult

ENCODINGS: Tuple[str, ...] = ("ascii", "utf-8", "utf16le")
DEFAULT_ENCODINGS: Tuple[str, ...] = ("ascii", "utf16le")
DEFAULT_MIN_LEN = 4
#: Rows a scan returns before it stops and reports ``truncated``.
DEFAULT_LIMIT = 50_000
#: Characters of ``value`` kept per row.
MAX_VALUE_CHARS = 4096

ProgressFn = Callable[[float, str], None]


def _invalid(message: str, code: str) -> CapabilityError:
    return _scan._invalid(message, code)


# -- validation ------------------------------------------------------------------


def _check_view(source: Any, view: Optional[str]) -> str:
    packed = hasattr(source, "captured_runs")
    chosen = view or ("va" if packed else "raw")
    allowed = {"msl": ("va", "vas"), "image_view": ("va",)}.get(source.format_name)
    if not packed:
        allowed = ("raw",)
    if allowed is None:
        raise _invalid(f"strings do not support {source.format_name!r} dumps",
                       "strings.unsupported_format")
    if chosen not in allowed:
        raise _invalid(f"view {chosen!r} is not available for a {source.format_name!r} "
                       f"dump; choose one of: {', '.join(allowed)}", "strings.bad_view")
    return chosen


def _validated(encodings: Sequence[str], min_len: int, limit: int,
               region: Optional[Tuple[int, int]]) -> Tuple[str, ...]:
    names = tuple(dict.fromkeys(encodings))
    bad = [e for e in names if e not in ENCODINGS]
    if not names or bad:
        raise _invalid(f"unknown encoding(s): {bad or 'none given'}; "
                       f"choose from: {', '.join(ENCODINGS)}", "strings.bad_encoding")
    if min_len < 1:
        raise _invalid("min_len must be >= 1", "strings.bad_min_len")
    if limit < 1:
        raise _invalid("limit must be >= 1", "invalid_limit")
    if region is not None and (region[0] < 0 or region[1] < 1):
        raise _invalid("region must be (offset >= 0, length >= 1)", "strings.bad_range")
    return names


# -- extraction ------------------------------------------------------------------


@dataclass
class _Scan:
    rows: List[Dict[str, Any]] = field(default_factory=list)
    bytes_scanned: int = 0
    runs_scanned: int = 0
    short_reads: int = 0
    clipped: int = 0
    truncated: bool = False


def _matches(data: bytes, encodings: Sequence[str], min_len: int) -> list:
    from memdiver.core.strings import extract_strings, extract_utf16le_strings

    found: list = []
    for enc in encodings:
        found += (extract_utf16le_strings(data, min_len) if enc == "utf16le"
                  else extract_strings(data, min_len, enc))
    return sorted(found, key=lambda m: (m.offset, m.encoding))


def _row_of(plan: Any, seg: Any, window: int, match: Any, regions: Any) -> Dict[str, Any]:
    from memdiver.analysis.queries.strings import (ioc_ambiguity, ioc_kinds,
                                                    oid_like_values)

    rel = window + match.offset
    addr = seg.addr + rel
    va = None if seg.va is None else seg.va + rel
    location = plan.location(addr)
    chars = len(match.value)
    wide = match.encoding == "utf16le"
    stored = match.value[:MAX_VALUE_CHARS]
    ambiguity, oid_prefix = ioc_ambiguity(stored) or (None, None)
    return {"addr": addr, "space": location.space.value, "location": location.to_dict(),
            "encoding": match.encoding, "length": chars,
            "byte_length": 2 * chars if wide else match.length,
            "value": stored, "value_truncated": len(match.value) > MAX_VALUE_CHARS,
            "iocs": ioc_kinds(stored), "ambiguity": ambiguity, "oid_prefix": oid_prefix,
            "oid_like_values": [{"value": v, "oid_prefix": p}
                                for v, p in oid_like_values(stored)],
            "va": va, "vas_offset": seg.vas + rel,
            "region": regions.at(va)}


def _window_rows(plan: Any, seg: Any, window: int, data: bytes, last: bool,
                 encodings: Sequence[str], min_len: int, regions: Any,
                 scan: _Scan) -> List[Dict[str, Any]]:
    rows = []
    for match in _matches(data, encodings, min_len):
        if not _scan._owns(match.offset, window, last):
            continue    # reported once, by the window that owns its start
        end = match.offset + match.length * (2 if match.encoding == "utf16le" else 1)
        scan.clipped += int(not last and end >= len(data))
        rows.append(_row_of(plan, seg, window, match, regions))
    return rows


def _scan_segment(plan: Any, seg: Any, encodings: Sequence[str], min_len: int,
                  regions: Any, limit: int, scan: _Scan,
                  progress: Optional[ProgressFn], total: int) -> bool:
    """Scan one captured run; ``False`` once the row limit stopped the scan."""
    step = _scan.WINDOW_BYTES - _scan.WINDOW_OVERLAP
    scan.runs_scanned += 1
    for window in _scan._windows(seg):
        want = min(_scan.WINDOW_BYTES, seg.length - window)
        data = plan.source.read_range(seg.vas + window, want, plan.read_view)
        scan.short_reads += int(len(data) < want)   # never pad: scan what came back
        last = window + want >= seg.length
        scan.rows.extend(_window_rows(plan, seg, window, data, last, encodings,
                                      min_len, regions, scan))
        scan.bytes_scanned += len(data) if last else min(step, len(data))
        if progress is not None:
            progress(min(scan.bytes_scanned / max(total, 1), 0.99), "extracting strings")
        if len(scan.rows) >= limit:
            more = not (last and seg is plan.segments[-1])
            scan.truncated = len(scan.rows) > limit or more
            return False
    return True


def _scan_plan(plan: Any, encodings: Sequence[str], min_len: int, limit: int,
               progress: Optional[ProgressFn]) -> _Scan:
    scan, regions = _Scan(), _scan._regions_of(plan)
    total = sum(s.length for s in plan.segments)
    for seg in plan.segments:
        if not _scan_segment(plan, seg, encodings, min_len, regions, limit, scan,
                             progress, total):
            break
    return scan


def _coverage(plan: Any, scan: _Scan, region: Optional[Tuple[int, int]]) -> Dict[str, Any]:
    gaps, gap_bytes = _scan._gap_stats(plan.segments)
    return {"view": plan.view, "requested_offset": region[0] if region else 0,
            "requested_length": region[1] if region else None,
            "captured_bytes": sum(s.length for s in plan.segments),
            "bytes_scanned": scan.bytes_scanned, "runs_scanned": scan.runs_scanned,
            "gaps_skipped": gaps, "gap_bytes": gap_bytes,
            "short_reads": scan.short_reads, "clipped_strings": scan.clipped}


# -- case integration ------------------------------------------------------------


def _table_row(row: Dict[str, Any]) -> Dict[str, Any]:
    region = row["region"] or {}
    return {"addr": row["addr"], "byte_length": row["byte_length"], "chars": row["length"],
            "encoding": row["encoding"], "value": row["value"], "va": row["va"],
            "vas_offset": row["vas_offset"], "region_start": region.get("start"),
            "region_end": region.get("end"), "region_perms": region.get("perms"),
            "region_path": region.get("path")}


def _file_case(plan: Any, rows: List[Dict[str, Any]], case_dir: str,
               truncated: bool) -> Dict[str, Any]:
    from memdiver.analysis.exporters import export_strings
    from memdiver.app.tools_case import _open

    case = _open(case_dir)
    ref = export_strings(case, [_table_row(r) for r in rows], capture_id=plan.capture_id,
                         space=plan.location(0).space.value, pid=plan.pid,
                         image_sha256=plan.image_sha256, truncated=truncated)
    return {"case_dir": str(case.dir), "table": ref.name, "run_id": ref.run_id,
            "rows": ref.row_count, "path": ref.path,
            "saved_query": "strings_iocs"}


# -- the producer ----------------------------------------------------------------


def _build_plan(view: Optional[str], region: Optional[Tuple[int, int]],
                source: Any, path: Path) -> Any:
    chosen = _check_view(source, view)
    offset, length = region if region else (None, None)
    return _scan._build_plan(source, path, chosen, offset, length)


#: A region given only an offset reads to the end of the dump.
OPEN_END = 1 << 62


def _region_of(offset: Optional[int], length: Optional[int]) -> Optional[Tuple[int, int]]:
    """``(offset, length)`` for the surfaces' two optional flags, ``None`` for neither."""
    if offset is None and length is None:
        return None
    return (offset or 0, OPEN_END if length is None else length)


def _scan_size(dump_path: str, view: Optional[str] = None,
                      region: Optional[Tuple[int, int]] = None) -> int:
    """Captured bytes a scan would read (run tables only); used to pick sync/job."""
    from memdiver.core.dump_source import open_dump

    path = _scan._dump_file(dump_path)
    with open_dump(path) as source:
        chosen = _check_view(source, view)
        offset, length = region if region else (None, None)
        return sum(s.length for s in _scan._clipped(
            _scan._segments_of(source, chosen), offset, length))


def strings_table_result(
    dump_path: str, view: Optional[str] = None,
    region: Optional[Tuple[int, int]] = None, min_len: int = DEFAULT_MIN_LEN,
    encodings: Sequence[str] = DEFAULT_ENCODINGS, limit: int = DEFAULT_LIMIT,
    case_dir: Optional[str] = None, progress: Optional[ProgressFn] = None,
) -> "ServiceResult":
    """One row per printable string in the CAPTURED bytes of a dump.

    ``view`` / ``region`` ``(offset, length)`` select the window in the view's
    coordinates (default ``va`` for an ``.msl`` / ``.mdview``, ``raw`` for a flat
    file; ``vas`` is also offered for an ``.msl``). ``encodings``: ``ascii``,
    ``utf-8``, ``utf16le``. Each row: ``addr`` + ``space`` + ``location``,
    ``encoding``, ``length`` (characters), ``byte_length``, ``value``, ``iocs``,
    ``va``, ``vas_offset`` and ``region`` (``start``/``end``/``perms``/``path``
    when known). Strings never cross a capture gap. ``truncated`` says whether
    ``limit`` cut the rows; ``coverage`` says what was read. With ``case_dir`` the
    rows become the ``strings`` table (query it with the ``strings_iocs`` saved query).
    """
    from memdiver.core.dump_source import open_dump

    names = _validated(encodings, min_len, limit, region)
    path = _scan._dump_file(dump_path)
    with open_dump(path) as source:
        plan = _build_plan(view, region, source, path)
        scan = _scan_plan(plan, names, min_len, limit, progress)
    rows = scan.rows[:limit]
    truncated = scan.truncated or len(scan.rows) > limit
    payload: Dict[str, Any] = {
        "dump_path": str(path), "format": source.format_name, "view": plan.view,
        "space": plan.location(0).space.value, "capture_id": plan.capture_id,
        "min_len": min_len, "encodings": list(names),
        "rows": rows, "row_count": len(rows), "limit": limit,
        "oid_like_count": sum(r["ambiguity"] == "oid_like" for r in rows),
        "truncated": truncated,
        "complete": not (truncated or scan.short_reads),
        "incomplete_reason": _scan._incomplete_reason(truncated, scan.short_reads),
        "coverage": _coverage(plan, scan, region),
    }
    if case_dir:
        payload["case"] = _file_case(plan, rows, case_dir, truncated)
    return ServiceResult.ok(payload)


__all__ = ["DEFAULT_ENCODINGS", "DEFAULT_LIMIT", "ENCODINGS",
           "strings_table_result"]
