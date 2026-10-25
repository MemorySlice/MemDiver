"""Key-finder producers: list the finders, scan a dump with them.

The ``keyfinders.*`` capabilities. A key finder recognises key material by its
structure (an expanded AES schedule, an RSA private key, ...) with no ground
truth; every finder is an ordinary registry algorithm whose module lives in
:mod:`memdiver.algorithms.keyfinders`, so new finders appear here with no edit.

Semantic-workbench rules this module is built around:

* **P2, every address carries its coordinate system.** A hit's ``addr`` is in
  the scanned ``view`` (``va`` = virtual address, ``vas`` = packed ``.msl`` stream
  offset, ``raw`` = file offset) and each row names its ``space`` plus a full
  :class:`~memdiver.core.location.Location` dict.
* **P3, coverage is part of the answer; absent bytes are never zeros.** Only
  CAPTURED runs are read, one VA-contiguous run at a time, so a structure that
  would straddle a capture gap is not found rather than found in invented zeros.
  ``coverage`` reports bytes scanned, runs scanned and gaps skipped; a ``limit``
  that cuts the result sets ``truncated`` and stops the scan (``complete: false``).
* **Interpretations live in the case, never in the ``.msl``.** With ``case_dir``
  the hits become the ``key_hits`` table (one ``case query`` can join it to
  ``heap_chunks`` / ``msl_regions``) and ``key_hit`` analysis-record entries.

``heap_policy``: ``off`` | ``annotate`` (attach the holding allocator chunk) |
``mask`` (keep only hits whose first AND last byte sit in one chunk's
``user_data``). ``mask`` is decided per hit from the chunk annotation rather than
through :class:`~memdiver.engine.consensus_heap.HeapRoleRuns`, which is a
consensus-slab-coordinate structure; a single dump's hit already has an exact
VA, so the per-hit check is exact and needs no projection.
"""

from __future__ import annotations

import ast
import bisect
import inspect
import math
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

FINDERS_PACKAGE = "memdiver.algorithms.keyfinders"
DEFAULT_FINDERS: Tuple[str, ...] = ("aes_schedule",)
HEAP_POLICIES: Tuple[str, ...] = ("off", "annotate", "mask")
#: Rows a scan returns before it stops and reports ``truncated``.
DEFAULT_LIMIT = 10_000
#: Bytes read and handed to the finders at a time (a bounded working set).
WINDOW_BYTES = 32 * 1024 * 1024
#: Bytes two neighbouring windows share, so a hit on the seam is found once.
WINDOW_OVERLAP = 64 * 1024
#: Author of the ``key_hit`` analysis-record entries.
ANNOTATION_AUTHOR = "tool:keyfinders"

ProgressFn = Callable[[float, str], None]


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


# -- finder discovery ----------------------------------------------------------


def _finders() -> Dict[str, Any]:
    """Registry algorithms living in the key-finder package, by name."""
    from memdiver.algorithms.registry import get_registry

    return {a.name: a for a in get_registry().list_all()
            if type(a).__module__.startswith(FINDERS_PACKAGE)}


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _default_of(node: ast.expr, module: Any) -> Any:
    try:
        return _jsonable(ast.literal_eval(node))
    except (ValueError, SyntaxError):
        pass
    if isinstance(node, ast.Name) and hasattr(module, node.id):
        return _jsonable(getattr(module, node.id))
    return None


def _is_extra_get(call: ast.Call) -> bool:
    func = call.func
    holder = func.value if isinstance(func, ast.Attribute) and func.attr == "get" else None
    named = isinstance(holder, ast.Name) and holder.id == "extra"
    attr = isinstance(holder, ast.Attribute) and holder.attr == "extra"
    return (named or attr) and bool(call.args) and isinstance(call.args[0], ast.Constant)


def _introspected_parameters(finder: Any) -> List[Dict[str, Any]]:
    """``extra.get("name", default)`` reads of the finder's ``run``, in source order."""
    module = sys.modules.get(type(finder).__module__)
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(type(finder).run)))
    except (OSError, TypeError, SyntaxError):
        return []
    found: Dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_extra_get(node):
            default = _default_of(node.args[1], module) if len(node.args) > 1 else None
            found.setdefault(str(node.args[0].value), default)
    return [{"name": n, "default": d, "source": "introspected"} for n, d in found.items()]


def _parameters(finder: Any) -> List[Dict[str, Any]]:
    """Declared ``parameters`` (a dict or list on the finder) win over introspection."""
    declared = getattr(finder, "parameters", None)
    if isinstance(declared, dict):
        return [{"name": n, **(_jsonable(d) if isinstance(d, dict) else {"default": _jsonable(d)}),
                 "source": "declared"} for n, d in declared.items()]
    if declared:
        return [{**_jsonable(d), "source": "declared"} for d in declared]
    return _introspected_parameters(finder)


def keyfinders_list_result() -> "ServiceResult":
    """Every key finder with its description, mode and ``params`` it understands."""
    rows = [{"name": f.name, "description": f.description, "mode": f.mode,
             "module": type(f).__module__, "parameters": _parameters(f)}
            for f in sorted(_finders().values(), key=lambda f: f.name)]
    return ServiceResult.ok({"finders": rows, "count": len(rows),
                             "default_finders": [n for n in DEFAULT_FINDERS
                                                 if n in {r["name"] for r in rows}],
                             "heap_policies": list(HEAP_POLICIES)})


# -- scan plan: what to read, in which coordinates -------------------------------


class _Segment(NamedTuple):
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

    def clip(self, lo: int, hi: Optional[int], align: int = 1) -> Optional["_Segment"]:
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
        return _Segment(read_from, end - read_from, self.vas + delta,
                        None if self.va is None else self.va + delta, start - read_from)


@dataclass
class _Plan:
    source: Any
    path: Path
    view: str
    read_view: str
    segments: List[_Segment]
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


def _merged(runs: Sequence[Tuple[int, int, int]]) -> List[Tuple[int, int, int]]:
    """Captured ``(va, length, vas)`` runs, adjacent-in-both-coordinates joined."""
    out: List[Tuple[int, int, int]] = []
    for va, length, vas in sorted(r for r in runs if r[1] > 0):
        if out and out[-1][0] + out[-1][1] == va and out[-1][2] + out[-1][1] == vas:
            out[-1] = (out[-1][0], out[-1][1] + length, out[-1][2])
        else:
            out.append((va, length, vas))
    return out


def _check_view(source: Any, view: Optional[str]) -> str:
    packed = hasattr(source, "captured_runs")
    default = "va" if packed else "raw"
    chosen = view or default
    allowed = {"msl": ("va", "vas"), "image_view": ("va",)}.get(source.format_name)
    if not packed:
        allowed = ("raw",)
    if allowed is None:
        raise _invalid(f"key finders do not support {source.format_name!r} dumps",
                       "keyfinders.unsupported_format")
    if chosen not in allowed:
        raise _invalid(f"view {chosen!r} is not scannable for a {source.format_name!r} "
                       f"dump; choose one of: {', '.join(allowed)}", "keyfinders.bad_view")
    return chosen


def _clipped(segments: Sequence[_Segment], offset: Optional[int],
             length: Optional[int], align: int = 1) -> List[_Segment]:
    lo = offset or 0
    hi = None if length is None else lo + length
    return [c for c in (s.clip(lo, hi, align) for s in segments) if c is not None]


#: ``params`` keys that set a finder's stride, with the default (``None``: stride 1).
_STRIDE_PARAMS = {"stride": None, "step": None, "rsa_le_stride": 8, "rsa_be_stride": 1}
_MAX_ALIGN = 1 << 20


def _stride_alignment(names: Sequence[str], params: Dict[str, Any]) -> int:
    """Common alignment of the strides the selected finders will use (1 when none)."""
    strides = [1]
    for key, default in _STRIDE_PARAMS.items():
        if key.startswith("rsa") and "rsa_factor" not in names:
            continue
        value = params.get(key, default)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            strides.append(value)
    align = math.lcm(*strides)
    return align if align <= _MAX_ALIGN else 1


def _segments_of(source: Any, view: str) -> List[_Segment]:
    if not hasattr(source, "captured_runs"):
        return [_Segment(0, int(source.size), 0, None)] if source.size else []
    merged = _merged(source.captured_runs())
    key = (lambda r: r[2]) if view == "vas" else (lambda r: r[0])
    return [_Segment(key(r), r[1], r[2], r[0]) for r in sorted(merged, key=key)]


def _heap_view_of(source: Any, view: str) -> Tuple[str, Optional[int]]:
    """The view heap code maps offsets through, and its span start (va view only)."""
    from memdiver.core.dump_source import supported_views

    if not hasattr(source, "captured_runs"):
        return "raw", None
    span = source.va_span_start() if "va" in supported_views(source) else None
    return ("va", span) if view == "va" and span is not None else ("vas", None)


def _build_plan(source: Any, path: Path, view: Optional[str], offset: Optional[int],
                length: Optional[int], align: int = 1) -> _Plan:
    from memdiver.analysis.capture_id import capture_id_for

    chosen = _check_view(source, view)
    heap_view, span = _heap_view_of(source, chosen)
    descriptor = getattr(source, "descriptor", None)
    pid = descriptor.pid if descriptor is not None else source.metadata().get("pid")
    return _Plan(
        source=source, path=path, view=chosen,
        read_view="raw" if not hasattr(source, "captured_runs") else "vas",
        segments=_clipped(_segments_of(source, chosen), offset, length, align),
        capture_id=capture_id_for(path), pid=pid,
        image_sha256=getattr(descriptor, "image_sha256", None),
        heap_view=heap_view, span_start=span)


# -- regions ------------------------------------------------------------------


class _Regions:
    """VMA / region lookup by virtual address (empty for flat files)."""

    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self._rows = sorted(rows, key=lambda r: r["start"])
        self._starts = [r["start"] for r in self._rows]

    def at(self, va: Optional[int]) -> Optional[Dict[str, Any]]:
        if va is None or not self._rows:
            return None
        i = bisect.bisect_right(self._starts, va) - 1
        return self._rows[i] if i >= 0 and va < self._rows[i]["end"] else None


def _perms(protection: Any) -> Optional[str]:
    """``rwx``-style text of an MSL protection bit-set (r=1, w=2, x=4); text passes through."""
    if protection is None or isinstance(protection, str):
        return protection
    return "".join(c if protection & bit else "-" for c, bit in (("r", 1), ("w", 2), ("x", 4)))


def _msl_regions(source: Any, path: Path) -> List[Dict[str, Any]]:
    """The VAS map's regions; the captured-region headers when the dump has no VAS map."""
    from memdiver.app.session import ToolSession
    from memdiver.app.tools_inspect import vas_regions_result

    entries = vas_regions_result(ToolSession(), str(path)).payload["vas_entries"]
    if entries:
        return [{"start": e["base_addr"], "end": e["base_addr"] + e["region_size"],
                 "perms": _perms(e.get("protection")), "path": e.get("mapped_path") or None,
                 "type": e.get("region_type")} for e in entries]
    return [{"start": r.base_addr, "end": r.base_addr + r.region_size,
             "perms": _perms(r.protection), "path": None, "type": r.region_type}
            for r in source.get_reader().collect_regions()]


def _vma_regions(source: Any) -> List[Dict[str, Any]]:
    return [{"start": v.start, "end": v.end, "perms": _perms(v.protection),
             "path": v.name or None, "type": "heap" if v.is_heap else None}
            for v in source.vmas()]


def _regions_of(plan: _Plan) -> _Regions:
    if plan.source.format_name == "msl":
        return _Regions(_msl_regions(plan.source, plan.path))
    if hasattr(plan.source, "vmas"):
        return _Regions(_vma_regions(plan.source))
    return _Regions([])


# -- hits ---------------------------------------------------------------------


@dataclass
class _Hit:
    row: Dict[str, Any]
    candidate: Dict[str, Any] = field(default_factory=dict)


def _translated(metadata: Dict[str, Any], delta: int) -> Dict[str, Any]:
    """``*_offset`` metadata is window-relative; move it into the view's coordinates."""
    out = _jsonable(metadata)
    for key, value in metadata.items():
        if key.endswith("_offset") and isinstance(value, int) and not isinstance(value, bool):
            out[key] = value + delta
    return out


def _candidate(finder: str, match: Any, row: Dict[str, Any], seg: _Segment,
               window: int) -> Dict[str, Any]:
    """A ``candidates.json`` region (offset into the flat reference stream)."""
    key_offset = match.metadata.get("key_offset")
    key_hex = match.metadata.get("key_hex")
    if isinstance(key_offset, int) and key_hex:
        offset, length = seg.vas + window + key_offset, len(key_hex) // 2
    else:
        offset, length = row["vas_offset"], row["length"]
    return {"offset": int(offset), "length": int(length), "finder": finder,
            "label": row["label"], "confidence": row["confidence"],
            "addr": row["addr"], "space": row["space"]}


def _hit_of(plan: _Plan, finder: str, match: Any, seg: _Segment, window: int) -> _Hit:
    rel = window + match.offset
    addr = seg.addr + rel
    location = plan.location(addr)
    row = {"finder": finder, "label": match.label, "addr": addr,
           "space": location.space.value, "location": location.to_dict(),
           "length": int(match.length), "confidence": float(match.confidence),
           "metadata": _translated(match.metadata, seg.addr + window),
           "va": None if seg.va is None else seg.va + rel,
           "vas_offset": seg.vas + rel, "heap": None, "region": None}
    return _Hit(row, _candidate(finder, match, row, seg, window))


# -- heap enrichment ------------------------------------------------------------


def _heap_offset(plan: _Plan, row: Dict[str, Any], last_byte: bool) -> int:
    shift = row["length"] - 1 if last_byte else 0
    if plan.heap_view == "va":
        return row["va"] + shift - plan.span_start
    return row["vas_offset"] + shift


def _annotate_heap(plan: _Plan, hits: List[_Hit]) -> None:
    from memdiver.engine.heap_hits import heap_hit_annotations

    rows = [h.row for h in hits if h.row["va"] is not None or plan.heap_view != "va"]
    offsets = [_heap_offset(plan, r, False) for r in rows]
    offsets += [_heap_offset(plan, r, True) for r in rows]
    found = heap_hit_annotations(plan.source, offsets, plan.heap_view, "auto")
    for row, first, last in zip(rows, found[:len(rows)], found[len(rows):]):
        if first is not None:
            row["heap"] = {**first, "spans_chunks": last is None
                           or last["chunk_va"] != first["chunk_va"]}


def _in_user_data(row: Dict[str, Any]) -> bool:
    heap = row["heap"]
    return heap is not None and heap["role"] == "user_data" and not heap["spans_chunks"]


def _enrich(plan: _Plan, hits: List[_Hit], regions: _Regions,
            policy: str) -> Tuple[List[_Hit], int]:
    """Attach region (+ heap) context; ``mask`` drops hits outside chunk user data."""
    for hit in hits:
        hit.row["region"] = regions.at(hit.row["va"])
    if policy == "off" or not hits:
        return hits, 0
    _annotate_heap(plan, hits)
    if policy != "mask":
        return hits, 0
    kept = [h for h in hits if _in_user_data(h.row)]
    return kept, len(hits) - len(kept)


def _heap_status(plan: _Plan, policy: str) -> str:
    from memdiver.heap.analyze import analyze_heap
    from memdiver.heap.model import AllocatorKind

    if policy == "off":
        return "off"
    try:
        layout = analyze_heap(plan.source, "auto")
    except Exception:  # noqa: BLE001 - annotation is soft, like heap_hit_annotations
        return "no_heap_detected"
    detected = layout.allocator != AllocatorKind.UNKNOWN and bool(layout.chunks)
    return "ok" if detected else "no_heap_detected"


# -- the scan -----------------------------------------------------------------


@dataclass
class _Scan:
    hits: List[_Hit] = field(default_factory=list)
    bytes_scanned: int = 0
    runs_scanned: int = 0
    short_reads: int = 0
    masked_out: int = 0
    stopped_early: bool = False


def _windows(seg: _Segment) -> List[int]:
    step = WINDOW_BYTES - WINDOW_OVERLAP
    return list(range(0, seg.length, step))


def _owns(offset: int, window: int, last: bool) -> bool:
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


def _run_finders(plan: _Plan, finders: Dict[str, Any], names: Sequence[str],
                 params: Dict[str, Any], seg: _Segment, window: int,
                 data: bytes, last: bool) -> List[_Hit]:
    from memdiver.algorithms.base import AnalysisContext

    context = AnalysisContext(library="", protocol_version="", phase="",
                              extra=dict(params))
    hits: List[_Hit] = []
    for name in names:
        for match in finders[name].run(data, context).matches:
            if (_owns(match.offset, window, last)
                    and seg.addr + window + match.offset >= seg.floor):
                hits.append(_hit_of(plan, name, match, seg, window))
    return sorted(hits, key=lambda h: (h.row["addr"], h.row["finder"], h.row["label"]))


def _scan_segment(plan: _Plan, finders: Dict[str, Any], names: Sequence[str],
                  params: Dict[str, Any], seg: _Segment, regions: _Regions,
                  policy: str, limit: int, scan: _Scan,
                  progress: Optional[ProgressFn], total: int) -> None:
    step = WINDOW_BYTES - WINDOW_OVERLAP
    scan.runs_scanned += 1
    scan.bytes_scanned -= seg.lead      # read to align the stride grid, not scanned
    for window in _windows(seg):
        want = min(WINDOW_BYTES, seg.length - window)
        data = plan.source.read_range(seg.vas + window, want, plan.read_view)
        scan.short_reads += int(len(data) < want)   # never pad: scan only what came back
        last = window + want >= seg.length
        found = _run_finders(plan, finders, names, params, seg, window, data, last)
        kept, dropped = _enrich(plan, found, regions, policy)
        scan.hits.extend(kept)
        scan.masked_out += dropped
        scan.bytes_scanned += len(data) if last else min(step, len(data))
        if progress is not None:
            progress(min(scan.bytes_scanned / max(total, 1), 0.99), "scanning")
        if len(scan.hits) >= limit:
            scan.stopped_early = not (last and seg is plan.segments[-1])
            return


def _harvest_moduli(plan: _Plan, params: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    """RSA moduli of EVERY captured run in scope, so a prime in one run meets its modulus
    held in another. Provenance keeps the source kind; the offset is dropped (it is only
    meaningful inside the window it was read from)."""
    from memdiver.algorithms.keyfinders import rsa_factor as rf

    if not params.get("rsa_scan_public_keys", True):
        return {}
    found: Dict[int, Dict[str, Any]] = {}
    for seg in plan.segments:
        for window in _windows(seg):
            want = min(WINDOW_BYTES, seg.length - window)
            data = plan.source.read_range(seg.vas + window, want, plan.read_view)
            for n, info in rf.collect_moduli(
                    data, (), True, params.get("rsa_min_bits", rf.DEFAULT_MIN_BITS),
                    params.get("rsa_max_bits", rf.DEFAULT_MAX_BITS),
                    params.get("rsa_max_moduli", rf.DEFAULT_MAX_MODULI)).items():
                found.setdefault(n, {**info, "offset": None})
    return dict(list(found.items())[:params.get("rsa_max_moduli", rf.DEFAULT_MAX_MODULI)])


def _with_harvested_moduli(plan: _Plan, names: Sequence[str],
                           params: Dict[str, Any]) -> Dict[str, Any]:
    """``params`` plus ``rsa_moduli_info`` when ``rsa_factor`` runs over several windows."""
    windows = sum(len(_windows(s)) for s in plan.segments)
    if "rsa_factor" not in names or windows < 2:
        return params
    return {**params, "rsa_moduli_info": _harvest_moduli(plan, params)}


def _gap_stats(segments: Sequence[_Segment]) -> Tuple[int, int]:
    """(gaps, gap bytes) between consecutive scanned segments, in virtual addresses."""
    ordered = sorted((s for s in segments if s.va is not None), key=lambda s: s.va)
    gaps = [b.va - (a.va + a.length) for a, b in zip(ordered, ordered[1:])]
    return len(gaps), sum(gaps)


def _scan_plan(plan: _Plan, finders: Dict[str, Any], names: Sequence[str],
               params: Dict[str, Any], policy: str, limit: int,
               progress: Optional[ProgressFn]) -> _Scan:
    scan, regions = _Scan(), _regions_of(plan)
    params = _with_harvested_moduli(plan, names, params)
    total = sum(s.length for s in plan.segments)
    for seg in plan.segments:
        _scan_segment(plan, finders, names, params, seg, regions, policy, limit,
                      scan, progress, total)
        if len(scan.hits) >= limit:
            break
    return scan


def _coverage(plan: _Plan, scan: _Scan, offset: Optional[int],
              length: Optional[int]) -> Dict[str, Any]:
    gaps, gap_bytes = _gap_stats(plan.segments)
    return {"view": plan.view, "requested_offset": offset or 0,
            "requested_length": length,
            "captured_bytes": sum(s.length - s.lead for s in plan.segments),
            "bytes_scanned": scan.bytes_scanned, "runs_scanned": scan.runs_scanned,
            "gaps_skipped": gaps, "gap_bytes": gap_bytes,
            "short_reads": scan.short_reads}


def _incomplete_reason(truncated: bool, short_reads: int) -> Optional[str]:
    """Why a scan is not ``complete``: ``truncated`` (limit), ``short_reads``, or ``None``."""
    if truncated:
        return "truncated"
    return "short_reads" if short_reads else None


# -- case integration ----------------------------------------------------------


def _table_row(row: Dict[str, Any]) -> Dict[str, Any]:
    import json

    heap, region = row["heap"] or {}, row["region"] or {}
    return {"addr": row["addr"], "length": row["length"], "va": row["va"],
            "vas_offset": row["vas_offset"], "confidence": row["confidence"],
            "finder": row["finder"], "label": row["label"],
            "key_hex": row["metadata"].get("key_hex"),
            "heap_chunk_va": heap.get("chunk_va"), "heap_chunk_size": heap.get("chunk_size"),
            "heap_role": heap.get("role"), "heap_state": heap.get("state"),
            "region_start": region.get("start"), "region_end": region.get("end"),
            "region_perms": region.get("perms"), "region_path": region.get("path"),
            "metadata_json": json.dumps(row["metadata"], sort_keys=True)}


def _entry_of(plan: _Plan, row: Dict[str, Any], run_id: str):
    from memdiver.analysis.record import KEY_HIT, AnalysisEntry, Support

    payload = {"finder": row["finder"], "label": row["label"],
               "confidence": row["confidence"], "metadata": row["metadata"],
               "heap": row["heap"], "region": row["region"], "table_run_id": run_id}
    return AnalysisEntry(
        capture_id=plan.capture_id, kind=KEY_HIT, author=ANNOTATION_AUTHOR,
        locations=(Location.from_dict(row["location"]),), length=row["length"],
        label=f"{row['finder']}:{row['label']}", payload=payload,
        support=(Support("keyfinder", row["finder"]),))


def _file_case(plan: _Plan, rows: List[Dict[str, Any]], case_dir: str,
               truncated: bool, annotate: bool) -> Dict[str, Any]:
    from memdiver.analysis.exporters import export_key_hits
    from memdiver.analysis.record_store import AnalysisRecord
    from memdiver.app.tools_case import _open

    case = _open(case_dir)
    ref = export_key_hits(
        case, [_table_row(r) for r in rows], capture_id=plan.capture_id,
        space=plan.location(0).space.value, pid=plan.pid,
        image_sha256=plan.image_sha256, truncated=truncated)
    entries = 0
    if annotate:
        record = AnalysisRecord(case.dir)
        for row in rows:
            record.append(_entry_of(plan, row, ref.run_id))
            entries += 1
    return {"case_dir": str(case.dir), "table": ref.name, "run_id": ref.run_id,
            "rows": ref.row_count, "path": ref.path, "annotations": entries,
            "annotation_kind": "key_hit"}


def _write_candidates(candidates: List[Dict[str, Any]], out: str) -> str:
    from memdiver.app.tools_pipeline import _dump_json

    path = Path(out).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    _dump_json({"regions": candidates}, path)
    return str(path)


# -- the producer -----------------------------------------------------------------


def _validated(finders: Sequence[str], heap_policy: str, limit: int,
               offset: Optional[int], length: Optional[int]) -> Dict[str, Any]:
    known = _finders()
    unknown = [f for f in finders if f not in known]
    if not finders or unknown:
        raise _invalid(f"unknown key finder(s): {unknown or 'none given'}; "
                       f"choose from: {', '.join(sorted(known))}", "keyfinders.unknown_finder")
    if heap_policy not in HEAP_POLICIES:
        raise _invalid(f"heap_policy must be one of {', '.join(HEAP_POLICIES)}",
                       "keyfinders.bad_heap_policy")
    if limit < 1:
        raise _invalid("limit must be >= 1", "invalid_limit")
    if (offset is not None and offset < 0) or (length is not None and length < 1):
        raise _invalid("offset must be >= 0 and length >= 1", "keyfinders.bad_range")
    return known


def _dump_file(dump_path: str) -> Path:
    if not dump_path or not str(dump_path).strip():
        raise _invalid("dump_path is required", "dump_path_required")
    path = Path(dump_path).expanduser()
    if not path.is_file():
        raise CapabilityError(f"dump not found: {path}",
                              category=ErrorCategory.NOT_FOUND, code="dump_not_found")
    return path


def _scan_size(dump_path: str, view: Optional[str] = None, offset: Optional[int] = None,
               length: Optional[int] = None) -> int:
    """Captured bytes a scan would read (cheap: run tables only); used to pick sync/job."""
    from memdiver.core.dump_source import open_dump

    path = _dump_file(dump_path)
    with open_dump(path) as source:
        chosen = _check_view(source, view)
        return sum(s.length - s.lead
                   for s in _clipped(_segments_of(source, chosen), offset, length))


def keyfinders_scan_result(
    dump_path: str, finders: Sequence[str] = DEFAULT_FINDERS,
    view: Optional[str] = None, offset: Optional[int] = None,
    length: Optional[int] = None, heap_policy: str = "annotate",
    params: Optional[Dict[str, Any]] = None, case_dir: Optional[str] = None,
    limit: int = DEFAULT_LIMIT, candidates_out: Optional[str] = None,
    annotate: bool = True, progress: Optional[ProgressFn] = None,
) -> "ServiceResult":
    """Scan the CAPTURED bytes of a dump with key finders.

    ``view`` / ``offset`` / ``length`` select the window in the chosen view's
    coordinates (default: ``va`` for an ``.msl`` or ``.mdview``, ``raw`` for a flat
    file; ``vas`` is also offered for an ``.msl``). Each row carries ``addr`` +
    ``space`` + ``location``, ``length``, ``confidence``, finder ``metadata``,
    ``heap`` and ``region`` context, plus ``va`` and ``vas_offset``. ``coverage``,
    ``truncated`` and ``candidates`` (the ``regions`` of a ``candidates.json``,
    offsets into the flat reference stream) are always present. With ``case_dir`` the
    rows become the ``key_hits`` table (and, with ``annotate``, ``key_hit`` entries).
    """
    from memdiver.core.dump_source import open_dump

    names = tuple(finders)
    known = _validated(names, heap_policy, limit, offset, length)
    path = _dump_file(dump_path)
    with open_dump(path) as source:
        plan = _build_plan(source, path, view, offset, length,
                           _stride_alignment(names, params or {}))
        scan = _scan_plan(plan, known, names, dict(params or {}), heap_policy,
                          limit, progress)
        status = _heap_status(plan, heap_policy)
    hits = scan.hits[:limit]
    truncated = scan.stopped_early or len(scan.hits) > limit
    payload: Dict[str, Any] = {
        "dump_path": str(path), "format": source.format_name, "view": plan.view,
        "space": plan.location(0).space.value, "capture_id": plan.capture_id,
        "finders": list(names), "params": _jsonable(params or {}),
        "heap_policy": heap_policy,
        "heap": {"policy": heap_policy, "status": status, "masked_out": scan.masked_out},
        "rows": [h.row for h in hits], "row_count": len(hits), "limit": limit,
        "truncated": truncated,
        "complete": not (truncated or scan.short_reads),
        "incomplete_reason": _incomplete_reason(truncated, scan.short_reads),
        "coverage": _coverage(plan, scan, offset, length),
        "candidates": [h.candidate for h in hits],
    }
    if candidates_out:
        payload["candidates_path"] = _write_candidates(payload["candidates"], candidates_out)
    if case_dir:
        payload["case"] = _file_case(plan, payload["rows"], case_dir, truncated, annotate)
    return ServiceResult.ok(payload)


__all__ = ["DEFAULT_FINDERS", "DEFAULT_LIMIT", "HEAP_POLICIES",
           "keyfinders_list_result", "keyfinders_scan_result"]
