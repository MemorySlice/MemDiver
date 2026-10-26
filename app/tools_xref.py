"""Pure tool functions for MemDiver — cross-references and structures.

get_cross_references, identify_structure.
"""

import logging
from dataclasses import replace
from pathlib import Path
from typing import Optional

from memdiver.app.reader_cache import cached_dump_source, cached_msl_reader
from memdiver.core.dump_source import ViewMode
from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)
from memdiver.core.service_result import ServiceResult

from .session import ToolSession

logger = logging.getLogger("memdiver.app.tools_xref")


def get_cross_references(session: ToolSession, msl_path: str) -> dict:
    """Resolve cross-references for an MSL file.

    .. deprecated:: Prefer :func:`get_cross_references_result`, which returns a status-carrying ServiceResult; this shim renders the bare payload / legacy error dict for backward compatibility.

    Thin adapter over :func:`get_cross_references_result`; see it for the
    behavioral contract.
    """
    try:
        return get_cross_references_result(session, msl_path).payload
    except CapabilityError as e:
        return e.to_error_body()


def identify_structure(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
) -> dict:
    """Try to identify a data structure at the given offset.

    .. deprecated:: Prefer :func:`identify_structure_result`, which returns a status-carrying ServiceResult; this shim renders the bare payload / legacy error dict for backward compatibility.

    Thin adapter over :func:`identify_structure_result`; see it for the
    behavioral contract.
    """
    try:
        return identify_structure_result(session, dump_path, offset, protocol).payload
    except CapabilityError as e:
        return e.to_error_body()


# ---------------------------------------------------------------------------
# ServiceResult producers.
#
# Each producer builds the SAME success payload as its sibling shim above and
# RAISES ``CapabilityError`` subclasses for the hard-error cases the shims used
# to return as ``{"error": ...}`` dicts. The human "no-match" payloads
# (``{"match": None, "reason": ...}``) are legitimate results, not errors, and
# pass through as normal payloads. Neither operation takes key material, so the
# result carries a default (OK) status via :meth:`ServiceResult.ok`.
# ---------------------------------------------------------------------------


def get_cross_references_result(session: ToolSession, msl_path: str) -> ServiceResult:
    """ServiceResult producer for :func:`get_cross_references`."""
    path = Path(msl_path)

    from memdiver.msl.xref_resolver import XrefResolver

    try:
        with cached_msl_reader(path) as reader:
            file_uuid = reader.file_header.dump_uuid
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {msl_path}")

    resolver = XrefResolver()
    resolver.index_directory(path.parent)
    entries = resolver.resolve()

    related = [e for e in entries if e.source_uuid == file_uuid]
    return ServiceResult.ok({
        "dump_uuid": str(file_uuid),
        "cross_references": [
            {
                "target_uuid": str(e.target_uuid),
                "target_path": str(e.target_path) if e.target_path else None,
                "relationship": e.relationship,
                "related_pid": e.related_pid,
            }
            for e in related
        ],
        "total_indexed": len(entries),
    })


def _view_kwargs(source, view: Optional[ViewMode]) -> dict:
    """``{"view": view}`` for an explicit view (refused if the source lacks
    it), ``{}`` for ``None`` = the source's own default byte view (the
    historical behaviour: VAS on .msl/gcore, the file itself on a flat dump)."""
    if view is None:
        return {}
    from memdiver.app.tools_inspect import _require_supported_view

    _require_supported_view(source, view)
    return {"view": view}


def identify_structure_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
    view: Optional[ViewMode] = None,
) -> ServiceResult:
    """ServiceResult producer for :func:`identify_structure`.

    ``view`` names the byte view ``offset`` addresses (a hex-viewer cursor is
    in the viewer's current view); ``None`` keeps the source default.
    """
    from memdiver.core.structure_library import get_structure_library
    from memdiver.core.structure_overlay import (
        best_match_structure,
        compute_max_size,
        serialize_overlay_result,
    )

    library = get_structure_library()
    candidates = library.list_by_protocol(protocol) if protocol else library.list_all()
    max_struct_size = max((compute_max_size(s) for s in candidates), default=0)
    if max_struct_size == 0:
        return ServiceResult.ok({"match": None, "reason": "No structures available"})

    try:
        with cached_dump_source(Path(dump_path)) as source:
            view_kwargs = _view_kwargs(source, view)
            file_size = source.size_for(**view_kwargs)
            # Reject an out-of-range offset with a clean error instead of
            # overlaying structures onto an empty/short read.
            if offset < 0 or offset >= file_size:
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={"offset": offset, "file_size": file_size},
                )
            # Only the window the largest candidate can span is needed. (This
            # used to read [0, offset + max) — the whole prefix — which on the
            # sparse multi-GB "va" view is unbounded.)
            window = source.read_range(offset, max_struct_size, **view_kwargs)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")

    result = best_match_structure(window, 0, library, protocol)
    if result is None:
        return ServiceResult.ok({"match": None, "reason": "No matching structure found"})

    struct_def, window_overlays, confidence = result
    # Matched at window position 0; report absolute offsets as before.
    overlays = [replace(o, offset=o.offset + offset) for o in window_overlays]
    if struct_def.auto_offsets:
        total_size = sum(o.length for o in overlays)
    else:
        total_size = struct_def.total_size
    payload = serialize_overlay_result(struct_def, overlays, total_size)
    payload["description"] = struct_def.description
    payload["confidence"] = confidence
    return ServiceResult.ok({"match": payload})


def apply_structure_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    structure_name: str = "",
    view: Optional[ViewMode] = None,
) -> ServiceResult:
    """ServiceResult producer for applying a named structure at an offset.

    ``view``: see :func:`identify_structure_result` (``None`` = source default).

    Overlays a caller-named structure definition onto the bytes at ``offset``
    and returns the serialized overlay wrapped as ``{"structure": {...}}`` (the
    ``offset`` is echoed inside the structure dict). Hard errors are RAISED as
    ``CapabilityError`` subclasses: an unknown ``structure_name`` as a
    NOT_FOUND error, a missing dump as :class:`FileNotFoundServiceError`, and a
    structure that runs past the end of the file as an
    :class:`OffsetOutOfRangeError`. Decryption key material is honoured through
    the active ``key_material_scope`` (the cached source picks it up).
    """
    from memdiver.core.structure_library import get_structure_library
    from memdiver.core.structure_overlay import (
        compute_max_size,
        overlay_structure,
        serialize_overlay_result,
    )

    library = get_structure_library()
    struct_def = library.get(structure_name)
    if struct_def is None:
        raise CapabilityError(
            f"Structure '{structure_name}' not found",
            category=ErrorCategory.NOT_FOUND,
        )

    try:
        with cached_dump_source(Path(dump_path)) as source:
            max_size = compute_max_size(struct_def)
            # Mirror identify_structure_result: reject a negative offset (a
            # negative read start would otherwise slice from the tail) and use
            # the view-aware size_for().
            view_kwargs = _view_kwargs(source, view)
            file_size = source.size_for(**view_kwargs)
            if offset < 0 or offset + max_size > file_size:
                raise OffsetOutOfRangeError(
                    "Structure extends beyond file boundary",
                    category=ErrorCategory.PRECONDITION,
                )
            data = source.read_range(offset, max_size, **view_kwargs)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")

    overlays, total_size = overlay_structure(data, offset, struct_def)
    payload = serialize_overlay_result(struct_def, overlays, total_size)
    payload["offset"] = offset
    return ServiceResult.ok({"structure": payload})


# ---------------------------------------------------------------------------
# Who points here (xref.pointers_to)
# ---------------------------------------------------------------------------


def _holder_region(runs, holder_va: int) -> Optional[dict]:
    """The captured run ``[va, va+length)`` that contains ``holder_va``."""
    import bisect

    starts = [r[0] for r in runs]
    i = bisect.bisect_right(starts, holder_va) - 1
    if i >= 0 and holder_va < runs[i][0] + runs[i][1]:
        return {"va": runs[i][0], "va_hex": hex(runs[i][0]), "length": runs[i][1]}
    return None


def _pointer_ref_rows(scan, runs) -> list:
    return [
        {"holder_va": r.holder_va, "holder_va_hex": hex(r.holder_va),
         "value": r.value, "value_hex": hex(r.value),
         "target_delta": r.target_delta,
         "holder_region": _holder_region(runs, r.holder_va)}
        for r in scan.refs
    ]


def xref_pointers_result(
    session: ToolSession,
    *,
    dump_path: str,
    target_va: int,
    span_before: int = 0,
    span_after: int = 1,
    word_size: int = 8,
    alignment: int = 8,
    max_refs: int = 1000,
    exclude_target: bool = False,
) -> ServiceResult:
    """Which captured words point into ``[target_va - before, target_va + after)``.

    The reverse of following a pointer. Needs a VA-bearing dump (``.msl`` /
    core): a raw dump is a PRECONDITION error ``xref.no_va_view``. Memory that
    was never captured is reported as ``uncaptured_gap_bytes`` (NOT scanned),
    never as "no pointers there"; ``truncated`` means ``max_refs`` stopped the
    scan, so ``refs`` is a prefix.
    """
    from contextlib import ExitStack

    from memdiver.app.tools_consensus import _open_one
    from memdiver.engine.xref_pointers import _captured_runs, find_pointers_to

    lo, hi = int(target_va) - int(span_before), int(target_va) + int(span_after)
    with ExitStack() as stack:
        source = _open_one(stack, str(dump_path), None)
        has_va = (getattr(source, "format_name", "") != "raw"
                  and hasattr(source, "va_span_start")
                  and source.va_span_start() is not None)
        if not has_va:
            raise CapabilityError(
                f"{dump_path!r} has no virtual-address view; pointer scan needs "
                f"a VA-bearing dump (.msl / core)",
                category=ErrorCategory.PRECONDITION, code="xref.no_va_view")
        try:
            scan = find_pointers_to(
                source, lo, hi, word_size=int(word_size),
                alignment=int(alignment), max_refs=int(max_refs),
                exclude=(lo, hi) if exclude_target else None)
        except ValueError as exc:
            raise CapabilityError(str(exc)) from exc
        runs = _captured_runs(source)
    payload = {
        "target": {"va": int(target_va), "va_hex": hex(int(target_va)),
                   "lo": lo, "lo_hex": hex(lo), "hi": hi, "hi_hex": hex(hi)},
        "refs": _pointer_ref_rows(scan, runs),
        "coverage": {"scanned_bytes": scan.scanned_bytes,
                     "scanned_runs": scan.scanned_runs,
                     "uncaptured_gap_bytes": scan.skipped_bytes,
                     "truncated": scan.truncated},
        "params": {"span_before": int(span_before), "span_after": int(span_after),
                   "word_size": int(word_size), "alignment": int(alignment),
                   "max_refs": int(max_refs), "exclude_target": bool(exclude_target)},
    }
    return ServiceResult(payload=payload)
