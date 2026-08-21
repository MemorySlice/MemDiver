"""Pure tool functions for MemDiver — cross-references and structures.

get_cross_references, identify_structure.
"""

import logging
from pathlib import Path

from memdiver.app.reader_cache import cached_dump_source, cached_msl_reader
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


def identify_structure_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
) -> ServiceResult:
    """ServiceResult producer for :func:`identify_structure`."""
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
            file_size = source.size_for()
            # Reject an out-of-range offset with a clean error instead of
            # overlaying structures onto an empty/short read.
            if offset < 0 or offset >= file_size:
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={"offset": offset, "file_size": file_size},
                )
            data = source.read_range(0, offset + max_struct_size)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")

    result = best_match_structure(data, offset, library, protocol)
    if result is None:
        return ServiceResult.ok({"match": None, "reason": "No matching structure found"})

    struct_def, overlays, confidence = result
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
) -> ServiceResult:
    """ServiceResult producer for applying a named structure at an offset.

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
            file_size = source.size_for()
            if offset < 0 or offset + max_size > file_size:
                raise OffsetOutOfRangeError(
                    "Structure extends beyond file boundary",
                    category=ErrorCategory.PRECONDITION,
                )
            data = source.read_range(offset, max_size)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")

    overlays, total_size = overlay_structure(data, offset, struct_def)
    payload = serialize_overlay_result(struct_def, overlays, total_size)
    payload["offset"] = offset
    return ServiceResult.ok({"structure": payload})
