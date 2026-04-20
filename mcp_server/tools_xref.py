"""Pure tool functions for MemDiver — cross-references and structures.

get_cross_references, identify_structure.
"""

import logging
from pathlib import Path

from api.services.reader_cache import cached_dump_source, cached_msl_reader

from .session import ToolSession

logger = logging.getLogger("memdiver.mcp_server.tools_xref")


def get_cross_references(session: ToolSession, msl_path: str) -> dict:
    """Resolve cross-references for an MSL file."""
    path = Path(msl_path)

    from msl.xref_resolver import XrefResolver

    try:
        with cached_msl_reader(path) as reader:
            file_uuid = reader.file_header.dump_uuid
    except FileNotFoundError:
        return {"error": f"File not found: {msl_path}"}

    resolver = XrefResolver()
    resolver.index_directory(path.parent)
    entries = resolver.resolve()

    related = [e for e in entries if e.source_uuid == file_uuid]
    return {
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
    }


def identify_structure(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
) -> dict:
    """Try to identify a data structure at the given offset."""
    from core.structure_library import get_structure_library
    from core.structure_overlay import (
        best_match_structure,
        compute_max_size,
        serialize_overlay_result,
    )

    library = get_structure_library()
    candidates = library.list_by_protocol(protocol) if protocol else library.list_all()
    max_struct_size = max((compute_max_size(s) for s in candidates), default=0)
    if max_struct_size == 0:
        return {"match": None, "reason": "No structures available"}

    try:
        with cached_dump_source(Path(dump_path)) as source:
            data = source.read_range(0, offset + max_struct_size)
    except FileNotFoundError:
        return {"error": f"File not found: {dump_path}"}

    result = best_match_structure(data, offset, library, protocol)
    if result is None:
        return {"match": None, "reason": "No matching structure found"}

    struct_def, overlays, confidence = result
    if struct_def.auto_offsets:
        total_size = sum(o.length for o in overlays)
    else:
        total_size = struct_def.total_size
    payload = serialize_overlay_result(struct_def, overlays, total_size)
    payload["description"] = struct_def.description
    payload["confidence"] = confidence
    return {"match": payload}
