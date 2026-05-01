"""Inspect router — hex, entropy, strings, structure, xref, session."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_tool_session
from core.dump_source import ViewMode
from mcp_server import tools_inspect, tools_xref
from mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.inspect")

router = APIRouter()


@router.get("/hex")
def read_hex(
    dump_path: str,
    offset: int = 0,
    length: int = 256,
    view: ViewMode = "raw",
    session: ToolSession = Depends(get_tool_session),
):
    """Read raw bytes from a dump file as hex + ASCII.

    For MSL files, ``view`` selects the byte source:
    ``raw`` (default) → .msl container bytes; ``vas`` → flattened
    captured memory projection.
    """
    return tools_inspect.read_hex(session, dump_path, offset, length, view=view)


@router.get("/hex-raw")
def read_hex_raw(
    dump_path: str,
    offset: int = 0,
    length: int = 8192,
    view: ViewMode = "raw",
    session: ToolSession = Depends(get_tool_session),
):
    """Read raw bytes from a dump file as base64."""
    return tools_inspect._read_hex_raw(session, dump_path, offset, length, view=view)


@router.get("/resolve-va")
def resolve_va(
    dump_path: str,
    va: int,
    session: ToolSession = Depends(get_tool_session),
):
    """Translate a virtual address to file and VAS offsets (MSL only)."""
    return tools_inspect._resolve_va(session, dump_path, va)


@router.get("/entropy")
def get_entropy(
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    window: int = 32,
    step: int = 16,
    threshold: float = 7.5,
    session: ToolSession = Depends(get_tool_session),
):
    """Compute entropy profile for a dump file region."""
    return tools_inspect.get_entropy(
        session, dump_path, offset, length, window, step, threshold,
    )


@router.get("/strings")
def extract_strings(
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    min_length: int = 4,
    encoding: str = "ascii",
    max_results: int = 500,
    cursor: int = 0,
    chunk_size: int = 8 * 1024 * 1024,
    session: ToolSession = Depends(get_tool_session),
):
    """Extract printable strings from a dump file via chunked streaming.

    ``cursor`` resumes a previous paged scan (pass the ``next_cursor`` from the
    last response). ``chunk_size`` controls how many bytes are read per chunk;
    larger chunks reduce overhead but raise peak RSS.
    """
    return tools_inspect._extract_strings(
        session, dump_path, offset, length, min_length, encoding, max_results,
        cursor=cursor, chunk_size=chunk_size,
    )


@router.get("/structure")
def identify_structure(
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
    session: ToolSession = Depends(get_tool_session),
):
    """Identify a data structure at the given offset."""
    return tools_xref.identify_structure(session, dump_path, offset, protocol)


@router.get("/structure-apply")
def apply_structure(
    dump_path: str,
    offset: int = 0,
    structure_name: str = "",
    session: ToolSession = Depends(get_tool_session),
):
    """Apply a named structure definition at the given offset."""
    from pathlib import Path

    from core.dump_source import open_dump
    from core.structure_library import get_structure_library
    from core.structure_overlay import (
        compute_max_size,
        overlay_structure,
        serialize_overlay_result,
    )

    lib = get_structure_library()
    struct_def = lib.get(structure_name)
    if struct_def is None:
        raise HTTPException(status_code=404, detail=f"Structure '{structure_name}' not found")

    try:
        src_ctx = open_dump(Path(dump_path))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {dump_path}")

    with src_ctx as src:
        max_size = compute_max_size(struct_def)
        if offset + max_size > src.size:
            raise HTTPException(status_code=400, detail="Structure extends beyond file boundary")
        data = src.read_range(offset, max_size)

    overlays, total_size = overlay_structure(data, offset, struct_def)
    payload = serialize_overlay_result(struct_def, overlays, total_size)
    payload["offset"] = offset
    return {"structure": payload}


@router.get("/xref")
def get_cross_references(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """Resolve cross-references for an MSL file."""
    return tools_xref.get_cross_references(session, msl_path)


@router.get("/session-info")
def get_session_info(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """Extract session metadata from an MSL file."""
    return tools_inspect.get_session_info(session, msl_path)


@router.get("/blocks")
def list_blocks(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List all blocks in an MSL file grouped by type."""
    from pathlib import Path

    from api.services.reader_cache import cached_msl_reader
    from msl.block_tree import group_blocks
    from msl.block_tree import list_blocks as msl_list_blocks

    path = Path(msl_path)
    if path.suffix != ".msl":
        raise HTTPException(status_code=400, detail="Not a valid MSL file")

    try:
        with cached_msl_reader(path) as reader:
            blocks = msl_list_blocks(reader)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")

    groups = group_blocks(blocks)
    result = []
    for category, nodes in groups.items():
        result.append({
            "category": category,
            "blocks": [
                {
                    "label": n.type_name,
                    "block_type": n.type_code,
                    "offset": n.file_offset,
                    "size": n.payload_size,
                    "detail": n.block_uuid,
                }
                for n in nodes
            ],
        })
    return result


@router.get("/modules")
def list_modules(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List loaded modules from MSL metadata."""
    from pathlib import Path

    from api.services.reader_cache import cached_msl_reader

    path = Path(msl_path)
    if path.suffix != ".msl":
        raise HTTPException(status_code=400, detail="Not a valid MSL file")

    try:
        with cached_msl_reader(path) as reader:
            modules = reader.collect_modules()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")

    return [
        {
            "path": m.path,
            "base_addr": m.base_addr,
            "size": m.module_size,
            "version": m.version,
        }
        for m in modules
    ]


# -- MSL table-block endpoints (Phase MSL-Decoders-02) ------------------

def _handle_type_name(value: int) -> str:
    """Map a raw HANDLE_TABLE handle_type int to its spec Table 24 name."""
    from msl.enums import HandleType
    try:
        return HandleType(value).name.capitalize()
    except ValueError:
        return "Unknown"


from contextlib import contextmanager


@contextmanager
def _open_msl(msl_path: str):
    """Validate MSL suffix and open via cached reader (shared helper).

    Translates both missing-suffix and missing-file errors into HTTP
    responses. Since MslReader.open() runs inside the inner context
    manager's __enter__, we must wrap the whole yield — not just the
    cached_msl_reader() call.
    """
    from pathlib import Path

    from api.services.reader_cache import cached_msl_reader

    path = Path(msl_path)
    if path.suffix != ".msl":
        raise HTTPException(status_code=400, detail="Not a valid MSL file")
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")
    try:
        with cached_msl_reader(path) as reader:
            yield reader
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")


def _format_addr(family: int, raw: bytes) -> str:
    """Render a CONNECTION_TABLE address blob as a human string."""
    import ipaddress

    try:
        if family == 0x02:  # AF_INET
            return str(ipaddress.IPv4Address(bytes(raw[:4])))
        if family == 0x0A:  # AF_INET6
            return str(ipaddress.IPv6Address(bytes(raw[:16])))
    except (ValueError, ipaddress.AddressValueError):
        pass
    return raw[:16].hex()


@router.get("/module-index")
def list_module_index(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from MODULE_LIST_INDEX blocks (spec §5.3, type 0x0010)."""
    with _open_msl(msl_path) as reader:
        tables = reader.collect_module_list_index()
    result = []
    for table in tables:
        for e in table.entries:
            result.append({
                "module_uuid": str(e.module_uuid),
                "base_addr": e.base_addr,
                "size": e.module_size,
                "path": e.path,
            })
    return result


@router.get("/processes")
def list_processes(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from PROCESS_TABLE blocks (spec §6.3, type 0x0051)."""
    with _open_msl(msl_path) as reader:
        tables = reader.collect_processes()
    result = []
    for table in tables:
        for e in table.entries:
            result.append({
                "pid": e.pid,
                "ppid": e.ppid,
                "uid": e.uid,
                "is_target": e.is_target,
                "start_time_ns": e.start_time_ns,
                "rss": e.rss,
                "exe_name": e.exe_name,
                "cmd_line": e.cmd_line,
                "user": e.user,
            })
    return result


@router.get("/connections")
def list_connections(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from CONNECTION_TABLE blocks (spec §6.4, type 0x0052)."""
    with _open_msl(msl_path) as reader:
        tables = reader.collect_connections()
    result = []
    for table in tables:
        for e in table.entries:
            result.append({
                "pid": e.pid,
                "family": e.family,
                "protocol": e.protocol,
                "state": e.state,
                "local_addr": _format_addr(e.family, e.local_addr),
                "local_port": e.local_port,
                "remote_addr": _format_addr(e.family, e.remote_addr),
                "remote_port": e.remote_port,
            })
    return result


@router.get("/handles")
def list_handles(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from HANDLE_TABLE blocks (spec §6.5, type 0x0053)."""
    with _open_msl(msl_path) as reader:
        tables = reader.collect_handles()
    result = []
    for table in tables:
        for e in table.entries:
            result.append({
                "pid": e.pid,
                "fd": e.fd,
                "handle_type": e.handle_type,
                "handle_type_name": _handle_type_name(e.handle_type),
                "path": e.path,
            })
    return result


# -- Ext decoders (speculative layouts; spec §4.3 reserved types) --

_RESERVED_NOTE = (
    "Layout speculative. Spec §4.3 reserves this block type and prohibits "
    "producers from emitting it until future spec versions define the payload."
)


def _ext_to_dict(block):
    """Best-effort JSON shape for a speculative ext block or its fallback."""
    from msl.decoders_ext import (MslEnvironmentBlock, MslFileDescriptor,
                                  MslNetworkConnection, MslSecurityToken,
                                  MslSystemContext, MslThreadContext)
    from msl.types import MslGenericBlock

    if isinstance(block, MslGenericBlock):
        return {"decoded": False, "payload_hex": block.payload[:256].hex()}
    if isinstance(block, MslThreadContext):
        return {"decoded": True, "thread_id": block.thread_id,
                "register_data_hex": block.register_data[:256].hex()}
    if isinstance(block, MslFileDescriptor):
        return {"decoded": True, "fd": block.fd, "path": block.path}
    if isinstance(block, MslNetworkConnection):
        return {"decoded": True,
                "local_port": block.local_port,
                "remote_port": block.remote_port,
                "protocol": block.protocol,
                "addresses_hex": block.addresses[:64].hex()}
    if isinstance(block, MslEnvironmentBlock):
        return {"decoded": True, "entries": block.entries}
    if isinstance(block, MslSecurityToken):
        return {"decoded": True, "token_type": block.token_type,
                "token_data_hex": block.token_data[:256].hex()}
    if isinstance(block, MslSystemContext):
        return {"decoded": True, "hostname": block.hostname,
                "os_version": block.os_version, "uptime_ns": block.uptime_ns}
    return {"decoded": False}


@router.get("/thread-contexts")
def list_thread_contexts(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """THREAD_CONTEXT blocks (0x0011). Speculative layout — spec reserved."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_thread_contexts()
    return {
        "spec_reserved": True,
        "note": _RESERVED_NOTE,
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/file-descriptors")
def list_file_descriptors(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """FILE_DESCRIPTOR blocks (0x0012). Speculative layout — spec reserved."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_file_descriptors()
    return {
        "spec_reserved": True,
        "note": _RESERVED_NOTE,
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/network-connections")
def list_network_connections(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """NETWORK_CONNECTION blocks (0x0013). Speculative layout — spec reserved."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_network_connections()
    return {
        "spec_reserved": True,
        "note": _RESERVED_NOTE,
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/env-blocks")
def list_environment_blocks(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """ENVIRONMENT_BLOCK blocks (0x0014). Speculative layout — spec reserved."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_environment_blocks()
    return {
        "spec_reserved": True,
        "note": _RESERVED_NOTE,
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/security-tokens")
def list_security_tokens(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """SECURITY_TOKEN blocks (0x0015). Speculative layout — spec reserved."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_security_tokens()
    return {
        "spec_reserved": True,
        "note": _RESERVED_NOTE,
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/system-context")
def list_system_context(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """SYSTEM_CONTEXT blocks (0x0050). Spec §6.2 — currently incomplete
    (missing BootTime/TargetCount/TableBitmap/AcqUser/Domain/OSDetail/CaseRef)."""
    with _open_msl(msl_path) as reader:
        blocks = reader.collect_system_context()
    return {
        "incomplete": True,
        "note": ("Decoder extracts only hostname/os_version/uptime_ns; spec §6.2 "
                 "defines additional fields (BootTime, TargetCount, TableBitmap, "
                 "AcqUser, Domain, OSDetail, CaseRef)."),
        "entries": [_ext_to_dict(b) for b in blocks],
    }


@router.get("/format")
def detect_format_endpoint(
    dump_path: str,
    offset: int = 0,
    force_format: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Detect binary format and return navigation tree.

    When ``force_format`` is provided, the server skips magic-byte
    detection and uses the caller's choice (validated against the
    Kaitai registry's available formats).
    """
    from pathlib import Path

    from core.binary_formats.kaitai_registry import get_kaitai_registry
    from core.binary_formats.navigator import build_nav_tree
    from core.dump_source import open_dump
    from core.format_detect import detect_format_at_offset, suggest_formats

    with open_dump(Path(dump_path)) as src:
        # Read first 64KB of the raw container for format detection and
        # navigation.  For MSL sources this is the .msl container bytes,
        # not the flattened VAS projection — so the container's own
        # magic ("MEMSLICE") is recognised instead of whatever happens
        # to live at VAS offset 0 (commonly an ELF header).
        raw_size = src.size_for("raw") if hasattr(src, "size_for") else src.size
        length = min(65536, max(0, raw_size - offset))
        data = src.read_range(offset, length, view="raw")

    registry = get_kaitai_registry()
    available = registry.available_formats()

    detected = detect_format_at_offset(data, 0)
    suggested = suggest_formats(data)

    if force_format is not None:
        if force_format not in available:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown format: {force_format}",
            )
        fmt = force_format
        forced = True
    else:
        fmt = detected
        forced = False

    if fmt is None:
        return {
            "format": None,
            "detected_format": detected,
            "forced": forced,
            "suggested_formats": suggested,
            "available_formats": available,
            "nav_tree": None,
            "overlays": None,
        }

    tree = build_nav_tree(data, fmt)

    # Kaitai deep parse for field-level overlays
    overlays = None
    try:
        from core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter

        parsed = registry.parse(fmt, data)
        if parsed:
            adapter = KaitaiOverlayAdapter()
            field_overlays = adapter.walk_fields(parsed, base_offset=offset)
            overlays = {
                "structure_name": fmt,
                "base_offset": offset,
                "fields": [o.to_dict() for o in field_overlays],
            }
    except Exception as exc:
        logger.debug("Kaitai parse failed for %s: %s", fmt, exc)

    return {
        "format": fmt,
        "detected_format": detected,
        "forced": forced,
        "suggested_formats": suggested,
        "available_formats": available,
        "nav_tree": tree.to_dict() if tree else None,
        "overlays": overlays,
    }
