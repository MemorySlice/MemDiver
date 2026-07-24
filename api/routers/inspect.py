"""Inspect router — hex, entropy, strings, structure, xref, session."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from memdiver.api.dependencies import get_tool_session
from memdiver.api.services.key_material import decode_key_material
from memdiver.api.services.reader_cache import key_material_scope
from memdiver.core.dump_source import ViewMode
from memdiver.core.service_errors import CapabilityError
from memdiver.mcp_server import tools_inspect, tools_xref
from memdiver.mcp_server.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.inspect")

router = APIRouter()


def present_inspect_http(result):
    """API surface: emit only the payload; the key/tag diagnostic is dropped
    here (the Web UI reads it from the dedicated /tag-status endpoints), so a
    locked dump reads back empty exactly as before."""
    return result.payload


def _http_inspect(produce):
    """Run a ServiceResult producer and present it on the HTTP surface.

    Preserves today's contract: success payloads are emitted without the status
    block, and the hard-error raises are turned back into the legacy
    200-with-error-dict bodies. A later phase introduces a global handler that
    maps these to proper HTTP status codes.
    """
    try:
        return present_inspect_http(produce())
    except CapabilityError as e:
        return e.to_error_body()


@router.get("/hex")
def read_hex(
    dump_path: str,
    offset: int = Query(0, ge=0),
    length: int = 256,
    view: ViewMode = "raw",
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Read raw bytes from a dump file as hex + ASCII.

    For MSL files, ``view`` selects the byte source:
    ``raw`` (default) → .msl container bytes; ``vas`` → flattened
    captured memory projection. Optional ``passphrase`` / ``key_hex`` /
    ``kem_key_hex`` unlock an encrypted ``.msl`` container (spec §10).
    """
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        # The API keeps the "encrypted-and-locked reads back empty" UI contract
        # (the diagnostic lives on the dedicated /tag-status endpoints): the
        # status-carrying producer always builds the payload, and
        # present_inspect_http drops the status block on the way out.
        return _http_inspect(lambda: tools_inspect.read_hex_result(
            session, dump_path, offset, length, view=view))


@router.get("/hex-raw")
def read_hex_raw(
    dump_path: str,
    offset: int = 0,
    length: int = 8192,
    view: ViewMode = "raw",
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Read raw bytes from a dump file as base64."""
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.read_hex_raw_result(
            session, dump_path, offset, length, view=view))


@router.get("/resolve-va")
def resolve_va(
    dump_path: str,
    va: int,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Translate a virtual address to file and VAS offsets (MSL only)."""
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.resolve_va_result(
            session, dump_path, va))


@router.get("/entropy")
def get_entropy(
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    window: int = 32,
    step: int = 16,
    threshold: float = 7.5,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Compute entropy profile for a dump file region."""
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.entropy_result(
            session, dump_path, offset, length, window, step, threshold,
        ))


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
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Extract printable strings from a dump file via chunked streaming.

    ``cursor`` resumes a previous paged scan (pass the ``next_cursor`` from the
    last response). ``chunk_size`` controls how many bytes are read per chunk;
    larger chunks reduce overhead but raise peak RSS.
    """
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.strings_result(
            session, dump_path, offset, length, min_length, encoding, max_results,
            cursor=cursor, chunk_size=chunk_size,
        ))


@router.get("/byte-search")
def search_bytes(
    dump_path: str,
    pattern_hex: str,
    view: ViewMode = "raw",
    max_results: int = 500,
    cursor: int = 0,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Search a dump for every occurrence of a hex byte pattern.

    ``pattern_hex`` accepts an optional leading ``0x`` and surrounding
    whitespace. ``cursor`` resumes a previous paged scan (pass the
    ``next_cursor`` from the last response). For MSL files, ``view`` selects
    the byte source: ``raw`` (default) → .msl container bytes; ``vas`` →
    flattened captured memory projection.
    """
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.search_bytes_result(
            session, dump_path, pattern_hex, view=view,
            max_results=max_results, cursor=cursor,
        ))


@router.get("/structure")
def identify_structure(
    dump_path: str,
    offset: int = 0,
    protocol: str = "",
    session: ToolSession = Depends(get_tool_session),
):
    """Identify a data structure at the given offset."""
    return _http_inspect(lambda: tools_xref.identify_structure_result(
        session, dump_path, offset, protocol))


@router.get("/structure-apply")
def apply_structure(
    dump_path: str,
    offset: int = 0,
    structure_name: str = "",
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Apply a named structure definition at the given offset.

    Routes through the shared ``apply_structure_result`` producer (single
    source of truth); the producer's transport-agnostic ``CapabilityError`` is
    mapped back onto the historical HTTP status codes (unknown structure /
    missing file → 404, structure past EOF → 400) so the wire contract is
    unchanged.
    """
    try:
        with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
            result = tools_xref.apply_structure_result(
                session, dump_path, offset, structure_name)
    except CapabilityError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return result.payload


@router.get("/xref")
def get_cross_references(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """Resolve cross-references for an MSL file."""
    return _http_inspect(lambda: tools_xref.get_cross_references_result(session, msl_path))


@router.get("/session-info")
def get_session_info(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Extract session metadata from an MSL file.

    Optional ``passphrase`` / ``key_hex`` / ``kem_key_hex`` unlock an
    encrypted container (spec §10); without them an encrypted dump reads
    back empty (no captured regions).
    """
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.session_info_result(session, msl_path))


@router.get("/page-states")
def get_page_states(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Surface the MSL three-state page model (CAPTURED/FAILED/UNMAPPED)."""
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return _http_inspect(lambda: tools_inspect.page_states_result(session, msl_path))


@router.get("/blocks")
def list_blocks(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List all blocks in an MSL file grouped by type.

    Routes through the shared ``blocks_result`` producer (single source of
    truth) and returns the bare grouped array the frontend consumes; the
    suffix/existence guards keep the historical 400/404 error contract.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.blocks_result(session, msl_path)
    return result.payload["blocks"]


@router.get("/modules")
def list_modules(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List loaded modules from MSL metadata.

    Routes through the shared ``modules_result`` producer and returns the bare
    module array the frontend consumes.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.modules_result(session, msl_path)
    return result.payload["modules"]


# -- MSL table-block endpoints (Phase MSL-Decoders-02) ------------------
#
# The handle-type-name mapping and the CONNECTION_TABLE address renderer that
# used to live here have moved into the shared ``tools_inspect`` producers
# (``handles_result`` / ``connections_result``) — the single source of truth
# these endpoints now route through.

from contextlib import contextmanager


def _validate_msl_path(msl_path: str):
    """Resolve an MSL path, raising HTTP 400/404 for bad suffix or missing file."""
    from pathlib import Path

    path = Path(msl_path)
    if path.suffix != ".msl":
        raise HTTPException(status_code=400, detail="Not a valid MSL file")
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")
    return path


@contextmanager
def _open_msl(msl_path: str):
    """Validate MSL suffix and open via cached reader (shared helper).

    Translates both missing-suffix and missing-file errors into HTTP
    responses. Since MslReader.open() runs inside the inner context
    manager's __enter__, we must wrap the whole yield — not just the
    cached_msl_reader() call.
    """
    from memdiver.api.services.reader_cache import cached_msl_reader

    path = _validate_msl_path(msl_path)
    try:
        with cached_msl_reader(path) as reader:
            yield reader
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {msl_path}")


@router.get("/tag-status")
def get_tag_status(
    msl_path: str,
    session: ToolSession = Depends(get_tool_session),
):
    """Report the AEAD tag-verification status of an MSL file (spec §10).

    Returns one of ``not_encrypted`` / ``valid`` / ``corrupted`` /
    ``missing_key``. This read-only path opens the file through the shared
    path-keyed cache without key material, so encrypted files report
    ``missing_key``; distinguishing ``valid`` from ``corrupted`` for an
    encrypted file requires the keyed POST variant.
    """
    with _open_msl(msl_path) as reader:
        return {"tag_status": reader.tag_status.value}


class TagStatusUnlockRequest(BaseModel):
    """Key material for a keyed AEAD tag-status probe. All secrets optional."""
    msl_path: str
    passphrase: str | None = None
    key_hex: str | None = None
    kem_key_hex: str | None = None


@router.post("/tag-status")
def probe_tag_status_with_key(
    body: TagStatusUnlockRequest,
    session: ToolSession = Depends(get_tool_session),
):
    """Probe AEAD tag status with caller-supplied key material (spec §10).

    Opens an UNCACHED reader with the supplied key/passphrase/KEM private
    key, reads the verification outcome, and closes immediately. Key
    material is never cached or logged. A wrong key surfaces as
    ``corrupted`` rather than an error.
    """
    from memdiver.msl.enums import TagStatus
    from memdiver.msl.reader import MslReader
    from memdiver.msl.types import MslAuthError, MslCryptoError

    path = _validate_msl_path(body.msl_path)

    try:
        key = bytes.fromhex(body.key_hex) if body.key_hex else None
        kem_private = bytes.fromhex(body.kem_key_hex) if body.kem_key_hex else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key material encoding")
    passphrase = body.passphrase.encode("utf-8") if body.passphrase else None

    try:
        with MslReader(path, key=key, passphrase=passphrase,
                       kem_private_key=kem_private) as reader:
            return {"tag_status": reader.tag_status.value}
    except (MslAuthError, MslCryptoError):
        return {"tag_status": TagStatus.CORRUPTED.value}


@router.get("/module-index")
def list_module_index(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from MODULE_LIST_INDEX blocks (spec §5.3, type 0x0010).

    Routes through the shared ``module_index_result`` producer and returns the
    bare entry array the frontend consumes.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.module_index_result(session, msl_path)
    return result.payload["module_index"]


@router.get("/processes")
def list_processes(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from PROCESS_TABLE blocks (spec §6.3, type 0x0051).

    Routes through the shared ``processes_result`` producer and returns the
    bare process array the frontend consumes.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.processes_result(session, msl_path)
    return result.payload["processes"]


@router.get("/connections")
def list_connections(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from CONNECTION_TABLE blocks (spec §6.4, type 0x0052).

    Routes through the shared ``connections_result`` producer and returns the
    bare connection array the frontend consumes.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.connections_result(session, msl_path)
    return result.payload["connections"]


@router.get("/handles")
def list_handles(
    msl_path: str,
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """List entries from HANDLE_TABLE blocks (spec §6.5, type 0x0053).

    Routes through the shared ``handles_result`` producer (which owns the
    handle-type-name mapping) and returns the bare handle array the frontend
    consumes.
    """
    _validate_msl_path(msl_path)
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        result = tools_inspect.handles_result(session, msl_path)
    return result.payload["handles"]


# -- Ext decoders (speculative layouts; spec §4.3 reserved types) --

_RESERVED_NOTE = (
    "Layout speculative. Spec §4.3 reserves this block type and prohibits "
    "producers from emitting it until future spec versions define the payload."
)


def _ext_to_dict(block):
    """Best-effort JSON shape for a speculative ext block or its fallback."""
    from memdiver.msl.decoders_ext import (MslEnvironmentBlock, MslFileDescriptor,
                                  MslNetworkConnection, MslSecurityToken,
                                  MslSystemContext, MslThreadContext)
    from memdiver.msl.types import MslGenericBlock

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
    passphrase: str | None = None,
    key_hex: str | None = None,
    kem_key_hex: str | None = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Detect binary format and return navigation tree.

    When ``force_format`` is provided, the server skips magic-byte
    detection and uses the caller's choice (validated against the
    Kaitai registry's available formats).
    """
    from pathlib import Path

    from memdiver.core.binary_formats.kaitai_registry import get_kaitai_registry
    from memdiver.core.binary_formats.navigator import build_nav_tree
    from memdiver.core.dump_source import open_dump
    from memdiver.core.service_errors import OffsetOutOfRangeError

    km = decode_key_material(passphrase, key_hex, kem_key_hex)

    # Magic-byte detection is delegated to the shared ``detect_format_result``
    # producer (single source of truth). Its raw-container view is keyless by
    # design, so no key scope is required. A pathological offset past the raw
    # container degrades to "no detection", matching the old empty-read path.
    try:
        detection = tools_inspect.detect_format_result(session, dump_path, offset)
        detected = detection.payload["detected_format"]
        suggested = detection.payload["suggested_formats"]
    except OffsetOutOfRangeError:
        detected, suggested = None, []

    with open_dump(Path(dump_path), **(km or {})) as src:
        # Read first 64KB of the raw container for the navigation tree and
        # field overlays. For MSL sources this is the .msl container bytes,
        # not the flattened VAS projection — so the container's own magic
        # ("MEMSLICE") is recognised instead of whatever happens to live at
        # VAS offset 0 (commonly an ELF header). Detection above ran against
        # the same raw window.
        raw_size = src.size_for("raw") if hasattr(src, "size_for") else src.size
        length = min(65536, max(0, raw_size - offset))
        data = src.read_range(offset, length, view="raw")

    registry = get_kaitai_registry()
    available = registry.available_formats()

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
        from memdiver.core.binary_formats.kaitai_adapter import KaitaiOverlayAdapter

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
