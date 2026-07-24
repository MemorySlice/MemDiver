"""Pure tool functions for MemDiver — low-level dump inspection.

read_hex, get_entropy, extract_strings, get_session_info.
"""

import logging
from pathlib import Path
from typing import List, Optional

from memdiver.core.dump_source import ViewMode
from memdiver.core.entropy import compute_entropy_profile, find_high_entropy_regions, shannon_entropy
from memdiver.core.service_errors import (
    CapabilityError,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.core.strings import extract_strings

from .key_material import key_material_kwargs, open_dump_source, open_msl_reader
from .session import ToolSession

logger = logging.getLogger("memdiver.app.tools_inspect")

MAX_HEX_LENGTH = 4096
MAX_ENTROPY_SAMPLES = 200
MAX_STRING_RESULTS = 500
# Bytes of read-back overlap between consecutive chunks, so strings that
# straddle a chunk boundary are still recovered by the next scan. The first
# TAIL_OVERLAP bytes of every non-initial chunk have already been scanned by
# the previous chunk, so matches landing inside that prefix are discarded as
# duplicates. 256 bytes comfortably exceeds any realistic printable run that
# an operator would reasonably want split across chunks.
TAIL_OVERLAP = 256


def _tag_status_error(reader_or_source) -> Optional[dict]:
    """Structured error when an encrypted container could not be decrypted.

    An encrypted ``.msl`` opened with a missing or wrong key otherwise reads
    back as a silently-empty result (0 regions, exit 0), which an operator
    cannot tell apart from a genuinely empty capture. When the reader/source
    reports a non-recoverable ``tag_status`` we surface it instead. Returns
    ``None`` for ``NOT_ENCRYPTED`` / ``VALID`` so real empty captures and
    successful decrypts pass through untouched.
    """
    from memdiver.core.service_result import KeyStatus

    key = KeyStatus.from_source(reader_or_source)
    if not key.decrypted:
        return key.locked_error_dict()
    return None


def read_hex(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 256,
    view: ViewMode = "raw",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Read raw bytes from a dump file and return hex + ASCII representation.

    .. deprecated:: Prefer :func:`read_hex_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`read_hex_result`; see it for the behavioral contract.
    """
    # NOTE: For report_key_status=False + a locked vas view + nonzero offset,
    # this returns the empty payload rather than the pre-collapse legacy's
    # spurious "offset out of range" dict (a locked dump has size_for("vas")==0).
    # Unreachable in production (the API routes through read_hex_result) and
    # consistent with the accepted "locked reads back empty" semantics.
    try:
        result = read_hex_result(
            session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def _read_hex_raw(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 8192,
    view: ViewMode = "raw",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Read raw bytes from a dump file, returned as base64.

    .. deprecated:: Prefer :func:`read_hex_raw_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`read_hex_raw_result`; see it for the behavioral contract.
    """
    # NOTE: For report_key_status=False + a locked vas view + nonzero offset,
    # this returns the empty payload rather than the pre-collapse legacy's
    # spurious "offset out of range" dict (a locked dump has size_for("vas")==0).
    # Unreachable in production (the API routes through read_hex_raw_result) and
    # consistent with the accepted "locked reads back empty" semantics.
    try:
        result = read_hex_raw_result(
            session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def _resolve_va(
    session: ToolSession,
    dump_path: str,
    va: int,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Translate a virtual address to file and VAS offsets for an MSL dump.

    .. deprecated:: Prefer :func:`resolve_va_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`resolve_va_result`; see it for the behavioral contract.
    """
    try:
        result = resolve_va_result(
            session, dump_path, va, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_entropy(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    window: int = 32,
    step: int = 16,
    threshold: float = 7.5,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> dict:
    """Compute entropy profile for a dump file region.

    .. deprecated:: Prefer :func:`entropy_result`, which always carries key/tag status in a ServiceResult; this shim returns the bare payload for backward compatibility.

    Thin adapter over :func:`entropy_result`; see it for the behavioral contract.
    """
    try:
        result = entropy_result(
            session, dump_path, offset, length, window, step, threshold,
            key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    return result.payload


def _extract_strings(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    min_length: int = 4,
    encoding: str = "ascii",
    max_results: int = 500,
    cursor: int = 0,
    chunk_size: int = 8 * 1024 * 1024,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> dict:
    """Extract printable strings from a dump file via chunked streaming.

    Backward-compatible with the legacy signature: ``offset`` / ``length`` still
    define the inclusive scan window and the response keeps its historical
    ``strings`` / ``total_count`` / ``truncated`` fields. Two new knobs drive
    chunked streaming so large dumps no longer slurp the whole buffer:

    - ``cursor``: absolute byte position to resume from (>= ``offset``). When
      a previous call returned ``next_cursor`` the client passes it straight
      back to fetch the next page.
    - ``chunk_size``: streamed read size in bytes (default 8 MiB). Each chunk
      is read with a ``TAIL_OVERLAP``-byte read-back overlap so strings that
      straddle a boundary are still recovered.

    The response is a strict superset of the old shape; ``next_cursor`` is
    ``None`` once the window is fully scanned and ``window_end`` exposes the
    resolved end-of-window for UI paging math.

    .. deprecated:: Prefer :func:`strings_result`, which always carries key/tag status in a ServiceResult; this shim returns the bare payload for backward compatibility.

    Thin adapter over :func:`strings_result`; see it for the behavioral contract.
    """
    try:
        result = strings_result(
            session, dump_path, offset, length, min_length, encoding,
            max_results, cursor, chunk_size, key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    return result.payload


def _scan_window_for_strings(
    source,
    window_start: int,
    window_end: int,
    min_length: int,
    encoding: str,
    max_results: int,
    chunk_size: int,
) -> tuple[list[dict], Optional[int], bool]:
    """Stream the window in overlapping chunks; return (results, cursor, trunc)."""
    results: List[dict] = []
    pos = window_start
    next_cursor: Optional[int] = None
    truncated = False

    while pos < window_end:
        read_len = min(chunk_size + TAIL_OVERLAP, window_end - pos)
        buf = source.read_range(pos, read_len)
        if not buf:
            break

        is_first_chunk = (pos == window_start)
        matches = extract_strings(buf, min_length=min_length, encoding=encoding)
        stopped_early, next_cursor = _collect_chunk_matches(
            matches, pos, is_first_chunk, results, max_results,
        )
        if stopped_early:
            truncated = True
            break

        pos += chunk_size

    return results, next_cursor, truncated


def _collect_chunk_matches(
    matches,
    pos: int,
    is_first_chunk: bool,
    results: List[dict],
    max_results: int,
) -> tuple[bool, Optional[int]]:
    """Append dedup'd matches; signal early-stop + next_cursor when full."""
    for m in matches:
        if not is_first_chunk and m.offset < TAIL_OVERLAP:
            continue  # already reported by the previous chunk's tail overlap
        absolute_offset = pos + m.offset
        results.append({
            "offset": absolute_offset,
            "value": m.value,
            "encoding": m.encoding,
            "length": m.length,
        })
        if len(results) >= max_results:
            return True, absolute_offset + m.length
    return False, None


def search_bytes(
    session: ToolSession,
    dump_path: str,
    pattern_hex: str,
    view: ViewMode = "raw",
    max_results: int = 500,
    cursor: int = 0,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Search a dump for every occurrence of a hex byte pattern.

    .. deprecated:: Prefer :func:`search_bytes_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`search_bytes_result`; see it for the behavioral contract.
    """
    try:
        result = search_bytes_result(
            session, dump_path, pattern_hex, view, max_results, cursor,
            key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_session_info(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Extract session metadata from an MSL file.

    .. deprecated:: Prefer :func:`session_info_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`session_info_result`; see it for the behavioral contract.
    """
    try:
        result = session_info_result(
            session, msl_path, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_page_states(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """Surface the MSL three-state page model (CAPTURED/FAILED/UNMAPPED).

    .. deprecated:: Prefer :func:`page_states_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`page_states_result`; see it for the behavioral contract.
    """
    try:
        result = page_states_result(
            session, msl_path, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_processes(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """List entries from PROCESS_TABLE blocks (spec §6.3, type 0x0051).

    .. deprecated:: Prefer :func:`processes_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`processes_result`; see it for the behavioral contract.
    """
    try:
        result = processes_result(
            session, msl_path, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_modules(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """List loaded modules from MSL metadata (Module Entry, type 0x0002).

    .. deprecated:: Prefer :func:`modules_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`modules_result`; see it for the behavioral contract.
    """
    try:
        result = modules_result(
            session, msl_path, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def get_handles(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    report_key_status: bool = True,
) -> dict:
    """List entries from HANDLE_TABLE blocks (spec §6.5, type 0x0053).

    .. deprecated:: Prefer :func:`handles_result`, which always carries key/tag status in a ServiceResult; the ``report_key_status`` flag is retained only for backward compatibility.

    Thin adapter over :func:`handles_result`; see it for the behavioral contract.
    """
    try:
        result = handles_result(
            session, msl_path, key_file, passphrase, kem_key_file
        )
    except CapabilityError as e:
        return e.to_error_body()
    if report_key_status and not result.status.key.decrypted:
        return result.status.key.locked_error_dict()
    return result.payload


def detect_format(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> dict:
    """Detect the binary format at ``offset`` in a dump's raw container.

    Mirrors the API's ``GET /api/inspect/format`` magic-byte detection:
    reads up to 64 KiB of the raw container (for ``.msl`` this is the
    ``MEMSLICE`` container, not the flattened VAS projection) and returns
    the detected format plus ranked format suggestions. Encrypted ``.msl``
    inputs are decrypted when key material is supplied.

    .. deprecated:: Prefer :func:`detect_format_result`, which always carries key/tag status in a ServiceResult; this shim returns the bare payload for backward compatibility.

    Thin adapter over :func:`detect_format_result`; see it for the behavioral contract.
    """
    try:
        result = detect_format_result(
            session, dump_path, offset, key_file, passphrase, kem_key_file,
        )
    except CapabilityError as e:
        return e.to_error_body()
    return result.payload


def _format_hex_lines(data: bytes, base_offset: int = 0) -> List[str]:
    """Format bytes as traditional hex dump lines (16 bytes per line)."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        addr = f"{base_offset + i:08x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr}  {hex_part:<48s}  |{ascii_part}|")
    return lines


# ---------------------------------------------------------------------------
# ServiceResult producers (step 2a — purely additive)
#
# Each ``<publicname>_result`` mirrors its sibling above MINUS the
# ``report_key_status`` guard: the read/collect is ALWAYS performed, the SAME
# success payload dict is built, and the encrypted/locked state is carried in
# the ``status`` block rather than replacing the payload with an error dict.
# Hard errors (missing file, wrong format, out-of-range offset, invalid
# pattern) are RAISED as transport-agnostic ``CapabilityError`` subclasses.
# ---------------------------------------------------------------------------


def _view_is_keyed(view=None) -> bool:
    """Whether reads in this view require decryption.

    Single source of truth for the legacy ``view == "vas"`` gate: ``view=None``
    (the metadata producers) and ``view == "vas"`` are keyed; the raw container
    view is keyless by design.
    """
    return view is None or view == "vas"


def _view_locked(src, view=None) -> bool:
    """True when a keyed view cannot be decrypted with the supplied key material.

    Lets the byte-reading producers surface the lock BEFORE their offset-bounds
    check, matching the legacy ordering (``read_hex`` ran the tag-status guard
    first, so an encrypted-without-key dump — whose ``size_for("vas")`` is 0 —
    reported the key hint rather than a misleading "offset out of range").
    """
    if not _view_is_keyed(view):
        return False
    from memdiver.core.service_result import KeyStatus

    return not KeyStatus.from_source(src).decrypted


def _finalize_inspect(payload: dict, src, *, view=None) -> "ServiceResult":
    """Wrap ``payload`` with a status block carrying the source's key state.

    Preserves the exact conditions under which the legacy code surfaced a tag
    error: ``read_hex`` / ``read_hex_raw`` / ``search_bytes`` gate on
    ``view == "vas"`` (the raw container view is keyless by design); the other
    producers are unconditional. When not keyed, no key check is performed so
    the result reports a clean (decrypted) status.
    """
    from memdiver.core.service_result import (
        KeyStatus,
        Resolution,
        ServiceResult,
        StatusBlock,
    )

    key = KeyStatus.from_source(src) if _view_is_keyed(view) else KeyStatus()
    res = Resolution.UNRESOLVED if not key.decrypted else Resolution.OK
    return ServiceResult(payload=payload, status=StatusBlock(resolution=res, key=key))


def _require_msl_path(path_str: str) -> Path:
    """Validate an MSL path, raising the hard-error equivalents of the guards.

    Mirrors the ``is_file`` / ``.suffix == ".msl"`` checks the sibling
    ``get_*`` functions return as error dicts, but raises instead.
    """
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundServiceError(f"File not found: {path_str}")
    if path.suffix != ".msl":
        raise UnsupportedFormatError(f"Not an MSL file: {path_str}")
    return path


def read_hex_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 256,
    view: ViewMode = "raw",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`read_hex` (always carries status)."""
    length = min(length, MAX_HEX_LENGTH)
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            file_size = source.size_for(view)
            format_name = source.format_name
            # Surface a locked/undecryptable keyed view before the offset-bounds
            # check (see _view_locked): matches the legacy tag-status-first order.
            if not _view_locked(source, view) and (offset < 0 or offset > file_size):
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={
                        "offset": offset,
                        "file_size": file_size,
                        "view": view,
                        "format": format_name,
                    },
                )
            data = source.read_range(offset, length, view=view)
            payload = {
                "hex_lines": _format_hex_lines(data, offset),
                "offset": offset,
                "length": len(data),
                "file_size": file_size,
                "format": format_name,
                "view": view,
            }
            return _finalize_inspect(payload, source, view=view)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def read_hex_raw_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 8192,
    view: ViewMode = "raw",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`_read_hex_raw` (base64 payload)."""
    import base64

    length = min(length, 16384)  # cap at 16KB
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            file_size = source.size_for(view)
            format_name = source.format_name
            # Surface a locked/undecryptable keyed view before the offset-bounds
            # check (see _view_locked): matches the legacy tag-status-first order.
            if not _view_locked(source, view) and (offset < 0 or offset > file_size):
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={
                        "offset": offset,
                        "file_size": file_size,
                        "view": view,
                        "format": format_name,
                    },
                )
            actual_length = max(0, min(length, file_size - offset))
            data = source.read_range(offset, actual_length, view=view)
            payload = {
                "offset": offset,
                "length": len(data),
                "file_size": file_size,
                "format": format_name,
                "view": view,
                "bytes": base64.b64encode(data).decode("ascii"),
            }
            return _finalize_inspect(payload, source, view=view)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def resolve_va_result(
    session: ToolSession,
    dump_path: str,
    va: int,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`_resolve_va` (MSL VA translation)."""
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            if source.format_name != "msl":
                raise UnsupportedFormatError("VA translation requires an MSL dump")
            file_offset = source.va_to_file_offset(va)
            vas_offset = source.va_to_vas_offset(va)

            module_path = None
            region_base = None
            reader = source.get_reader()
            for m in reader.collect_modules():
                if m.base_addr <= va < m.base_addr + m.module_size:
                    module_path = m.path
                    region_base = m.base_addr
                    break
            if region_base is None:
                for r in reader.collect_regions():
                    if r.base_addr <= va < r.base_addr + r.region_size:
                        region_base = r.base_addr
                        break
            payload = {
                "va": va,
                "file_offset": file_offset,
                "vas_offset": vas_offset,
                "module_path": module_path,
                "region_base": region_base,
            }
            return _finalize_inspect(payload, source, view=None)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def search_bytes_result(
    session: ToolSession,
    dump_path: str,
    pattern_hex: str,
    view: ViewMode = "raw",
    max_results: int = 500,
    cursor: int = 0,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`search_bytes` (hex pattern search)."""
    normalized = pattern_hex.strip()
    if normalized[:2].lower() == "0x":
        normalized = normalized[2:]
    normalized = "".join(normalized.split())
    if not normalized:
        raise CapabilityError("Empty byte pattern")
    try:
        needle = bytes.fromhex(normalized)
    except ValueError:
        raise CapabilityError(f"Invalid hex byte pattern: {pattern_hex!r}")
    if not needle:
        raise CapabilityError("Empty byte pattern")

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            file_size = source.size_for(view)
            offsets = source.find_all(needle, view=view)
            page = offsets[cursor:cursor + max_results]
            truncated = len(offsets) > cursor + max_results
            next_cursor = cursor + max_results if truncated else 0
            payload = {
                "pattern_hex": needle.hex(),
                "pattern_len": len(needle),
                "offsets": page,
                "count": len(offsets),
                "truncated": truncated,
                "next_cursor": next_cursor,
                "view": view,
                "file_size": file_size,
            }
            return _finalize_inspect(payload, source, view=view)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def session_info_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_session_info`."""
    _require_msl_path(msl_path)

    from memdiver.msl.session_extract import extract_session_report

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        report = extract_session_report(reader)
        total_pages = sum(r.num_pages for r in reader.collect_regions())
        coverage = (
            report.captured_page_count / total_pages if total_pages else 0.0
        )
        payload = {
            "dump_uuid": str(report.dump_uuid),
            "pid": report.pid,
            "os_type": report.os_type,
            "arch_type": report.arch_type,
            "timestamp_iso": report.timestamp_iso,
            "exe_path": (
                report.process_identity.exe_path
                if report.process_identity else None
            ),
            "modules": [
                {"path": m.path, "base_addr": m.base_addr, "size": m.module_size}
                for m in report.modules
            ],
            "region_count": report.region_count,
            "total_region_size": report.total_region_size,
            "captured_page_count": report.captured_page_count,
            "key_hint_count": report.key_hint_count,
            "key_hints_by_type": dict(report.key_hints_by_type),
            "vas_entries": [
                {"base_addr": e.base_addr, "size": e.region_size, "type": e.region_type}
                for e in report.vas_entries
            ],
            "vas_coverage": dict(report.vas_coverage),
            "string_count": report.string_count,
            "total_pages": total_pages,
            "coverage": coverage,
        }
        return _finalize_inspect(payload, reader, view=None)


def page_states_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_page_states`."""
    _require_msl_path(msl_path)

    from memdiver.msl.enums import PageState
    from memdiver.msl.page_map import _states_to_intervals

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        regions = reader.collect_regions()
        regions.sort(key=lambda r: r.base_addr)

        vas_offset = 0
        total_pages = 0
        captured_pages = 0
        out_regions: List[dict] = []
        for region in regions:
            intervals = region.page_intervals or _states_to_intervals(
                region.page_states
            )
            entries: List[dict] = []
            for iv in intervals:
                if iv.state == PageState.CAPTURED:
                    state_name = "CAPTURED"
                elif iv.state == PageState.UNMAPPED:
                    state_name = "UNMAPPED"
                else:  # FAILED or RESERVED -> FAILED
                    state_name = "FAILED"
                entry = {
                    "va": region.base_addr + iv.start_page * region.page_size,
                    "length": iv.count * region.page_size,
                    "state": state_name,
                    "page_count": iv.count,
                }
                if iv.state == PageState.CAPTURED:
                    entry["vas_offset"] = vas_offset
                    vas_offset += iv.count * region.page_size
                    captured_pages += iv.count
                total_pages += iv.count
                entries.append(entry)
            out_regions.append({
                "base_addr": region.base_addr,
                "region_size": region.region_size,
                "page_size": region.page_size,
                "intervals": entries,
            })

        payload = {
            "regions": out_regions,
            "total_pages": total_pages,
            "captured_pages": captured_pages,
            "coverage": captured_pages / total_pages if total_pages else 0.0,
            "vas_size": vas_offset,
        }
        return _finalize_inspect(payload, reader, view=None)


def processes_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_processes`."""
    _require_msl_path(msl_path)

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        tables = reader.collect_processes()
        processes: List[dict] = []
        for table in tables:
            for e in table.entries:
                processes.append({
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
        return _finalize_inspect({"processes": processes}, reader, view=None)


def modules_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_modules`."""
    _require_msl_path(msl_path)

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        collected = reader.collect_modules()
        modules = [
            {
                "path": m.path,
                "base_addr": m.base_addr,
                "size": m.module_size,
                "version": m.version,
            }
            for m in collected
        ]
        return _finalize_inspect({"modules": modules}, reader, view=None)


def handles_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_handles`."""
    _require_msl_path(msl_path)

    from memdiver.msl.enums import HandleType

    def handle_type_name(value: int) -> str:
        try:
            return HandleType(value).name.capitalize()
        except ValueError:
            return "Unknown"

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        tables = reader.collect_handles()
        handles: List[dict] = []
        for table in tables:
            for e in table.entries:
                handles.append({
                    "pid": e.pid,
                    "fd": e.fd,
                    "handle_type": e.handle_type,
                    "handle_type_name": handle_type_name(e.handle_type),
                    "path": e.path,
                })
        return _finalize_inspect({"handles": handles}, reader, view=None)


def connections_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer listing CONNECTION_TABLE entries (spec §6.4, 0x0052)."""
    _require_msl_path(msl_path)

    import ipaddress

    def format_addr(family: int, raw: bytes) -> str:
        """Render a CONNECTION_TABLE address blob as a human string."""
        try:
            if family == 0x02:  # AF_INET
                return str(ipaddress.IPv4Address(bytes(raw[:4])))
            if family == 0x0A:  # AF_INET6
                return str(ipaddress.IPv6Address(bytes(raw[:16])))
        except (ValueError, ipaddress.AddressValueError):
            pass
        return raw[:16].hex()

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        tables = reader.collect_connections()
        connections: List[dict] = []
        for table in tables:
            for e in table.entries:
                connections.append({
                    "pid": e.pid,
                    "family": e.family,
                    "protocol": e.protocol,
                    "state": e.state,
                    "local_addr": format_addr(e.family, e.local_addr),
                    "local_port": e.local_port,
                    "remote_addr": format_addr(e.family, e.remote_addr),
                    "remote_port": e.remote_port,
                })
        return _finalize_inspect({"connections": connections}, reader, view=None)


def module_index_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer listing MODULE_LIST_INDEX entries (spec §5.3, 0x0010)."""
    _require_msl_path(msl_path)

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        tables = reader.collect_module_list_index()
        entries: List[dict] = []
        for table in tables:
            for e in table.entries:
                entries.append({
                    "module_uuid": str(e.module_uuid),
                    "base_addr": e.base_addr,
                    "size": e.module_size,
                    "path": e.path,
                })
        return _finalize_inspect({"module_index": entries}, reader, view=None)


def blocks_result(
    session: ToolSession,
    msl_path: str,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for the grouped MSL block tree.

    Groups every block by its :mod:`block_tree` category, preserving order, so
    each group is ``{"category", "blocks": [{label, block_type, offset, size,
    detail}]}`` — the same shape the block navigator surfaces consume.
    """
    _require_msl_path(msl_path)

    from memdiver.msl.block_tree import group_blocks, list_blocks

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    with open_msl_reader(msl_path, km) as reader:
        groups = group_blocks(list_blocks(reader))
        block_groups: List[dict] = []
        for category, nodes in groups.items():
            block_groups.append({
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
        return _finalize_inspect({"blocks": block_groups}, reader, view=None)


def entropy_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    window: int = 32,
    step: int = 16,
    threshold: float = 7.5,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`get_entropy` (entropy profile).

    Opens a keyed dump source (``view=None``): the read is ALWAYS performed and
    the key/tag state is carried in ``status``. Missing file / out-of-range
    offset are RAISED as ``CapabilityError`` subclasses.
    """
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            file_size = source.size_for()
            # Reject an out-of-range offset with a clean error instead of letting
            # read_range silently return an empty/tail slice that yields odd stats.
            if offset < 0 or offset > file_size:
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={"offset": offset, "file_size": file_size},
                )
            data = (
                source.read_all() if length == 0
                else source.read_range(offset, length)
            )

            overall = shannon_entropy(data)
            profile = compute_entropy_profile(data, window=window, step=step)
            regions = find_high_entropy_regions(profile, threshold=threshold)

            # Sample profile to keep response size reasonable. Use index-based
            # even sampling that spans the whole profile (always including the
            # last entry) so the plotted sample matches the full-profile stats.
            sample = profile
            if len(profile) > MAX_ENTROPY_SAMPLES:
                n = len(profile)
                sample = [
                    profile[(i * (n - 1)) // (MAX_ENTROPY_SAMPLES - 1)]
                    for i in range(MAX_ENTROPY_SAMPLES)
                ]

            entropies = [e for _, e in profile] if profile else [0.0]
            payload = {
                "overall_entropy": round(overall, 4),
                "high_entropy_regions": [
                    {"start": s, "end": e, "mean_entropy": round(m, 4)}
                    for s, e, m in regions
                ],
                "profile_sample": [
                    {"offset": o, "entropy": round(e, 4)} for o, e in sample
                ],
                "stats": {
                    "min": round(min(entropies), 4),
                    "max": round(max(entropies), 4),
                    "mean": round(sum(entropies) / len(entropies), 4),
                },
            }
            return _finalize_inspect(payload, source, view=None)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def strings_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    min_length: int = 4,
    encoding: str = "ascii",
    max_results: int = 500,
    cursor: int = 0,
    chunk_size: int = 8 * 1024 * 1024,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`_extract_strings` (chunked streaming).

    Opens a keyed dump source (``view=None``): the scan is ALWAYS performed and
    the key/tag state is carried in ``status``. A missing file is RAISED as a
    ``FileNotFoundServiceError``.
    """
    max_results = min(max_results, MAX_STRING_RESULTS)
    chunk_size = max(chunk_size, TAIL_OVERLAP + 1)

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            window_end = (offset + length) if length else source.size
            window_start = max(offset, cursor)
            results, next_cursor, truncated = _scan_window_for_strings(
                source, window_start, window_end,
                min_length, encoding, max_results, chunk_size,
            )
            payload = {
                "strings": results,
                "total_count": len(results) if not truncated else f">{max_results}",
                "truncated": truncated,
                "next_cursor": next_cursor,
                "window_end": window_end,
            }
            return _finalize_inspect(payload, source, view=None)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def detect_format_result(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`detect_format` (raw-container detection).

    Reads the RAW container (``view="raw"``): this view is keyless by design, so
    the result reports a clean/decrypted status. Missing file / out-of-range
    offset are RAISED as ``CapabilityError`` subclasses.
    """
    from memdiver.core.format_detect import detect_format_at_offset, suggest_formats

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            raw_size = (
                source.size_for("raw") if hasattr(source, "size_for")
                else source.size
            )
            if offset < 0 or offset > raw_size:
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={"offset": offset, "file_size": raw_size},
                )
            length = min(65536, max(0, raw_size - offset))
            data = source.read_range(offset, length, view="raw")

            detected = detect_format_at_offset(data, 0)
            suggested = suggest_formats(data)
            payload = {
                "format": detected,
                "detected_format": detected,
                "suggested_formats": suggested,
                "offset": offset,
                "file_size": raw_size,
            }
            return _finalize_inspect(payload, source, view="raw")
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


def analyze_region_result(
    session: ToolSession,
    dump_path: str,
    offset: int,
    window: int = 64,
    view: ViewMode = "raw",
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """ServiceResult producer for :func:`core.region_analysis.analyze_region`.

    Single source for a per-offset region investigation (byte value, local
    entropy band, and printable strings in the neighbourhood window). Opens the
    dump source and runs the SAME ``analyze_region`` primitive the marimo view
    uses, then serialises the :class:`RegionReport` into a JSON-safe payload and
    carries key/tag state in ``status``. A missing file, wrong-format container,
    or out-of-range offset are RAISED as ``CapabilityError`` subclasses rather
    than returned as an ``{"error": ...}`` dict.

    ``variance`` / ``hits`` are intentionally NOT parameters: they are in-memory
    cross-run analysis artefacts with no on-disk representation, so a path-based
    producer leaves ``variance_at_offset`` / ``matching_secrets`` empty.
    """
    from memdiver.core.region_analysis import analyze_region

    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            file_size = source.size_for(view)
            if offset < 0 or offset >= file_size:
                raise OffsetOutOfRangeError(
                    "offset out of range",
                    details={"offset": offset, "file_size": file_size, "view": view},
                )
            data = source.read_range(0, file_size, view=view)
            report = analyze_region(data, offset, window=window)
            payload = {
                "offset": report.offset,
                "byte_value": report.byte_value,
                "entropy": round(report.entropy, 4),
                "entropy_level": report.entropy_level,
                "variance_at_offset": report.variance_at_offset,
                "variance_class": report.variance_class,
                "matching_secrets": [
                    {"secret_type": h.secret_type, "offset": h.offset, "length": h.length}
                    for h in report.matching_secrets
                ],
                "strings": [
                    {"offset": st.offset, "value": st.value,
                     "encoding": st.encoding, "length": st.length}
                    for st in report.strings
                ],
                "neighborhood_hex": report.neighborhood.hex(),
                "window": window,
                "view": view,
            }
            return _finalize_inspect(payload, source, view=view)
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}")
