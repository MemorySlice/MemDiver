"""Deprecated back-compat shims extracted from :mod:`tools_inspect` (P3.1).

These thin adapters predate the ``*_result`` ServiceResult producers, which are
now the real public surface. Each shim delegates to its sibling producer in
:mod:`memdiver.app.tools_inspect` and flattens the result back to the historical
bare-``dict`` return shape (optionally gating on key/tag status). They are kept
here, and re-exported from :mod:`tools_inspect`, purely so existing callers keep
working unchanged; new code should call the ``*_result`` producers directly.
"""

import logging
from typing import Optional

from memdiver.core.dump_source import ViewMode
from memdiver.core.service_errors import CapabilityError

from .session import ToolSession
from .tools_inspect import (
    detect_format_result,
    entropy_result,
    handles_result,
    modules_result,
    page_states_result,
    processes_result,
    read_hex_raw_result,
    read_hex_result,
    resolve_va_result,
    search_bytes_result,
    session_info_result,
    strings_result,
)

logger = logging.getLogger("memdiver.app.tools_inspect_legacy")


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
