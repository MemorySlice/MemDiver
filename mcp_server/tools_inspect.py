"""Pure tool functions for MemDiver — low-level dump inspection.

read_hex, get_entropy, extract_strings, get_session_info.
"""

import logging
from pathlib import Path
from typing import List, Optional

from api.services.reader_cache import cached_dump_source, cached_msl_reader
from core.dump_source import ViewMode
from core.entropy import compute_entropy_profile, find_high_entropy_regions, shannon_entropy
from core.strings import extract_strings

from .session import ToolSession

logger = logging.getLogger("memdiver.mcp_server.tools_inspect")

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


def read_hex(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 256,
    view: ViewMode = "raw",
) -> dict:
    """Read raw bytes from a dump file and return hex + ASCII representation.

    For ``.msl`` files, ``view="raw"`` (default) reads the .msl container
    bytes; ``view="vas"`` reads the flattened captured memory projection.
    For ``.dump`` files the ``view`` parameter is accepted but ignored.
    """
    length = min(length, MAX_HEX_LENGTH)
    try:
        with cached_dump_source(Path(dump_path)) as source:
            file_size = source.size_for(view)
            data = source.read_range(offset, length, view=view)
            format_name = source.format_name
    except FileNotFoundError:
        return {"error": f"File not found: {dump_path}"}

    return {
        "hex_lines": _format_hex_lines(data, offset),
        "offset": offset,
        "length": len(data),
        "file_size": file_size,
        "format": format_name,
        "view": view,
    }


def _read_hex_raw(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 8192,
    view: ViewMode = "raw",
) -> dict:
    """Read raw bytes from a dump file, returned as base64."""
    import base64

    length = min(length, 16384)  # cap at 16KB
    try:
        with cached_dump_source(Path(dump_path)) as source:
            file_size = source.size_for(view)
            format_name = source.format_name
            if offset < 0 or offset > file_size:
                return {
                    "error": "offset out of range",
                    "offset": offset,
                    "file_size": file_size,
                    "view": view,
                    "format": format_name,
                }
            actual_length = max(0, min(length, file_size - offset))
            data = source.read_range(offset, actual_length, view=view)
    except FileNotFoundError:
        return {"error": f"File not found: {dump_path}"}

    return {
        "offset": offset,
        "length": len(data),
        "file_size": file_size,
        "format": format_name,
        "view": view,
        "bytes": base64.b64encode(data).decode("ascii"),
    }


def _resolve_va(
    session: ToolSession,
    dump_path: str,
    va: int,
) -> dict:
    """Translate a virtual address to file and VAS offsets for an MSL dump.

    Returns ``{file_offset, vas_offset, module_path, region_base}`` with
    ``None`` for any field that could not be resolved. ``.dump`` inputs
    return an error — raw dumps have no VA mapping.
    """
    try:
        with cached_dump_source(Path(dump_path)) as source:
            if source.format_name != "msl":
                return {"error": "VA translation requires an MSL dump"}
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
    except FileNotFoundError:
        return {"error": f"File not found: {dump_path}"}

    return {
        "va": va,
        "file_offset": file_offset,
        "vas_offset": vas_offset,
        "module_path": module_path,
        "region_base": region_base,
    }


def get_entropy(
    session: ToolSession,
    dump_path: str,
    offset: int = 0,
    length: int = 0,
    window: int = 32,
    step: int = 16,
    threshold: float = 7.5,
) -> dict:
    """Compute entropy profile for a dump file region."""
    path = Path(dump_path)
    if not path.is_file():
        return {"error": f"File not found: {dump_path}"}

    with cached_dump_source(path) as source:
        data = source.read_all() if length == 0 else source.read_range(offset, length)

    overall = shannon_entropy(data)
    profile = compute_entropy_profile(data, window=window, step=step)
    regions = find_high_entropy_regions(profile, threshold=threshold)

    # Sample profile to keep response size reasonable
    sample = profile
    if len(profile) > MAX_ENTROPY_SAMPLES:
        step_size = len(profile) // MAX_ENTROPY_SAMPLES
        sample = profile[::step_size][:MAX_ENTROPY_SAMPLES]

    entropies = [e for _, e in profile] if profile else [0.0]
    return {
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
    """
    path = Path(dump_path)
    if not path.is_file():
        return {"error": f"File not found: {dump_path}"}

    max_results = min(max_results, MAX_STRING_RESULTS)
    chunk_size = max(chunk_size, TAIL_OVERLAP + 1)

    with cached_dump_source(path) as source:
        window_end = (offset + length) if length else source.size
        window_start = max(offset, cursor)
        results, next_cursor, truncated = _scan_window_for_strings(
            source, window_start, window_end,
            min_length, encoding, max_results, chunk_size,
        )

    return {
        "strings": results,
        "total_count": len(results) if not truncated else f">{max_results}",
        "truncated": truncated,
        "next_cursor": next_cursor,
        "window_end": window_end,
    }


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


def get_session_info(session: ToolSession, msl_path: str) -> dict:
    """Extract session metadata from an MSL file."""
    path = Path(msl_path)
    if not path.is_file():
        return {"error": f"File not found: {msl_path}"}
    if not path.suffix == ".msl":
        return {"error": f"Not an MSL file: {msl_path}"}

    from msl.session_extract import extract_session_report

    # Use the cached reader so repeated get_session_info calls (common in
    # AI-driven investigation sessions) skip the mmap + 6 collect_*
    # passes on every hit.
    with cached_msl_reader(path) as reader:
        report = extract_session_report(reader)
    return {
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
    }


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
