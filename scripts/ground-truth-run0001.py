"""R2-B ground-truth validation for run_0001.

Exercises the headless dump-source pipeline + a slice of the MCP tool
surface against the four dump flavours of a real dataset run:

  - memslicer.msl     -> MslDumpSource
  - gdb_raw.bin       -> GdbRawDumpSource
  - lldb_raw.bin      -> LldbRawDumpSource
  - gcore.core        -> GCoreDumpSource

For each dump we:
  1. open() it via the auto-detect ``open_dump`` factory
  2. locate the 32-byte master key with ``find_all(..., view='raw')``
     and ``find_all(..., view='vas')``
  3. translate one hit to a VA where possible
  4. benchmark extract_strings_tool() wall-clock (first page)

Prints a machine-readable JSON blob to stdout plus a human summary.

Run:
    python scripts/ground-truth-run0001.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# --- ensure project root is on sys.path ------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.dataset_metadata import load_run_meta
from core.dump_source import open_dump
from mcp_server.tools_inspect import _extract_strings as extract_strings_tool, get_session_info


RUN_DIR = Path(
    "/Users/danielbaier/research/projects/github/issues/"
    "2024 fritap issues/2026_success/mempdumps/dataset_memory_slice/"
    "gocryptfs/dataset_gocryptfs/run_0001"
)


class _StubSession:
    """Stand-in for mcp_server.session.ToolSession."""

    pass


def _inverse_va_for_msl(source, raw_offset: int):
    """MSL (raw view): best-effort — locate the payload block that contains
    ``raw_offset`` and return its region base as a VA anchor.

    The MSL container is compressed per-block, so a raw file hit cannot be
    byte-for-byte inverted to a VA. We instead return the region_base
    whose block payload covers this raw offset.
    """
    reader = source.get_reader()
    for region in reader.collect_regions():
        block = region.block_header
        start = block.file_offset
        end = start + block.block_length
        if start <= raw_offset < end:
            return region.base_addr, {
                "region_base": region.base_addr,
                "region_size": region.region_size,
                "block_file_offset": block.file_offset,
                "block_length": block.block_length,
                "note": "MSL raw view is compressed; VA is region base anchor.",
            }
    return None, None


def _inverse_va_for_msl_vas(source, vas_offset: int):
    """MSL (vas view): walk iter_ranges to convert a flat VAS offset -> VA."""
    flat_pos = 0
    for vaddr, length, _chunk in source.iter_ranges():
        if flat_pos <= vas_offset < flat_pos + length:
            return vaddr + (vas_offset - flat_pos), {
                "region_base": vaddr,
                "region_size": length,
            }
        flat_pos += length
    return None, None


def _inverse_va_for_regioned(source, raw_offset: int):
    """gdb_raw/lldb_raw: walk _regions + _cum_offsets, no reader indirection."""
    regions = source._regions  # noqa: SLF001
    cum = source._cum_offsets  # noqa: SLF001
    for idx in range(source._usable_region_count):  # noqa: SLF001
        bin_start = cum[idx]
        bin_end = cum[idx + 1]
        if bin_start <= raw_offset < bin_end:
            region = regions[idx]
            return region.start + (raw_offset - bin_start), {
                "region_start_va": region.start,
                "region_end_va": region.end,
                "region_perms": region.perm,
                "region_path": region.path,
            }
    return None, None


def _inverse_va_for_gcore(source, raw_offset: int):
    """gcore: walk PT_LOAD segments."""
    for seg in source._vas_segments:  # noqa: SLF001
        if seg.file_offset <= raw_offset < seg.file_offset + seg.filesz:
            return seg.vaddr + (raw_offset - seg.file_offset), {
                "seg_vaddr": seg.vaddr,
                "seg_filesz": seg.filesz,
                "seg_file_offset": seg.file_offset,
            }
    return None, None


def _region_count(source) -> int:
    """Shared probe: how many regions did this source materialise?"""
    fmt = source.format_name
    if fmt == "msl":
        return len(source.get_reader().collect_regions())
    if fmt in ("gdb_raw", "lldb_raw"):
        return source._usable_region_count  # noqa: SLF001
    if fmt == "gcore":
        return len(source._vas_segments)  # noqa: SLF001
    return 0


def _benchmark_strings(dump_path: Path) -> dict:
    """Time a single MCP extract_strings_tool page, capped at 500 results."""
    session = _StubSession()
    t0 = time.perf_counter()
    result = extract_strings_tool(
        session,
        str(dump_path),
        offset=0,
        length=0,  # whole file
        min_length=6,
        encoding="ascii",
        max_results=500,
    )
    elapsed = time.perf_counter() - t0
    return {
        "wall_seconds": round(elapsed, 3),
        "returned": len(result.get("strings", [])) if "strings" in result else 0,
        "truncated": result.get("truncated"),
        "next_cursor": result.get("next_cursor"),
    }


def _analyse_one_dump(label: str, path: Path, master_key: bytes) -> dict:
    size = path.stat().st_size
    with open_dump(path) as source:
        fmt = source.format_name
        region_count = _region_count(source)

        hits_raw = source.find_all(master_key, view="raw")
        # VAS is the default for most sources; try it too (best-effort).
        try:
            hits_vas = source.find_all(master_key, view="vas")
        except Exception as exc:  # noqa: BLE001
            hits_vas = []
            vas_err = str(exc)
        else:
            vas_err = None

        va_info = None
        if fmt == "msl" and hits_vas:
            # MSL: VAS hits give byte-exact VA translation via flat map.
            va, extra = _inverse_va_for_msl_vas(source, hits_vas[0])
            va_info = {"va": va, "extra": extra, "source": "vas"}
        elif hits_raw:
            if fmt == "msl":
                va, extra = _inverse_va_for_msl(source, hits_raw[0])
            elif fmt in ("gdb_raw", "lldb_raw"):
                va, extra = _inverse_va_for_regioned(source, hits_raw[0])
            elif fmt == "gcore":
                va, extra = _inverse_va_for_gcore(source, hits_raw[0])
            else:
                va, extra = None, None
            va_info = {"va": va, "extra": extra, "source": "raw"}

    # strings benchmark runs after closing the source (it reopens via cache).
    strings_bench = _benchmark_strings(path)

    return {
        "label": label,
        "path": str(path),
        "size_bytes": size,
        "format": fmt,
        "region_count": region_count,
        "hits_raw": hits_raw,
        "hits_vas": hits_vas,
        "hits_vas_error": vas_err,
        "va_info": va_info,
        "strings_bench": strings_bench,
    }


def main() -> int:
    meta = load_run_meta(RUN_DIR)
    assert meta is not None, f"meta.json missing under {RUN_DIR}"
    print(f"[run {meta.run_id}] cipher={meta.cipher} pid={meta.pid} "
          f"aslr_base=0x{meta.aslr_base:x}", flush=True)
    print(f"[run {meta.run_id}] master_key = {meta.master_key.hex()}", flush=True)

    dumps = [
        ("memslicer.msl", RUN_DIR / "memslicer.msl"),
        ("gdb_raw.bin",   RUN_DIR / "gdb_raw.bin"),
        ("lldb_raw.bin",  RUN_DIR / "lldb_raw.bin"),
        ("gcore.core",    RUN_DIR / "gcore.core"),
    ]

    results = []
    for label, path in dumps:
        print(f"\n--- {label} ({path.stat().st_size / 1024**2:,.1f} MiB) ---", flush=True)
        t0 = time.perf_counter()
        info = _analyse_one_dump(label, path, meta.master_key)
        print(f"  regions={info['region_count']}  "
              f"hits(raw)={len(info['hits_raw'])}  "
              f"hits(vas)={len(info['hits_vas'])}  "
              f"strings={info['strings_bench']['wall_seconds']}s  "
              f"total_walltime={time.perf_counter() - t0:.2f}s",
              flush=True)
        if info["hits_raw"]:
            raw0 = info["hits_raw"][0]
            va = info["va_info"]["va"] if info["va_info"] else None
            va_str = f"0x{va:x}" if va else "?"
            print(f"  first hit: raw=0x{raw0:x} -> VA={va_str}", flush=True)
        results.append(info)

    # MCP session_info exercise on the MSL dump
    session = _StubSession()
    t0 = time.perf_counter()
    sess_info = get_session_info(session, str(RUN_DIR / "memslicer.msl"))
    print(f"\nMCP get_session_info(msl): pid={sess_info.get('pid')} "
          f"uuid={sess_info.get('dump_uuid')} "
          f"walltime={time.perf_counter() - t0:.2f}s", flush=True)

    payload = {
        "run_id": meta.run_id,
        "master_key_hex": meta.master_key_hex,
        "aslr_base": meta.aslr_base,
        "pid": meta.pid,
        "dumps": results,
        "session_info": {
            "pid": sess_info.get("pid"),
            "dump_uuid": sess_info.get("dump_uuid"),
        },
    }
    out = REPO_ROOT / "scripts" / "ground-truth-run0001.json"
    out.write_text(json.dumps(payload, indent=2, default=str))
    print(f"\nJSON written to {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
