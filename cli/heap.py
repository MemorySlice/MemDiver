"""Heap CLI commands: ``memdiver heap {detect,summary,chunks,at,free-lists,roles}``.

Thin CLI adapters over the ``heap.*`` ServiceResult producers in
:mod:`memdiver.app.tools_heap` — the same functions behind the web API and
the MCP server, so the surfaces cannot drift. Errors and the key state are
presented exactly like ``inspect`` (:func:`._present_inspect_cli_call`).

Output is a human-readable report by default; ``--json`` (or ``-o FILE``)
emits the producer payload unchanged. Errors are printed to stderr in text
mode and as the usual ``{"error": …}`` JSON in ``--json`` mode.
"""

import argparse
import sys
from typing import Callable, Iterable, List, Sequence

# Parser defaults come from the producer module so the CLI cannot drift.
from memdiver.app.tools_heap import (DEFAULT_CHUNK_PAGE_SIZE,
                                     DEFAULT_ROLES_LENGTH, HEAP_VIEWS,
                                     MAX_CHUNK_PAGE_SIZE, MAX_ROLES_LENGTH)
from memdiver.heap.model import ChunkState

from ._shared import ALLOCATOR_CHOICES, _auto_int, _decrypt_parent_parser
from .inspect import (_emit_inspect, _inspect_key_kwargs, _new_tool_session,
                      _present_inspect_cli_call)

#: ``--allocator`` choices (``auto`` lets the detector pick).
HEAP_ALLOCATOR_CHOICES = ALLOCATOR_CHOICES
HEAP_VIEW_CHOICES = HEAP_VIEWS
_STATE_CHOICES = tuple(state.value for state in ChunkState)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _heap_common_parent_parser() -> argparse.ArgumentParser:
    """Options shared by every ``heap`` action."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("dump_path", help="Dump (.msl, ELF core, minidump or raw) path")
    p.add_argument("--allocator", choices=HEAP_ALLOCATOR_CHOICES, default="auto",
                   help="Allocator to parse the heap as (default: auto-detect)")
    p.add_argument("--base-va", type=_auto_int, default=None,
                   help="Virtual address of byte 0 of a flat raw dump with no "
                        "memory map (hex or decimal)")
    p.add_argument("--json", action="store_true",
                   help="Print the JSON payload instead of a text report")
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _add_chunk_filter_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state", choices=_STATE_CHOICES,
                        help="Only chunks in this allocation state")
    parser.add_argument("--min-size", type=_auto_int, help="Minimum chunk size")
    parser.add_argument("--max-size", type=_auto_int, help="Maximum chunk size")
    parser.add_argument("--va-start", type=_auto_int,
                        help="Window start VA (half-open, hex or decimal)")
    parser.add_argument("--va-end", type=_auto_int,
                        help="Window end VA (exclusive)")
    parser.add_argument("--offset", type=_auto_int,
                        help="Window start offset in --view (use with --length)")
    parser.add_argument("--length", type=_auto_int, help="Window length in bytes")
    parser.add_argument("--view", choices=HEAP_VIEW_CHOICES, default="vas",
                        help="Byte view for --offset and the view_offset "
                             "column (default: vas)")
    parser.add_argument("--page", type=int, default=0,
                        help="0-based result page (default: 0)")
    parser.add_argument("--page-size", type=int,
                        default=DEFAULT_CHUNK_PAGE_SIZE,
                        help=f"Chunks per page (default: "
                             f"{DEFAULT_CHUNK_PAGE_SIZE}, max: "
                             f"{MAX_CHUNK_PAGE_SIZE})")


def add_heap_parser(sub) -> None:
    """Register the ``heap <action>`` group on the top-level subparsers."""
    parents = [_heap_common_parent_parser(), _decrypt_parent_parser()]
    heap = sub.add_parser(
        "heap", help="Heap allocator analysis (detect, summary, chunks, at, "
                     "free-lists, roles)")
    heap_sub = heap.add_subparsers(dest="heap_action")
    heap_sub.add_parser("detect", parents=parents,
                        help="Rank allocator candidates with their evidence")
    heap_sub.add_parser("summary", parents=parents,
                        help="Allocator, state counts, size histogram and "
                             "coverage of the heap")
    chunks = heap_sub.add_parser("chunks", parents=parents,
                                 help="One page of the chunk table")
    _add_chunk_filter_arguments(chunks)
    at = heap_sub.add_parser("at", parents=parents,
                             help="The chunk containing a VA or offset")
    at_target = at.add_mutually_exclusive_group(required=True)
    at_target.add_argument("--va", type=_auto_int, help="Virtual address")
    at_target.add_argument("--offset", type=_auto_int,
                           help="Offset in --view (hex or decimal)")
    at.add_argument("--view", choices=HEAP_VIEW_CHOICES, default="vas",
                    help="Byte view for --offset (default: vas)")
    free_lists = heap_sub.add_parser("free-lists", parents=parents,
                                     help="Walked free lists (tcache, "
                                          "fastbins, ...)")
    free_lists.add_argument("--kind", help="Only free lists of this kind "
                                           "(e.g. tcache, fastbin)")
    roles = heap_sub.add_parser("roles", parents=parents,
                                help="Byte-role runs (header, user data, "
                                     "free link, ...) of a view window")
    _add_roles_window_arguments(roles)


def _add_roles_window_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--view", choices=HEAP_VIEW_CHOICES, default="vas",
                        help="Byte view of the window (default: vas)")
    parser.add_argument("--offset", type=_auto_int, default=0,
                        help="Window start offset in --view (default: 0)")
    parser.add_argument("--length", type=_auto_int,
                        default=DEFAULT_ROLES_LENGTH,
                        help=f"Window length in bytes (default: "
                             f"{DEFAULT_ROLES_LENGTH}, max: {MAX_ROLES_LENGTH})")


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _hex(value) -> str:
    return "-" if value is None else f"{value:#x}"


def _table(headers: Sequence[str], rows: Iterable[Sequence]) -> List[str]:
    """Left-aligned fixed-width table lines."""
    cells = [[str(c) for c in headers]] + [[str(c) for c in r] for r in rows]
    widths = [max(len(row[i]) for row in cells) for i in range(len(headers))]
    return ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip()
            for row in cells]


def _evidence_lines(evidence: Sequence[dict], indent: str = "  ") -> List[str]:
    return [f"{indent}[{e.get('source')}] {e.get('detail')} "
            f"(weight {e.get('weight')})" for e in evidence]


def _diagnostic_lines(payload: dict) -> List[str]:
    diagnostics = payload.get("diagnostics") or []
    if not diagnostics:
        return []
    return ["", "Diagnostics:"] + [f"  - {d}" for d in diagnostics]


def _platform_text(platform) -> str:
    if not platform:
        return "unknown"
    return (f"{platform.get('os')}/{platform.get('arch')}, "
            f"{platform.get('pointer_size')}-byte pointers, "
            f"{platform.get('endianness')} endian")


def _chunk_rows(chunks: Sequence[dict]) -> List[list]:
    return [[_hex(c.get("va")), _hex(c.get("size")), c.get("state"),
             _hex(c.get("user_va")), c.get("user_len"), c.get("bin") or "-",
             _hex(c.get("view_offset"))] for c in chunks]


_CHUNK_HEADERS = ("VA", "SIZE", "STATE", "USER_VA", "USER_LEN", "BIN",
                  "VIEW_OFFSET")


def render_detect(payload: dict) -> List[str]:
    lines = [f"Allocator:  {payload.get('best')}"
             + (" (hinted)" if payload.get("hinted") else ""),
             f"Confidence: {payload.get('confidence')}",
             f"Format:     {payload.get('format')}",
             f"Platform:   {_platform_text(payload.get('platform'))}",
             "", "Candidates:"]
    for candidate in payload.get("candidates", []):
        lines.append(f"  {candidate.get('kind'):<10} score "
                     f"{candidate.get('score')}")
        lines.extend(_evidence_lines(candidate.get("evidence", []), "      "))
    return lines


def _summary_header(payload: dict) -> List[str]:
    flags = [name for name in ("partial", "heuristic") if payload.get(name)]
    return [f"Allocator:  {payload.get('allocator')}"
            + (f" ({payload['version_hint']})" if payload.get("version_hint")
               else ""),
            f"Confidence: {payload.get('confidence')}",
            f"Flags:      {', '.join(flags) if flags else 'none'}",
            f"Format:     {payload.get('format')}",
            f"Platform:   {_platform_text(payload.get('platform'))}",
            f"Regions:    {len(payload.get('regions', []))}",
            f"Chunks:     {payload.get('chunk_count')}",
            f"Free lists: {payload.get('free_list_count')}",
            f"Metadata:   {payload.get('metadata_bytes')} bytes"]


def render_summary(payload: dict) -> List[str]:
    bytes_by_state = payload.get("bytes_by_state", {})
    state_rows = [[state, count, bytes_by_state.get(state, 0)]
                  for state, count in payload.get("counts_by_state", {}).items()]
    histogram_rows = [[f"{b['min_size']}-{b['max_size']}", b["count"]]
                      for b in payload.get("size_histogram", [])]
    lines = _summary_header(payload)
    lines += ["", "Chunks by state:"] + _table(("STATE", "COUNT", "BYTES"),
                                               state_rows)
    lines += ["", "Size histogram:"] + _table(("SIZE", "COUNT"), histogram_rows)
    lines += ["", "Evidence:"] + _evidence_lines(payload.get("evidence", []))
    return lines + _diagnostic_lines(payload)


def render_chunks(payload: dict) -> List[str]:
    lines = [f"Allocator: {payload.get('allocator')}  view: "
             f"{payload.get('view')}  matches: {payload.get('total')} of "
             f"{payload.get('chunk_count')}  page {payload.get('page', 0) + 1}/"
             f"{max(payload.get('pages', 0), 1)}", ""]
    lines += _table(_CHUNK_HEADERS, _chunk_rows(payload.get("chunks", [])))
    return lines + _diagnostic_lines(payload)


def render_chunk_at(payload: dict) -> List[str]:
    lines = [f"Address:   {_hex(payload.get('va'))} "
             f"({payload.get('view')} offset {_hex(payload.get('view_offset'))})",
             f"Allocator: {payload.get('allocator')}",
             f"Role:      {payload.get('role')}"]
    if payload.get("found"):
        lines += [f"Offset in chunk: {payload.get('offset_in_chunk')}",
                  f"Offset in user data: "
                  f"{'-' if payload.get('offset_in_user') is None else payload['offset_in_user']}"]
    else:
        lines.append("No chunk contains this address.")
    rows = [[label] + _chunk_rows([payload[key]])[0]
            for label, key in (("prev", "prev"), ("chunk", "chunk"),
                               ("next", "next")) if payload.get(key)]
    return lines + [""] + _table(("",) + _CHUNK_HEADERS, rows)


def render_free_lists(payload: dict) -> List[str]:
    lines = [f"Allocator: {payload.get('allocator')}  lists: "
             f"{payload.get('list_count')}  cycles: {payload.get('cycle_count')}"
             f"  corrupt: {payload.get('corrupt_count')}", ""]
    rows = [[fl["kind"], fl["index"], _hex(fl["head_va"]), fl["length"],
             "yes" if fl["cycle"] else "no", "yes" if fl["corrupt"] else "no",
             " ".join(_hex(va) for va in fl["chunk_vas"][:8])
             + (" ..." if fl["length"] > 8 else "")]
            for fl in payload.get("lists", [])]
    lines += _table(("KIND", "INDEX", "HEAD", "LENGTH", "CYCLE", "CORRUPT",
                     "CHUNKS"), rows)
    return lines + _diagnostic_lines(payload)


def render_roles(payload: dict) -> List[str]:
    flags = [name for name in ("partial", "heuristic") if payload.get(name)]
    lines = [f"Allocator: {payload.get('allocator')}  view: "
             f"{payload.get('view')}  window: {_hex(payload.get('offset'))}"
             f"+{_hex(payload.get('length'))}  runs: "
             f"{len(payload.get('runs', []))}  chunk starts: "
             f"{len(payload.get('chunk_starts', []))}"
             + (f"  ({', '.join(flags)})" if flags else ""), ""]
    rows = [[_hex(run["offset"]), _hex(run["offset"] + run["length"]),
             run["length"], run["role"]] for run in payload.get("runs", [])]
    return lines + _table(("START", "END", "LENGTH", "ROLE"), rows)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _common_kwargs(args: argparse.Namespace) -> dict:
    return {"base_va": args.base_va, **_inspect_key_kwargs(args)}


def _run_heap(args: argparse.Namespace, produce: Callable,
              render: Callable[[dict], List[str]]) -> int:
    """Run *produce*, then print a text report or emit the JSON payload."""
    payload, exit_code, stderr_msg = _present_inspect_cli_call(produce)
    if args.json or args.output:
        return _emit_inspect(payload, args.output)
    if exit_code != 0:
        print(f"memdiver heap: ERROR — {stderr_msg or payload.get('error')}",
              file=sys.stderr)
        return exit_code
    print("\n".join(render(payload)))
    return 0


def _cmd_heap_detect(args: argparse.Namespace) -> int:
    """Rank allocator candidates with their evidence."""
    from memdiver.app.tools_heap import heap_detect_result
    return _run_heap(args, lambda: heap_detect_result(
        _new_tool_session(), args.dump_path, args.allocator,
        **_common_kwargs(args)), render_detect)


def _cmd_heap_summary(args: argparse.Namespace) -> int:
    """Whole-heap overview."""
    from memdiver.app.tools_heap import heap_summary_result
    return _run_heap(args, lambda: heap_summary_result(
        _new_tool_session(), args.dump_path, args.allocator,
        **_common_kwargs(args)), render_summary)


def _cmd_heap_chunks(args: argparse.Namespace) -> int:
    """One filtered page of the chunk table."""
    from memdiver.app.tools_heap import heap_chunks_result
    return _run_heap(args, lambda: heap_chunks_result(
        _new_tool_session(), args.dump_path, args.allocator,
        state=args.state, min_size=args.min_size, max_size=args.max_size,
        va_start=args.va_start, va_end=args.va_end, offset=args.offset,
        length=args.length, view=args.view, page=args.page,
        page_size=args.page_size, **_common_kwargs(args)), render_chunks)


def _cmd_heap_at(args: argparse.Namespace) -> int:
    """The chunk containing a VA or view offset."""
    from memdiver.app.tools_heap import heap_chunk_at_result
    return _run_heap(args, lambda: heap_chunk_at_result(
        _new_tool_session(), args.dump_path, args.allocator, va=args.va,
        offset=args.offset, view=args.view, **_common_kwargs(args)),
        render_chunk_at)


def _cmd_heap_free_lists(args: argparse.Namespace) -> int:
    """Walked free lists, optionally of one kind."""
    from memdiver.app.tools_heap import heap_free_lists_result
    return _run_heap(args, lambda: heap_free_lists_result(
        _new_tool_session(), args.dump_path, args.allocator, kind=args.kind,
        **_common_kwargs(args)), render_free_lists)


def _cmd_heap_roles(args: argparse.Namespace) -> int:
    """Byte-role runs of a view window."""
    from memdiver.app.tools_heap import heap_roles_result
    return _run_heap(args, lambda: heap_roles_result(
        _new_tool_session(), args.dump_path, args.allocator, view=args.view,
        offset=args.offset, length=args.length, **_common_kwargs(args)),
        render_roles)


_HEAP_HANDLERS = {
    "detect": _cmd_heap_detect,
    "summary": _cmd_heap_summary,
    "chunks": _cmd_heap_chunks,
    "at": _cmd_heap_at,
    "free-lists": _cmd_heap_free_lists,
    "roles": _cmd_heap_roles,
}


def _cmd_heap(args: argparse.Namespace) -> int:
    """Dispatch a ``heap <action>`` subcommand to its handler."""
    handler = _HEAP_HANDLERS.get(getattr(args, "heap_action", None))
    if handler is None:
        print("memdiver heap: pick an action: " + ", ".join(_HEAP_HANDLERS),
              file=sys.stderr)
        return 1
    return handler(args)
