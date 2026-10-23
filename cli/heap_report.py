"""Human-readable heap lines for the consensus-backed CLI commands.

The JSON payloads already carry the heap annotation verbatim (``heap`` /
``heap_status`` / per-region ``heap`` / per-hit ``heap``); these helpers render
the operator-facing summary that goes to STDERR, so a reader piping the JSON
onward still sees whether a candidate or a hit sits in a freed (residual) chunk.
"""

import sys
from typing import Any, Dict, Iterable, List, Optional

#: Shown hits/regions per command before the summary says "... and N more".
MAX_HEAP_LINES = 10


def _emit(line: str) -> None:
    print(f"memdiver: {line}", file=sys.stderr)


def consensus_heap_line(heap: Optional[Any]) -> Optional[str]:
    """One status line for a ``ConsensusHeap`` (``None`` when heap is off)."""
    if heap is None:
        return None
    report = heap.report or {}
    line = f"heap status={heap.status} allocator={report.get('allocator', '?')}"
    if heap.status == "ok":
        line += (f" chunks={report.get('chunk_count', len(heap.chunks))}"
                 f" runs={report.get('run_count', len(heap.runs))}")
    return line


def report_consensus_heap(heap: Optional[Any]) -> None:
    """Print the consensus heap status line, if there is one."""
    line = consensus_heap_line(heap)
    if line is not None:
        _emit(line)


def candidate_heap_lines(regions: Iterable[Dict[str, Any]]) -> List[str]:
    """Chunk column + ``residual`` marker for every heap-annotated region."""
    lines = []
    for region in regions:
        annotation = region.get("heap")
        chunk = (annotation or {}).get("chunk")
        if not chunk:
            continue
        marker = " residual" if annotation.get("residual") else ""
        lines.append(
            f"  rank={region.get('rank', '?')} offset=0x{region['offset']:x} "
            f"len={region['length']} chunk=0x{chunk['start']:x}"
            f"+0x{chunk['offset_in_chunk']:x} size={chunk['size']} "
            f"state={chunk['state']}{marker}")
    return lines


def report_candidate_heap(payload: Dict[str, Any]) -> None:
    """Heap status, masked count and per-candidate chunk lines (stderr)."""
    status = payload.get("heap_status")
    if status is None:
        return
    masked = (payload.get("stages") or {}).get("heap_masked")
    regions = payload.get("regions") or []
    residual = sum(1 for r in regions if (r.get("heap") or {}).get("residual"))
    line = f"heap status={status} residual={residual}/{len(regions)}"
    if masked is not None:
        line += f" heap_masked={masked}"
    _emit(line)
    _emit_capped(candidate_heap_lines(regions))


def locate_key_heap_lines(dumps: Iterable[Dict[str, Any]]) -> List[str]:
    """One line per located hit that sits inside a heap chunk."""
    from memdiver.engine.consensus_heap import FREED_STATE_VALUES

    lines = []
    for row in dumps:
        for offset, hit in zip(row.get("offsets") or [], row.get("heap") or []):
            if not hit:
                continue
            marker = " residual" if hit.get("state") in FREED_STATE_VALUES else ""
            lines.append(
                f"  {row.get('dump_path', '?')} 0x{offset:x} chunk=0x{hit['chunk_va']:x}"
                f"+0x{hit['offset_in_chunk']:x} size={hit['chunk_size']} "
                f"state={hit['state']} allocator={hit['allocator']}{marker}")
    return lines


def report_locate_key_heap(payload: Dict[str, Any]) -> None:
    """Chunk + ``residual`` lines for every heap-resident hit (stderr)."""
    _emit_capped(locate_key_heap_lines(payload.get("dumps") or []))


def _emit_capped(lines: List[str]) -> None:
    for line in lines[:MAX_HEAP_LINES]:
        print(line, file=sys.stderr)
    if len(lines) > MAX_HEAP_LINES:
        print(f"  ... and {len(lines) - MAX_HEAP_LINES} more", file=sys.stderr)
