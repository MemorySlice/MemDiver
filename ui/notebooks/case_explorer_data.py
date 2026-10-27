"""Pure data helpers behind the case-explorer notebook (no marimo import).

Kept out of the template so they can be unit-tested and reused. Nothing here
fabricates data: a missing table, view or byte comes back as an explicit
message or an absent marker, never an exception or a zero.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PSLIST_TABLE = "vol3__linux_pslist"
PSLIST_ROW_LIMIT = 100_000   # query cap; hitting it must be shown, never hidden
HEX_ABSENT = "--"
MAX_HEX_BYTES = 256


def case_arg(cli_args: Any) -> Optional[str]:
    """The case from ``--case`` on the command line, else ``$MEMDIVER_CASE``."""
    value = None
    try:
        value = cli_args.get("case")
    except AttributeError:
        pass
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value or os.environ.get("MEMDIVER_CASE") or None


def table_rows(case: Any) -> List[Dict[str, Any]]:
    """One row per (table, run) with its row count."""
    rows: List[Dict[str, Any]] = []
    for name in case.tables():
        for ref in case.runs(name):
            rows.append({"table": name, "run_id": ref.run_id, "rows": ref.row_count})
    return rows


def latest_run_id(case: Any, table: str) -> Optional[str]:
    """The newest run of ``table`` (run ids sort by UTC timestamp), or ``None``."""
    ids = sorted(ref.run_id for ref in case.runs(table))
    return ids[-1] if ids else None


def process_tree(case: Any) -> Dict[str, Any]:
    """Process tree of the newest pslist run.

    Returns ``{"message", "run_id", "nodes", "roots", "truncated"}`` (``truncated``: the
    row cap was hit, so the tree is partial). ``nodes`` maps pid to
    ``{pid, ppid, comm, offset_v, capture_id, children}``; ``roots`` are the pids
    whose parent is not itself in the run. A missing table gives a ``message``.
    """
    if PSLIST_TABLE not in case.tables():
        return {"message": f"This case has no {PSLIST_TABLE} table. Run the "
                           "linux.pslist plugin into the case to get a process tree.",
                "run_id": None, "nodes": {}, "roots": [], "truncated": False}
    run_id = latest_run_id(case, PSLIST_TABLE)
    result = case.query(
        f'SELECT pid, ppid, comm, offset_v, capture_id FROM "{PSLIST_TABLE}" '  # nosec B608 - constant table, bound run_id
        "WHERE run_id = ? ORDER BY pid", params=[run_id], limit=PSLIST_ROW_LIMIT)
    payload = result.to_dict()
    rows = payload["rows"]
    nodes = {r[0]: {"pid": r[0], "ppid": r[1], "comm": r[2], "offset_v": r[3],
                    "capture_id": r[4], "children": []}
             for r in rows}
    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        if parent is not None and node["ppid"] != pid:
            parent["children"].append(pid)
        else:
            roots.append(pid)
    return {"message": None, "run_id": run_id, "nodes": nodes, "roots": roots,
            "truncated": bool(payload["truncated"])}


def tree_lines(tree: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The tree flattened depth-first into ``{process, pid, ppid, offset_v}`` rows."""
    out: List[Dict[str, Any]] = []
    seen: set = set()

    def walk(pid: int, depth: int) -> None:
        if pid in seen:
            return
        seen.add(pid)
        node = tree["nodes"][pid]
        out.append({"process": "    " * depth + str(node["comm"]), "pid": pid,
                    "ppid": node["ppid"], "offset_v": hex(node["offset_v"])})
        for child in node["children"]:
            walk(child, depth + 1)

    for root in tree["roots"]:
        walk(root, 0)
    return out


def kernel_view_paths(case_dir: Path) -> List[Path]:
    """The case's ``.mdview`` descriptors whose name says kernel, then the rest."""
    views = sorted((Path(case_dir) / "views").glob("*.mdview"))
    return sorted(views, key=lambda p: "kernel" not in p.name)


def hexdump(data: bytes, present: Sequence[bool], start: int, width: int = 16) -> str:
    """Hexdump where bytes that were not captured print as ``--``, never ``00``."""
    lines = []
    for off in range(0, len(data), width):
        chunk, flags = data[off:off + width], present[off:off + width]
        hexes = " ".join(f"{b:02x}" if ok else HEX_ABSENT for b, ok in zip(chunk, flags))
        text = "".join(chr(b) if ok and 32 <= b < 127 else ("." if ok else " ")
                       for b, ok in zip(chunk, flags))
        lines.append(f"{start + off:016x}  {hexes:<{width * 3 - 1}}  |{text}|")
    return "\n".join(lines)


def read_hex(view_path: Path, address: int, length: int = MAX_HEX_BYTES) -> Dict[str, Any]:
    """Read up to ``length`` bytes at ``address`` from a ``.mdview`` and dump them."""
    from memdiver.core.dump_source import open_dump

    length = max(1, min(int(length), MAX_HEX_BYTES))
    with open_dump(Path(view_path)) as source:   # open_dump returns it UNOPENED
        result = source.read_location(address, length)
    present = [False] * length
    for start, chunk in result.segments():
        base = start - address
        present[base:base + len(chunk)] = [True] * len(chunk)
    return {"captured": result.coverage.captured, "requested": length,
            "dump": hexdump(result.data, present, address)}


def context_for_row(case_dir: Path, node: Dict[str, Any], view: Optional[Path]) -> Dict[str, Any]:
    """Case context rows at a pslist row's kernel address, plus its hexdump."""
    from memdiver.app.tools_case import context_at_result

    location = {"space": "kernel_va", "value": node["offset_v"],
                "capture_id": node["capture_id"]}
    envelope = context_at_result(str(case_dir), location, length=1,
                                 dump_path=str(view) if view else None)
    layers = envelope.payload.get("layers", [])
    hex_part = (read_hex(view, node["offset_v"]) if view
                else {"dump": "No .mdview kernel view in this case; bytes are absent."})
    return {"layers": [{"table": l["name"], "run": l["ref"], "start": hex(l["start"]),
                        "end": hex(l["end"])} for l in layers], **hex_part}
