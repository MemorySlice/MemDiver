"""Try an ISF (draft) against the image it describes and say what is wrong (plan T4.4).

One try = build a fresh vol3 context with the ISF, run a plugin (``linux.pslist``
by default), compare the rows with a ground truth, and name the symbols / types /
fields the outcome implicates.

Why the comparison is the point: on real data (arista-eos, 2026-10-25) wrong
offsets are mostly SILENT. ``task_struct.tasks`` +8 gives 0 rows, −8 gives 19
garbage rows, ``tgid`` −4 gives 122/123 correct rows, ``real_parent`` +8 gives
identical rows. Only ``comm`` is caught by the context's own self-test. So "rows
came back" is never a verdict; a try without a ground truth is ``unverified``.

Ground truths understood: vol3's text pslist output (``OFFSET (V)  PID  TID  PPID
COMM …``; offsets may be de-canonicalized) and ``ps -ef`` (``UID PID PPID … CMD``).
``ps`` ran before the dump, so its own process is missing from the image and the
acquisition tool is extra: the verdict tolerates that through recall/precision
thresholds and compares ``comm`` only for bracketed kernel threads (a ``ps`` CMD
is a command line, not a ``comm``; procps appends ``-<workqueue>`` to a kworker's
name, so a ps name matches when it equals the ``comm`` or starts with ``<comm>-``).

The build always uses a fresh, uncached context: a draft changes between tries,
and a failed build must not leave anything behind in the shared cache.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Verdicts, strongest first.
PASS, PARTIAL, FAIL, UNVERIFIED, ERROR = "pass", "partial", "fail", "unverified", "error"

#: Which draft entries a wrong pslist column points at (vol3 2.27 ``linux.pslist``).
PSLIST_COLUMN_FIELDS: Dict[str, Tuple[str, ...]] = {
    "PID": ("task_struct.tgid",),
    "TID": ("task_struct.pid",),
    "PPID": ("task_struct.real_parent", "task_struct.tgid"),
    "COMM": ("task_struct.comm",),
    "OFFSET (V)": ("task_struct.tasks", "list_head.next", "symbol:init_task"),
    "UID": ("task_struct.cred", "cred.uid", "kuid_t.val"),
    "GID": ("task_struct.cred", "cred.gid", "kgid_t.val"),
    "EUID": ("task_struct.cred", "cred.euid", "kuid_t.val"),
    "EGID": ("task_struct.cred", "cred.egid", "kgid_t.val"),
}
#: What an empty or mostly missing task list points at.
TASK_LIST_FIELDS: Tuple[str, ...] = ("task_struct.tasks", "list_head.next", "symbol:init_task")

_COMM_LEN = 15  # TASK_COMM_LEN - 1

# vol3 / ImageContext failure messages -> implicated draft entries.
_ERROR_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"Symbol type not in \S+ SymbolTable: ([\w ]+)"), "type:{0}"),
    (re.compile(r"Unknown symbol:? ?'?([\w.]+)'?"), "symbol:{0}"),
    (re.compile(r"[Ss]ymbol (?:not found|missing)[^\w]*'?([\w.]+)"), "symbol:{0}"),
    (re.compile(r"has no attribute:? '?(?:\w+!)?(\w+)\.(\w+)'?"), "{0}.{1}"),
    (re.compile(r"Type ([\w ]+) not found"), "type:{0}"),
    (re.compile(r"init_task reads"), "task_struct.comm"),
)
#: Only when nothing more specific matched: the self-test could not read the
#: kernel back at any depth, and no field-level reason was given.
_PAGING_FAILURE = re.compile(r"no paging depth reads the kernel back")


@dataclass(frozen=True)
class GroundTruthTask:
    pid: int
    ppid: int
    comm: Optional[str] = None      # None: not comparable (a ps command line)
    tid: Optional[int] = None
    offset: Optional[int] = None    # kernel VA as written (maybe de-canonical)


@dataclass(frozen=True)
class GroundTruth:
    source: str                     # "vol3_pslist" | "ps"
    path: str
    tasks: Tuple[GroundTruthTask, ...]
    skipped_rows: int = 0           # data rows that could not be parsed

    @property
    def hard_columns(self) -> Tuple[str, ...]:
        if self.source == "vol3_pslist":
            return ("PID", "TID", "PPID", "COMM", "OFFSET (V)")
        return ("PID", "PPID", "COMM")


def _invalid_truth(message: str, code: str = "isf.ground_truth_invalid") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _split_cells(line: str) -> List[str]:
    """vol3 text is tab- OR multi-space-aligned: tabs if any, else split on 2+ spaces."""
    if "\t" in line:
        return [c.strip() for c in line.split("\t")]
    return [c.strip() for c in re.split(r"\s{2,}", line.strip())]


def parse_ground_truth(path: Path) -> GroundTruth:
    """Parse a vol3 pslist text dump or a ``ps -ef`` listing (format sniffed).

    Unusable input raises ``CapabilityError`` (``isf.ground_truth_invalid``, or
    ``isf.ground_truth_empty`` when no task could be parsed); rows that cannot be
    parsed are skipped and counted in ``skipped_rows``.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise _invalid_truth(f"{path}: cannot read ground truth: {exc}") from exc
    truth = _sniff_truth(path, lines)
    if not truth.tasks:
        raise _invalid_truth(f"{path}: ground truth holds no parseable task "
                             f"({truth.skipped_rows} rows skipped)", "isf.ground_truth_empty")
    return truth


def _sniff_truth(path: Path, lines: Sequence[str]) -> GroundTruth:
    for i, line in enumerate(lines):
        if line.startswith("OFFSET (V)") and "PID" in line:
            tasks, skipped = _parse_vol3(line, lines[i + 1:])
            return GroundTruth("vol3_pslist", str(path), tasks, skipped)
        cols = line.split()
        if cols[:1] == ["UID"] and "PID" in cols and "PPID" in cols and cols[-1] == "CMD":
            tasks, skipped = _parse_ps(cols, lines[i + 1:])
            return GroundTruth("ps", str(path), tasks, skipped)
    raise _invalid_truth(f"{path}: neither a vol3 pslist nor a 'ps -ef' listing")


def _parse_vol3(header: str, body: Sequence[str]) -> Tuple[Tuple[GroundTruthTask, ...], int]:
    names = _split_cells(header)
    wanted = ("OFFSET (V)", "PID", "TID", "PPID", "COMM")
    missing = [n for n in wanted if n not in names]
    if missing:
        raise _invalid_truth(f"vol3 pslist header lacks column(s) {missing}: {names}")
    idx = {n: names.index(n) for n in wanted}
    tasks: List[GroundTruthTask] = []
    skipped = 0
    for line in body:
        if not line.strip():
            continue
        cells = _split_cells(line)
        try:
            if len(cells) < len(names):
                raise ValueError("short row")
            tasks.append(GroundTruthTask(
                pid=int(cells[idx["PID"]]), ppid=int(cells[idx["PPID"]]),
                comm=cells[idx["COMM"]], tid=int(cells[idx["TID"]]),
                offset=int(cells[idx["OFFSET (V)"]], 16)))
        except ValueError:
            skipped += 1
    return tuple(tasks), skipped


def _parse_ps(header: Sequence[str], body: Sequence[str]) -> Tuple[Tuple[GroundTruthTask, ...], int]:
    pid_i, ppid_i, cmd_i = header.index("PID"), header.index("PPID"), len(header) - 1
    tasks: List[GroundTruthTask] = []
    skipped = 0
    for line in body:
        if not line.strip():
            continue
        cells = line.split(None, cmd_i)
        try:
            if len(cells) <= cmd_i:
                raise ValueError("short row")
            pid, ppid = int(cells[pid_i]), int(cells[ppid_i])
        except ValueError:
            skipped += 1
            continue
        cmd = cells[cmd_i].strip()
        comm = cmd[1:-1][:_COMM_LEN] if cmd.startswith("[") and cmd.endswith("]") else None
        tasks.append(GroundTruthTask(pid=pid, ppid=ppid, comm=comm))
    return tuple(tasks), skipped


def canonical(address: int, va_bits: int) -> int:
    """Sign-extend a (possibly masked) kernel VA from bit ``va_bits - 1``."""
    address &= (1 << 64) - 1
    if address >> (va_bits - 1) & 1:
        return address | (((1 << 64) - 1) ^ ((1 << va_bits) - 1))
    return address


@dataclass
class Comparison:
    matched: int = 0
    missing: List[int] = field(default_factory=list)     # GT pids not in the rows
    extra: List[int] = field(default_factory=list)       # row pids not in the GT
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    duplicates: List[int] = field(default_factory=list)  # pid seen twice in the rows
    expected: int = 0
    returned: int = 0

    @property
    def recall(self) -> float:
        return self.matched / self.expected if self.expected else 0.0

    @property
    def precision(self) -> float:
        return self.matched / self.returned if self.returned else 0.0

    def to_dict(self, limit: int = 50) -> Dict[str, Any]:
        return {"expected": self.expected, "returned": self.returned, "matched": self.matched,
                "recall": round(self.recall, 4), "precision": round(self.precision, 4),
                "missing": self.missing[:limit], "extra": self.extra[:limit],
                "duplicates": self.duplicates[:limit],
                "mismatches": self.mismatches[:limit], "mismatch_count": len(self.mismatches),
                "truncated": any(len(x) > limit for x in (self.missing, self.extra,
                                                          self.mismatches, self.duplicates))}


def compare_pslist(columns: Sequence[str], rows: Sequence[Sequence[Any]], truth: GroundTruth,
                   va_bits: int) -> Comparison:
    """Match rows to the ground truth, then compare the hard columns.

    Rows are keyed by the task's kernel address when the ground truth has one
    (vol3 output): then a wrong ``tgid`` shows up as a PID mismatch on the right
    task instead of as a missing task. Otherwise (``ps``) they are keyed by PID.
    Reported pids (missing/extra/duplicates/mismatches) are ground-truth pids
    where a ground-truth task is involved.
    """
    col = {name: i for i, name in enumerate(columns)}
    by_offset = truth.source == "vol3_pslist" and "OFFSET (V)" in col and all(
        t.offset is not None for t in truth.tasks)
    key_column = "OFFSET (V)" if by_offset else "PID"

    def key_of_row(row: Sequence[Any]) -> Any:
        value = row[col[key_column]]
        return canonical(value, va_bits) if by_offset and isinstance(value, int) else value

    def key_of_task(task: GroundTruthTask) -> Any:
        return canonical(task.offset, va_bits) if by_offset else task.pid

    by_key: Dict[Any, Sequence[Any]] = {}
    out = Comparison(expected=len(truth.tasks))
    for row in rows:
        key = key_of_row(row)
        if not isinstance(key, int):
            continue
        out.returned += 1
        if key in by_key:
            out.duplicates.append(row[col["PID"]])
        by_key[key] = row
    for task in truth.tasks:
        row = by_key.get(key_of_task(task))
        if row is None:
            out.missing.append(task.pid)
            continue
        out.matched += 1
        for column, expected, got in _pairs(task, row, col, truth, va_bits):
            if expected is not None and not _same(column, expected, got, truth.source):
                out.mismatches.append({"pid": task.pid, "column": column,
                                       "expected": _show(expected), "got": _show(got)})
    known = {key_of_task(t) for t in truth.tasks}
    out.extra = sorted(row[col["PID"]] for key, row in by_key.items()
                       if key not in known and isinstance(row[col["PID"]], int))
    return out


def _pairs(task: GroundTruthTask, row: Sequence[Any], col: Dict[str, int],
           truth: GroundTruth, va_bits: int) -> List[Tuple[str, Any, Any]]:
    def cell(name: str) -> Any:
        return row[col[name]] if name in col else None
    pairs: List[Tuple[str, Any, Any]] = [("PID", task.pid, cell("PID")),
                                         ("PPID", task.ppid, cell("PPID"))]
    if task.comm is not None:
        got = cell("COMM")
        pairs.append(("COMM", task.comm[:_COMM_LEN],
                      got[:_COMM_LEN] if isinstance(got, str) else got))
    if truth.source == "vol3_pslist":
        pairs.append(("TID", task.tid, cell("TID")))
        if task.offset is not None:
            got = cell("OFFSET (V)")
            pairs.append(("OFFSET (V)", canonical(task.offset, va_bits),
                          canonical(got, va_bits) if isinstance(got, int) else got))
    return pairs


def _same(column: str, expected: Any, got: Any, source: str) -> bool:
    if expected == got:
        return True
    return (source == "ps" and column == "COMM" and isinstance(got, str) and bool(got)
            and expected.startswith(got + "-"))


def _show(value: Any) -> Any:
    return hex(value) if isinstance(value, int) and value > 0xFFFFFFFF else value


def implicated_by_error(message: str) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    for pattern, template in _ERROR_PATTERNS:
        for match in pattern.finditer(message):
            item = template.format(*(g.strip() for g in match.groups()))
            if all(f["item"] != item for f in found):
                found.append({"item": item, "reason": match.group(0)[:200]})
    if not found and _PAGING_FAILURE.search(message):
        found.append({"item": "symbol:init_top_pgt", "reason": _PAGING_FAILURE.pattern})
    return found


_REQUIRED_TYPE = re.compile(r"""\bself\.set_type_class\(\s*["'](\w+)["']""")
_TYPE_NOT_IN_TABLE = re.compile(r"Symbol type not in \S+ SymbolTable")


def vol3_required_types() -> Tuple[str, ...]:
    """Types vol3's Linux symbol table refuses to load without (``set_type_class``,
    not ``optional_set_type_class``), read from the installed vol3's own source so
    the list follows the vol3 version. Empty if vol3 cannot be inspected."""
    import inspect
    try:
        from volatility3.framework.symbols.linux import LinuxKernelIntermedSymbols
        source = inspect.getsource(LinuxKernelIntermedSymbols.__init__)
    except (ImportError, OSError, TypeError):
        return ()
    return tuple(dict.fromkeys(_REQUIRED_TYPE.findall(source)))


def missing_required_types(isf_path: Path) -> List[Dict[str, str]]:
    """All vol3-required types absent from an ISF (vol3 itself names only the first)."""
    import json
    try:
        with open(isf_path, encoding="utf-8") as handle:
            present = set((json.load(handle).get("user_types") or {}))
    except (OSError, ValueError):
        return []
    return [{"item": f"type:{name}", "reason": "required by vol3 LinuxKernelIntermedSymbols "
             "(set_type_class); a field-less stub is enough to load"}
            for name in vol3_required_types() if name not in present]


def implicated_by_comparison(cmp: Comparison) -> List[Dict[str, str]]:
    found: Dict[str, str] = {}
    if cmp.returned == 0 or cmp.recall < 0.5:
        for item in TASK_LIST_FIELDS:
            found.setdefault(item, f"task list walk returned {cmp.returned} rows "
                                   f"({cmp.matched}/{cmp.expected} expected pids)")
    per_column: Dict[str, int] = {}
    for m in cmp.mismatches:
        per_column[m["column"]] = per_column.get(m["column"], 0) + 1
    for column, count in sorted(per_column.items(), key=lambda kv: -kv[1]):
        for item in PSLIST_COLUMN_FIELDS.get(column, ()):
            found.setdefault(item, f"{count} rows disagree on {column}")
    return [{"item": k, "reason": v} for k, v in found.items()]


def verdict_of(cmp: Comparison, *, min_recall: float, min_precision: float) -> str:
    if cmp.returned == 0 or cmp.recall < 0.5:
        return FAIL
    if not cmp.mismatches and not cmp.duplicates and cmp.recall >= min_recall \
            and cmp.precision >= min_precision:
        return PASS
    return PARTIAL


def try_isf(image_path: Path, isf_path: Path, *, plugin: str = "linux.pslist",
            args: Optional[Dict[str, Any]] = None, ground_truth: Optional[Path] = None,
            timeout_s: float = 120.0, limit: int = 100_000, min_recall: float = 0.95,
            min_precision: float = 0.95, capture_id: Optional[str] = None) -> Dict[str, Any]:
    """Build, run, compare. Never raises for a bad ISF: the failure is the answer."""
    from memdiver.core.image.context import ImageContext
    from memdiver.engine.vol3_runner import resolve_plugin, run_plugin
    result: Dict[str, Any] = {"plugin": plugin, "isf": str(isf_path), "stage": "build",
                              "verdict": ERROR, "implicated": [], "elapsed_s": {}}
    truth = parse_ground_truth(ground_truth) if ground_truth else None
    if truth is not None:
        result["ground_truth"] = {"source": truth.source, "path": truth.path,
                                  "tasks": len(truth.tasks),
                                  "skipped_rows": truth.skipped_rows}
    started = time.monotonic()
    try:
        image_ctx = ImageContext.build(Path(image_path), Path(isf_path))
    except Exception as exc:  # noqa: BLE001 - a broken draft fails here; report it
        failed = _failed(result, "build", exc, started)
        if _TYPE_NOT_IN_TABLE.search(failed.get("error", "")):
            known = {i["item"] for i in failed["implicated"]}
            failed["implicated"] += [i for i in missing_required_types(Path(isf_path))
                                     if i["item"] not in known]
        return failed
    result["elapsed_s"]["build"] = round(time.monotonic() - started, 3)
    result["paging"] = image_ctx.kernel_paging.to_dict()
    result["stage"] = "run"
    started = time.monotonic()
    try:
        run = run_plugin(image_ctx, resolve_plugin(plugin), args, limit=limit,
                         timeout_s=timeout_s, capture_id=capture_id)
    except Exception as exc:  # noqa: BLE001 - vol3 SymbolError / AttributeError / ...
        return _failed(result, "run", exc, started)
    result["elapsed_s"]["run"] = round(time.monotonic() - started, 3)
    result.update(rows=run.row_count, truncated=run.truncated, stop_reason=run.stop_reason,
                  diagnostics=run.diagnostics[:20])
    columns = [c.name for c in run.columns]
    result["sample"] = [dict(zip(columns, (_show(v) for v in r))) for r in run.rows[:5]]
    if truth is None or plugin != "linux.pslist":
        result.update(stage="done", verdict=UNVERIFIED if run.row_count else FAIL,
                      implicated=[] if run.row_count else
                      [{"item": i, "reason": "0 rows"} for i in TASK_LIST_FIELDS])
        return result
    cmp = compare_pslist(columns, run.rows, truth, image_ctx.kernel_paging.va_bits)
    verdict = verdict_of(cmp, min_recall=min_recall, min_precision=min_precision)
    if run.truncated and run.stop_reason == "timeout" and verdict == FAIL:
        # A run cut by the timeout says nothing about the draft: never blame a field.
        result.update(stage="run", verdict=ERROR, implicated=[], comparison=cmp.to_dict(),
                      error=f"run incomplete: timed out after {timeout_s:g}s with "
                            f"{cmp.matched}/{cmp.expected} expected pids")
        return result
    if run.truncated and verdict == PASS:
        verdict = PARTIAL  # a cut run never looks complete
    result.update(stage="done", verdict=verdict, comparison=cmp.to_dict(),
                  implicated=implicated_by_comparison(cmp))
    return result


def _failed(result: Dict[str, Any], stage: str, exc: BaseException,
            started: float) -> Dict[str, Any]:
    message = f"{type(exc).__name__}: {exc}"
    result["elapsed_s"][stage] = round(time.monotonic() - started, 3)
    result.update(stage=stage, verdict=ERROR, error=message[:2000],
                  implicated=implicated_by_error(message))
    return result
