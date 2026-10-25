"""Volatility 3 producers: plugin catalogue, describe, run, annotate, query.

The ``vol3.*`` capabilities (plan T2.2). Thin, surface-agnostic wrappers over
:mod:`memdiver.engine.vol3_runner` and the case data lake. Each returns a
:class:`ServiceResult` with a plain-JSON payload and RAISES a
:class:`CapabilityError` on bad input; Volatility 3 itself loads lazily (the
``memdiver[image]`` extra).

A run executed with ``case_dir`` is registered as the Parquet table
``vol3__<os>_<plugin>`` carrying the standard columns (``addr``/``size``/
``space`` are derived here from the plugin's address columns) so SQL and the
saved queries in :mod:`memdiver.analysis.queries` can join it with other runs.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from memdiver.app.tools_case import DEFAULT_QUERY_LIMIT, case_query_result
from memdiver.app.tools_image import _context_for, _read_descriptor, _tool_versions
from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

#: Plugins whose empty result means a wrong profile or paging, never "no processes".
PROCESS_LISTING_PLUGINS = frozenset({"linux.pslist.PsList", "linux.pstree.PsTree"})
#: Names of a plugin's process-filter list argument.
_PID_ARGUMENTS = ("pid", "pids")
DEFAULT_RUN_ROWS = 100_000
DEFAULT_RUN_TIMEOUT_S = 300.0
DEFAULT_MAX_ROWS = 1000
_ID_REPORT_CAP = 1000
logger = logging.getLogger("memdiver.app.tools_vol3")


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _runner() -> Any:
    from memdiver.engine import vol3_runner
    return vol3_runner


def _log_user_source(source: str) -> str:
    """Log (and return) the SHA-256 of user plugin source before it executes in-process."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    logger.warning("executing unsandboxed vol3 plugin source sha256=%s bytes=%d",
                   digest, len(source.encode("utf-8")))
    return digest


def _plugin_info(plugin: str, source: Optional[str]) -> Any:
    runner = _runner()
    if source is not None:
        _log_user_source(source)
        return runner.plugin_from_source(source)
    return runner.resolve_plugin(plugin)


def vol3_plugins_result(os_family: str = "linux") -> "ServiceResult":
    """The bundled plugins of one OS family with description and version."""
    plugins = [p.to_dict() for p in _runner().list_plugins(os_family)]
    return ServiceResult.ok({"os_family": os_family, "plugins": plugins,
                             "count": len(plugins)})


def vol3_describe_result(plugin: str, source: Optional[str] = None, *,
                         source_name: Optional[str] = None,
                         case_dir: Optional[str] = None) -> "ServiceResult":
    """A plugin's user requirements (a bundled plugin, ``source`` text or a stored ``source_name``)."""
    from memdiver.app.tools_vol3_sources import _resolve_source
    resolved = _resolve_source(source, source_name, case_dir)
    return ServiceResult.ok(_runner().describe_plugin(_plugin_info(plugin, resolved)))


# -- run -----------------------------------------------------------------------

def _pid_argument(info: Any) -> Optional[str]:
    """Name of the plugin's pid-list argument, or ``None`` when it has none."""
    for req in _runner().user_requirements(info.cls):
        if type(req).__name__ == "ListRequirement" and req.name in _PID_ARGUMENTS:
            return req.name
    return None


def _with_process_default(info: Any, args: Optional[Dict[str, Any]],
                          descriptor: Any) -> "tuple[Dict[str, Any], Dict[str, Any]]":
    """Scope a process view's run to its pid unless the caller chose a filter."""
    final: Dict[str, Any] = dict(args or {})
    applied: Dict[str, Any] = {}
    argument = _pid_argument(info)
    if descriptor.pid is None or argument is None:
        return final, applied
    if any(final.get(name) not in (None, []) for name in _PID_ARGUMENTS):
        return final, applied
    final[argument] = [descriptor.pid]
    applied[argument] = [descriptor.pid]
    return final, applied


#: Plugin -> {address column: kernel type the column points at}. Only where the vol3
#: 2.27 plugin source makes it certain: pslist/pstree/psscan list ``task_struct``
#: objects (``OFFSET (V)`` virtual, psscan's ``OFFSET (P)`` physical, both the task's
#: own address) and lsmod lists ``module`` objects (``Offset`` = ``module.vol.offset``).
OBJECT_TYPE_COLUMNS: Dict[str, Dict[str, str]] = {
    "linux.pslist.PsList": {"OFFSET (V)": "task_struct"},
    "linux.pstree.PsTree": {"OFFSET (V)": "task_struct"},
    "linux.psscan.PsScan": {"OFFSET (P)": "task_struct"},
    "linux.lsmod.Lsmod": {"Offset": "module"},
}


def _object_sizes(image_ctx: Any, plugin: str) -> Dict[str, Dict[str, Any]]:
    """``{column: {"object_type", "object_size"}}`` for a known plugin, else ``{}``.

    A type the profile lacks is left out (the column then keeps a null ``size``).
    """
    found: Dict[str, Dict[str, Any]] = {}
    for column, type_name in OBJECT_TYPE_COLUMNS.get(plugin, {}).items():
        try:
            with image_ctx.lock:
                size = int(image_ctx.kernel.get_type(type_name).size)
        except Exception:                      # noqa: BLE001 - profile without the type
            logger.debug("no %s in the profile for %s", type_name, plugin)
            continue
        found[column] = {"object_type": type_name, "object_size": size}
    return found


def _as_ints(values: Sequence[Any]) -> List[Optional[int]]:
    return [None if v is None else int(v) & 0xFFFF_FFFF_FFFF_FFFF for v in values]


def _span_columns(result: Any) -> "tuple[Optional[str], Optional[str]]":
    """Names of ``Start``/``End`` when both are address columns in one space."""
    spaces = result.location_columns()
    if "Start" in spaces and "End" in spaces and spaces["Start"] == spaces["End"]:
        return "Start", "End"
    return None, None


def _standard_address_columns(result: Any, table: Any,
                              object_sizes: Optional[Dict[str, Dict[str, Any]]] = None) -> Any:
    """Add ``addr``/``size``/``space`` to the Arrow table from the address columns."""
    import pyarrow as pa

    from memdiver.analysis.case import snake_case_columns

    spaces = result.location_columns()
    if not spaces:
        return table
    taken = set(snake_case_columns(table.column_names))
    start, end = _span_columns(result)
    anchor = start or next(iter(spaces))
    addr = _as_ints(table.column(anchor).to_pylist())
    size: List[Optional[int]] = [None] * len(addr)
    if end:
        ends = _as_ints(table.column(end).to_pylist())
        size = [e - a if a is not None and e is not None and e >= a else None
                for a, e in zip(addr, ends)]
    elif object_sizes and anchor in object_sizes:
        object_size = object_sizes[anchor]["object_size"]
        size = [None if a is None else object_size for a in addr]
    space = [spaces[anchor] if a is not None else None for a in addr]
    additions = {"addr": pa.array(addr, pa.uint64()), "size": pa.array(size, pa.uint64()),
                 "space": pa.array(space, pa.string())}
    for name, column in additions.items():
        if name not in taken:
            table = table.append_column(name, column)
    return table


def _precondition(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.PRECONDITION, code=code)


def _check_listing_not_empty(result: Any) -> None:
    if result.row_count == 0 and result.plugin in PROCESS_LISTING_PLUGINS:
        if result.truncated or result.stop_reason:
            raise _precondition(
                f"{result.plugin} stopped early with 0 rows "
                f"(stop_reason={result.stop_reason!r}): raise timeout_s/max_rows and "
                "re-run before judging the profile or paging", "vol3.run_stopped_early")
        raise _precondition(
            f"{result.plugin} returned 0 rows: the profile or paging of this view is "
            "wrong (a live kernel always has tasks); check the ISF and 5-level paging",
            "vol3.empty_process_list")


def _register_run(case_dir: str, result: Any, descriptor: Any, view: Path,
                  args: Dict[str, Any],
                  object_sizes: Optional[Dict[str, Dict[str, Any]]] = None) -> Any:
    from memdiver.analysis.case import Case

    from memdiver.app.tools_case import _open
    case: Case = _open(case_dir)
    table = _standard_address_columns(result, result.to_arrow(), object_sizes)
    meta = {"plugin": result.plugin, "args": args, "truncated": result.truncated,
            "stop_reason": result.stop_reason, "elapsed_s": round(result.elapsed_s, 3),
            "view_path": str(view), "vol3_version": _tool_versions()["volatility3"]}
    return case.register_table(
        _runner().table_name(result.plugin), table, capture_id=result.capture_id,
        image_sha256=descriptor.image_sha256, producer="vol3",
        file_stem=result.plugin, locations=result.location_columns(), meta=meta)


def vol3_run_result(view_path: str, plugin: str, args: Optional[Dict[str, Any]] = None, *,
                    case_dir: Optional[str] = None, limit: int = DEFAULT_RUN_ROWS,
                    timeout_s: float = DEFAULT_RUN_TIMEOUT_S,
                    max_rows: int = DEFAULT_MAX_ROWS,
                    column_map: Optional[Dict[str, Optional[str]]] = None,
                    source: Optional[str] = None, out_dir: Optional[str] = None,
                    progress: Optional[Callable[[float, str], None]] = None,
                    source_name: Optional[str] = None) -> "ServiceResult":
    """Run a plugin over a ``.mdview``; register the table when ``case_dir`` is given.

    A user plugin is raw ``source`` text or a ``source_name`` stored in ``case_dir``.
    """
    from memdiver.analysis.capture_id import capture_id_for
    from memdiver.app.tools_vol3_sources import _resolve_source

    info = _plugin_info(plugin, _resolve_source(source, source_name, case_dir))
    path, descriptor = _read_descriptor(view_path)
    final_args, defaults = _with_process_default(info, args, descriptor)
    image_ctx = _context_for(descriptor, path)
    result = _runner().run_plugin(
        image_ctx, info, final_args, limit=limit, timeout_s=timeout_s,
        column_overrides=column_map, capture_id=capture_id_for(path),
        out_dir=Path(out_dir).expanduser() if out_dir else None, progress=progress)
    _check_listing_not_empty(result)
    payload = result.to_dict(max_rows)
    sizes = _object_sizes(image_ctx, result.plugin)
    for column in payload["columns"]:
        column.update(sizes.get(column["name"], {}))
    from memdiver.app.image_preview import view_block
    payload.update({"defaults_applied": defaults, "args": final_args,
                    "table": None, "run_id": None, "view": view_block(descriptor, path)})
    if case_dir:
        ref = _register_run(case_dir, result, descriptor, path, final_args, sizes)
        payload.update({"table": ref.to_dict(), "run_id": ref.run_id})
    return ServiceResult.ok(payload)


# -- annotate ------------------------------------------------------------------

def _run_ref(case: Any, table: str, run_id: str) -> Any:
    for ref in case.runs(table):
        if ref.run_id == run_id:
            return ref
    raise CapabilityError(f"no run {run_id!r} of table {table!r}",
                          category=ErrorCategory.NOT_FOUND, code="vol3.run_not_found")


def _row_location(row: Dict[str, Any], column: str, space: str) -> Optional[Location]:
    """The :class:`Location` of one stored row cell; ``None`` when it is absent."""
    value = row.get(column)
    if value is None:
        return None
    kind = AddressSpace(space)
    pid = row.get("pid") if kind is AddressSpace.PROCESS_VA else None
    if kind is AddressSpace.PROCESS_VA and pid is None:
        return None
    try:
        return Location(kind, int(value), capture_id=row.get("capture_id"), pid=pid)
    except (TypeError, ValueError):
        return None


def _plugin_of(path: str) -> str:
    import json

    import pyarrow.parquet as pq
    raw = (pq.read_schema(path).metadata or {}).get(b"memdiver.meta", b"{}")
    return str(json.loads(raw).get("meta", {}).get("plugin", ""))


def _entry_for(row: Dict[str, Any], column: str, location: Location, plugin: str,
               label_column: Optional[str], author: str, run_id: str) -> Any:
    from memdiver.analysis.case import _json_safe
    from memdiver.analysis.record import PLUGIN_ROW, AnalysisEntry, Support

    label = (str(row[label_column]) if label_column and row.get(label_column) is not None
             else f"{plugin} {column}")
    return AnalysisEntry(
        capture_id=row["capture_id"], kind=PLUGIN_ROW, author=author, locations=(location,),
        label=label, support=(Support("vol3_run", run_id),),
        payload={"plugin": plugin, "column": column, "run_id": run_id,
                 "row": {k: _json_safe(v) for k, v in row.items()}})


def _selected_rows(all_rows: List[Dict[str, Any]], rows: Optional[Sequence[int]]) -> List[int]:
    if rows is None:
        return list(range(len(all_rows)))
    bad = [i for i in rows if not 0 <= i < len(all_rows)]
    if bad:
        raise _invalid(f"row index out of range: {bad[:5]} (table has {len(all_rows)} rows)",
                       "vol3.bad_row")
    return list(rows)


def vol3_annotate_result(case_dir: str, table: str, run_id: str, column: str, *,
                         rows: Optional[Sequence[int]] = None,
                         label_column: Optional[str] = None,
                         author: str = "tool:vol3") -> "ServiceResult":
    """File one ``plugin_row`` entry per row of a registered run whose ``column`` is set."""
    import pyarrow.parquet as pq

    from memdiver.analysis.record_store import AnalysisRecord
    from memdiver.app.tools_case import _open
    case = _open(case_dir)
    ref = _run_ref(case, table, run_id)
    if column not in ref.locations:
        raise _invalid(f"column {column!r} is not a location column of {table}; "
                       f"choose one of: {', '.join(ref.locations) or 'none'}", "vol3.bad_column")
    data = pq.read_table(ref.path).to_pylist()
    plugin, record = _plugin_of(ref.path), AnalysisRecord(case.dir)
    ids: List[str] = []
    skipped: List[int] = []
    for index in _selected_rows(data, rows):
        location = _row_location(data[index], column, ref.locations[column])
        if location is None:
            skipped.append(index)
            continue
        entry = _entry_for(data[index], column, location, plugin, label_column, author, run_id)
        ids.append(record.append(entry).id)
    return ServiceResult.ok({"created": len(ids), "entry_ids": ids[:_ID_REPORT_CAP],
                             "skipped": skipped[:_ID_REPORT_CAP],
                             "skipped_count": len(skipped), "run_id": run_id})


# -- query ---------------------------------------------------------------------

def _truncation_warnings(case_dir: str, sql: str) -> List[str]:
    """One warning per truncated run of a case table whose name appears in ``sql``."""
    from memdiver.analysis.queries import truncated_runs
    from memdiver.app.tools_case import _open

    case = _open(case_dir)
    mentioned = [t for t in case.tables() if t in sql]
    return [f"table {r['table']} run {r['run_id']} is truncated "
            f"(stop_reason={r['stop_reason']!r}): results may be incomplete"
            for r in truncated_runs(mentioned, case)]


def vol3_query_result(case_dir: str, sql: Optional[str] = None, saved: Optional[str] = None,
                      params: Optional[Sequence[Any]] = None,
                      limit: int = DEFAULT_QUERY_LIMIT) -> "ServiceResult":
    """Run raw SQL or a built-in saved query; with neither, list the saved queries."""
    if sql and saved:
        raise _invalid("give exactly one of sql or saved (or neither to list "
                       "the saved queries)", "vol3.query_source")
    if not sql and not saved:
        from memdiver.analysis.queries import saved_queries
        listing = [q.to_dict() for q in saved_queries().values()]
        return ServiceResult.ok({"saved_queries": listing, "count": len(listing)})
    if sql:
        result = case_query_result(case_dir, sql, limit=limit, params=params)
        return ServiceResult.ok({**result.payload,
                                 "warnings": _truncation_warnings(case_dir, sql)})
    from memdiver.analysis.queries import (get_saved_query, require_complete_runs,
                                           require_tables)
    from memdiver.app.tools_case import _open
    query = get_saved_query(str(saved))
    case = _open(case_dir)
    require_tables(query, case.tables())
    require_complete_runs(query, case)
    result = case_query_result(case_dir, query.sql, limit=limit, params=params)
    return ServiceResult.ok({**result.payload, "saved": query.name,
                             "description": query.description})
