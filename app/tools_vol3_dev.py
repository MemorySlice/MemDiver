"""Volatility 3 plugin-development producers: scaffold, check, write-config, import.

The ``vol3.*`` development capabilities (plan T2.2 / T2.6). Thin, surface-agnostic
wrappers over :mod:`memdiver.engine.vol3_runner` and :mod:`memdiver.analysis.case`
that return a :class:`ServiceResult` with a plain-JSON payload and RAISE a
:class:`CapabilityError` on bad input. Running plugins lives in ``app/tools_vol3``.

* :func:`vol3_scaffold_result` — source text of a new, loadable plugin.
* :func:`vol3_check_result` — does the source load, and which requirements stay
  unsatisfied against a view's context? A broken plugin is a *finding*
  (``ok: false`` with a line number), never an exception.
* :func:`vol3_write_config_result` — ``config.json`` that makes stock
  ``vol -c`` reproduce MemDiver's kernel stack outside MemDiver.
* :func:`vol3_import_parquet_result` — an external vol3 table (Parquet / CSV /
  vol3's JSON / JSONL renderer output) into a ``vol3__*`` case table.
* :func:`vol3_exec_result` — run a plugin by NAME under the stock ``vol``
  launcher (a subprocess), e.g. ``msl.info`` or a synthesized plugin.
"""

from __future__ import annotations

import json
import re
import time
import traceback
import uuid
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

from .tools_vol3_sources import SYNTHESIZED_HISTORY_DIR

#: Layer-class module prefix that stock ``vol`` cannot import on its own.
_MEMDIVER_LAYER_PREFIX = "memdiver."
#: File name of the shim plugin that makes ``vol`` import MemDiver's layer classes.
SHIM_FILE = "memdiver_layers.py"
_PLUGIN_SOURCE_NAME = "<emitted:"
_IMPORT_FORMATS = ("parquet", "csv", "jsonl", "json")
_CHILDREN_KEY = "__children"


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


# -- scaffold ---------------------------------------------------------------------

_SCAFFOLD_HEADER = Template('''\
"""$description"""
import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
$extra_imports
vollog = logging.getLogger(__name__)


class $class_name(interfaces.plugins.PluginInterface):
    """$description"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
$requirement_lines        ]
''')

_PER_PROCESS_IMPORTS = ("from volatility3.framework.objects import utility\n"
                        "from volatility3.plugins.linux import pslist\n")
_PER_PROCESS_REQUIREMENTS = '''\
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)),
            requirements.ListRequirement(
                name="pid", description="Process IDs to include (all if not specified)",
                element_type=int, optional=True),
'''

_PER_PROCESS_BODY = '''
    def _generator(self):
        pid_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task in pslist.PsList.list_tasks(
                self.context, self.config["kernel"], filter_func=pid_filter):
            yield (0, (format_hints.Hex(task.vol.offset), int(task.tgid),
                       utility.array_to_string(task.comm)))

    def run(self):
        return renderers.TreeGrid(
            [("OFFSET (V)", format_hints.Hex), ("PID", int), ("COMM", str)],
            self._generator())
'''

_KERNEL_ONLY_BODY = '''
    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        init_task = kernel.object_from_symbol("init_task")
        yield (0, (format_hints.Hex(init_task.vol.offset), int(init_task.tgid)))

    def run(self):
        return renderers.TreeGrid(
            [("OFFSET (V)", format_hints.Hex), ("PID", int)], self._generator())
'''


def _scaffold_class_name(name: str) -> str:
    from memdiver.architect.volatility3_exporter import _sanitize_class_name
    stripped = (name or "").strip()
    if stripped.isidentifier():
        return stripped[0].upper() + stripped[1:]
    return _sanitize_class_name(stripped)


def _scaffold_description(description: str, class_name: str) -> str:
    text = " ".join((description or "").split()).replace('"""', "'''").rstrip("\\")
    return text or f"{class_name} (MemDiver scaffold)."


def vol3_scaffold_result(name: str, *, os_family: str = "linux", description: str = "",
                         per_process: bool = True) -> "ServiceResult":
    """Source text of a new plugin: kernel module, optional ``pid`` filter, one TreeGrid."""
    if os_family != "linux":
        raise _invalid(f"scaffolds exist for os_family 'linux' only, not {os_family!r}",
                       "vol3.scaffold_os_unsupported")
    class_name = _scaffold_class_name(name)
    if not class_name.isidentifier():
        raise _invalid(f"cannot derive a class name from {name!r}", "vol3.scaffold_bad_name")
    header = _SCAFFOLD_HEADER.substitute(
        description=_scaffold_description(description, class_name),
        class_name=class_name,
        extra_imports=_PER_PROCESS_IMPORTS if per_process else "",
        requirement_lines=_PER_PROCESS_REQUIREMENTS if per_process else "")
    source = header + (_PER_PROCESS_BODY if per_process else _KERNEL_ONLY_BODY)
    return ServiceResult.ok({"class_name": class_name, "os_family": os_family,
                             "per_process": per_process, "source": source,
                             "line_count": source.count("\n")})


# -- check ------------------------------------------------------------------------

def _failure(kind: str, message: str, *, line: Optional[int] = None,
             offset: Optional[int] = None, text: Optional[str] = None,
             code: Optional[str] = None) -> Dict[str, Any]:
    return {"ok": False, "error": {"type": kind, "message": message, "line": line,
                                   "offset": offset, "text": text, "code": code}}


def _source_line(error: BaseException) -> Optional[int]:
    """Line inside the plugin source of an exception raised while executing it."""
    for frame in reversed(traceback.extract_tb(error.__traceback__)):
        if frame.filename.startswith(_PLUGIN_SOURCE_NAME):
            return frame.lineno
    return None


def _load_for_check(source: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """``(PluginInfo, None)`` or ``(None, structured failure)``."""
    from memdiver.app.tools_vol3 import _log_user_source
    from memdiver.engine.vol3_runner import plugin_from_source
    if not source or not str(source).strip():
        raise _invalid("source is required", "vol3.source_required")
    _log_user_source(source)
    try:
        return plugin_from_source(source), None
    except SyntaxError as exc:
        return None, _failure("SyntaxError", exc.msg or str(exc), line=exc.lineno,
                              offset=exc.offset, text=(exc.text or "").rstrip("\n") or None)
    except CapabilityError as exc:
        if exc.category is ErrorCategory.UNSUPPORTED:
            raise            # volatility3 itself is missing: not the plugin's fault
        return None, _failure("PluginError", str(exc), code=exc.code)
    except Exception as exc:  # noqa: BLE001 - user code ran: report whatever it raised
        return None, _failure(type(exc).__name__, str(exc), line=_source_line(exc))


def _drop_subtree(image_ctx: Any, base: str) -> None:
    """Delete every config leaf under ``base`` (shared with the runner)."""
    from memdiver.engine.vol3_runner import forget_config
    forget_config(image_ctx, base)


def _unsatisfied_entries(image_ctx: Any, cls: Any) -> List[Dict[str, Any]]:
    """Requirements the view's context leaves open (configured like the runner does)."""
    from memdiver.engine import vol3_runner as runner
    base = f"memdiver_check.c{uuid.uuid4().hex[:12]}"
    path = f"{base}.{cls.__name__}"
    with image_ctx.lock:
        try:
            runner._configure(image_ctx, cls, base, {})
            open_reqs = cls.unsatisfied(image_ctx.context, path)
        except CapabilityError as exc:
            return [{"name": "kernel", "requirement": "ModuleRequirement",
                     "reason": str(exc), "code": exc.code}]
        finally:
            _drop_subtree(image_ctx, base)
    return [{"name": req.name, "requirement": type(req).__name__,
             "path": config_path, "description": req.description or "",
             "optional": bool(req.optional)}
            for config_path, req in sorted(open_reqs.items())]


def vol3_check_result(source: Optional[str] = None, view_path: Optional[str] = None, *,
                      source_name: Optional[str] = None,
                      case_dir: Optional[str] = None) -> "ServiceResult":
    """Load ``source`` (or a stored ``source_name``); return its description, plus the
    unsatisfied requirements for a view."""
    from memdiver.app.tools_vol3_sources import _resolve_source
    from memdiver.engine.vol3_runner import describe_plugin
    info, failure = _load_for_check(_resolve_source(source, source_name, case_dir) or "")
    if failure is not None or info is None:
        return ServiceResult.ok(failure or _failure("PluginError", "plugin did not load"))
    payload: Dict[str, Any] = {"ok": True, "plugin": describe_plugin(info)}
    if view_path:
        from memdiver.app.tools_image import _context_for, _read_descriptor
        path, descriptor = _read_descriptor(view_path)
        unsatisfied = _unsatisfied_entries(_context_for(descriptor, path), info.cls)
        payload.update({"view_path": str(path), "unsatisfied": unsatisfied,
                        "satisfied": not any(not u.get("optional") for u in unsatisfied)})
    return ServiceResult.ok(payload)


# -- write-config -----------------------------------------------------------------

def _layer_class_name(config: Dict[str, Any]) -> Optional[str]:
    value = config.get("kernel.layer_name.class")
    return str(value) if value else None


def _write_shim(shim_dir: Path) -> Path:
    shim_dir.mkdir(parents=True, exist_ok=True)
    target = shim_dir / SHIM_FILE
    target.write_text(
        '"""Makes stock `vol` import MemDiver\'s kernel layer classes (LA57 paging).\n\n'
        'vol3 rebuilds a layer from config only if the layer\'s module is already in\n'
        'sys.modules; loading this file through `-p` imports it."""\n'
        "import memdiver.core.image.paging  # noqa: F401\n", encoding="utf-8")
    return target


def _vol_command(out: Path, shim_dir: Optional[Path], image: Path, plugin: str) -> List[str]:
    plugin_dir = ["-p", str(shim_dir)] if shim_dir else []
    return ["vol", "-q", *plugin_dir, "-c", str(out), "-f", str(image), plugin]


def _built_configuration(image_ctx: Any, plugin_name: str,
                         source: Optional[str] = None) -> Tuple[Dict[str, Any], Any]:
    """``plugin.build_configuration()`` of a plugin constructed like the runner does."""
    from memdiver.app.tools_vol3 import _plugin_info
    from memdiver.engine import vol3_runner as runner
    info = _plugin_info(plugin_name, source)
    with image_ctx.lock:
        plugin, base = runner._construct(image_ctx, info, {}, runner._OutputFiles(None, []),
                                         time.monotonic() + runner.DEFAULT_TIMEOUT_S, [], None)
        try:
            return dict(plugin.build_configuration()), info
        finally:
            _drop_subtree(image_ctx, base)


def vol3_write_config_result(view_path: str, out_path: str,
                             plugin: str = "linux.pslist.PsList", *,
                             source: Optional[str] = None,
                             source_name: Optional[str] = None,
                             case_dir: Optional[str] = None) -> "ServiceResult":
    """Write a Volatility 3 ``config.json`` reproducing the view's stack for ``plugin``.

    ``source`` / ``source_name`` write it for a user plugin instead (e.g. an
    emitted key-finder plugin), so its own requirements — ``primary``,
    ``kernel`` — are filled exactly as MemDiver fills them.
    """
    from memdiver.app.tools_vol3_sources import _resolve_source
    resolved = _resolve_source(source, source_name, case_dir)
    from memdiver.app.tools_image import _context_for, _read_descriptor
    path, descriptor = _read_descriptor(view_path)
    if not out_path or not str(out_path).strip():
        raise _invalid("out_path is required", "out_path_required")
    out = Path(out_path).expanduser().resolve()
    image_ctx = _context_for(descriptor, path)
    config, info = _built_configuration(image_ctx, plugin, resolved)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(config, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    layer_class = _layer_class_name(config)
    needs_shim = bool(layer_class and layer_class.startswith(_MEMDIVER_LAYER_PREFIX))
    shim_dir = _write_shim(out.with_name(out.stem + "_plugins")).parent if needs_shim else None
    image = descriptor.image_path(path)
    return ServiceResult.ok({
        "view_path": str(path), "config_path": str(out), "plugin": info.name,
        "image": str(image), "keys": len(config), "kernel_layer_class": layer_class,
        "page_map_offset": config.get("kernel.layer_name.page_map_offset"),
        "kernel_offset": config.get("kernel.offset"),
        "shim_dir": None if shim_dir is None else str(shim_dir),
        "command": _vol_command(out, shim_dir, image, info.name),
        "note": _config_note(layer_class, needs_shim)})


def _config_note(layer_class: Optional[str], needs_shim: bool) -> str:
    note = ("The config carries the stacked kernel (layer chain, page-table root, KASLR "
            "offset, symbol table), so vol's own stacker is not needed for the kernel layer.")
    if needs_shim:
        note += (f" The kernel layer class {layer_class} lives in MemDiver: run vol with "
                 "the same interpreter that has memdiver installed, and pass the shim "
                 "directory with -p so vol imports it before rebuilding the layer.")
    return note


# -- import -----------------------------------------------------------------------

def _detect_format(path: Path, requested: str) -> str:
    if requested != "auto":
        if requested not in _IMPORT_FORMATS:
            raise _invalid(f"format must be auto or one of {', '.join(_IMPORT_FORMATS)}",
                           "vol3.bad_format")
        return requested
    suffix = path.suffix.lower()
    table = {".parquet": "parquet", ".pq": "parquet", ".csv": "csv",
             ".jsonl": "jsonl", ".ndjson": "jsonl", ".json": "json"}
    if suffix not in table:
        raise _invalid(f"cannot detect the format of {path.name}; pass format=",
                       "vol3.format_undetected")
    return table[suffix]


def _flatten_rows(records: List[Dict[str, Any]], depth: int = 0,
                  out: Optional[List[Tuple[int, Dict[str, Any]]]] = None
                  ) -> List[Tuple[int, Dict[str, Any]]]:
    """Depth-first ``(depth, row)`` list of vol3's nested ``__children`` records."""
    out = [] if out is None else out
    for record in records:
        out.append((depth, {k: v for k, v in record.items() if k != _CHILDREN_KEY}))
        _flatten_rows(record.get(_CHILDREN_KEY) or [], depth + 1, out)
    return out


def _read_json_records(path: Path, fmt: str) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    try:
        if fmt == "json":
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except ValueError as exc:
        raise _invalid(f"{path.name} is not valid {fmt}: {exc}", "vol3.bad_file") from exc


def _arrow_column(values: List[Any]) -> Any:
    import pyarrow as pa
    try:
        return pa.array(values)
    except (pa.ArrowInvalid, pa.ArrowTypeError, OverflowError):
        pass
    present = [v for v in values if v is not None]
    if present and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0
                       for v in present):
        return pa.array(values, type=pa.uint64())
    return pa.array([None if v is None else str(v) for v in values], type=pa.string())


def _table_from_records(records: List[Dict[str, Any]]) -> Any:
    import pyarrow as pa
    flat = _flatten_rows(records)
    names: List[str] = []
    for _, row in flat:
        names.extend(k for k in row if k not in names)
    data = {name: _arrow_column([row.get(name) for _, row in flat]) for name in names}
    data["depth"] = pa.array([d for d, _ in flat], type=pa.int32())
    data["absent"] = pa.array([None] * len(flat), type=pa.string())
    return pa.table(data)


def _read_table(path: Path, fmt: str) -> Any:
    try:
        if fmt == "parquet":
            import pyarrow.parquet as pq
            return pq.read_table(path)
        if fmt == "csv":
            import pyarrow.csv as pacsv
            return pacsv.read_csv(path)
        return _table_from_records(_read_json_records(path, fmt))
    except CapabilityError:
        raise
    except (OSError, ValueError) as exc:     # pyarrow's ArrowInvalid is a ValueError
        raise _invalid(f"cannot read {path.name} as {fmt}: {exc}", "vol3.bad_file") from exc


def _guess_locations(table: Any) -> Dict[str, str]:
    """Address columns by the runner's heuristic; integers stand in for ``Hex``."""
    import pyarrow as pa
    from memdiver.engine.vol3_runner import _find_pid_column, guess_space
    names = list(table.column_names)
    has_pid = _find_pid_column(names) is not None
    has_kernel = any(n.lower().replace(" ", "").endswith("(v)") for n in names)
    found: Dict[str, str] = {}
    for name in names:
        if not pa.types.is_integer(table.schema.field(name).type):
            continue
        space = guess_space(name, "hex", has_pid, has_kernel)
        if space:
            found[name] = space
    return found


def _canonical_kernel_columns(table: Any, locations: Dict[str, str]) -> Any:
    """External vol3 output prints kernel VAs de-canonical; MemDiver Locations are canonical."""
    import pyarrow as pa
    from memdiver.engine.vol3_runner import canonicalize_masked_kernel_va
    for name, space in locations.items():
        if space != "kernel_va" or name not in table.column_names:
            continue
        values = [canonicalize_masked_kernel_va(v) for v in table.column(name).to_pylist()]
        index = table.column_names.index(name)
        table = table.set_column(index, name, pa.array(values, type=pa.uint64()))
    return table


def _validate_locations(table: Any, locations: Dict[str, str]) -> None:
    """Explicit ``locations`` must use AddressSpace values on integer columns."""
    import pyarrow as pa
    from memdiver.core.location import AddressSpace
    valid = [m.value for m in AddressSpace]
    for column, space in locations.items():
        if space not in valid:
            raise _invalid(f"location space {space!r} for column {column!r} is not valid; "
                           f"valid: {', '.join(valid)}", "vol3.bad_location_space")
        if column in table.column_names and not pa.types.is_integer(
                table.schema.field(column).type):
            raise _invalid(f"located column {column!r} must be integer-typed, got "
                           f"{table.schema.field(column).type}", "vol3.location_column_type")


def vol3_import_parquet_result(case_dir: str, path: str, *, table: str, capture_id: str,
                               image_sha256: Optional[str] = None,
                               locations: Optional[Dict[str, str]] = None,
                               format: str = "auto") -> "ServiceResult":  # noqa: A002
    """Register an external vol3 output file as one run of the case table ``table``."""
    from memdiver.app.tools_case import _open
    if not str(table or "").startswith("vol3__"):
        raise _invalid("table must start with 'vol3__' (e.g. 'vol3__linux_pslist')",
                       "vol3.bad_table_name")
    if not capture_id:
        raise _invalid("capture_id is required", "capture_id_required")
    source = Path(path).expanduser()
    if not source.is_file():
        raise CapabilityError(f"file not found: {source}", category=ErrorCategory.NOT_FOUND,
                              code="vol3.file_not_found")
    fmt = _detect_format(source, format)
    case = _open(case_dir)
    arrow = _read_table(source, fmt)
    used = dict(locations) if locations is not None else _guess_locations(arrow)
    if locations is not None:
        _validate_locations(arrow, used)
    arrow = _canonical_kernel_columns(arrow, used)
    ref = case.register_table(
        table, arrow, capture_id=capture_id, image_sha256=image_sha256,
        producer="vol3_import", file_stem=_file_stem(source), locations=used,
        meta={"source_file": str(source), "source_format": fmt})
    return ServiceResult.ok({**ref.to_dict(), "format": fmt, "columns": list(arrow.column_names),
                             "locations_guessed": locations is None})


def _file_stem(path: Path) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.\-]+", "_", path.stem).strip("._") or "import"
    return stem[:128]


# -- exec: run a plugin by name under stock vol ----------------------------------

#: Default wall-clock ceiling and echoed-row cap of :func:`vol3_exec_result`.
DEFAULT_EXEC_TIMEOUT_S = 900
DEFAULT_EXEC_MAX_ROWS = 1000
#: stderr bytes echoed in the payload (the engine keeps a longer tail).
EXEC_STDERR_ECHO = 16 * 1024
#: Where replaced synthesized plugins are archived (``tools_vol3_sources.SYNTHESIZED_HISTORY_DIR``).
#: vol imports EVERY ``.py`` beneath a ``-p`` directory, so an archive under
#: one would load stale plugin versions; such a ``-p`` is refused. Compared
#: casefolded (macOS / Windows file systems are case-insensitive).
_HISTORY_PARTS = tuple(SYNTHESIZED_HISTORY_DIR.casefold().split("/"))
#: Bounds on the history walk of one ``-p`` directory; beyond either the
#: directory is refused rather than passed to vol unchecked.
HISTORY_WALK_MAX_DIRS = 20_000
HISTORY_WALK_MAX_DEPTH = 32


def _not_found(what: str, path: Path) -> CapabilityError:
    return CapabilityError(f"{what} not found: {path}", category=ErrorCategory.NOT_FOUND,
                           code="vol3.exec.not_found")


def _is_history_path(parts: Tuple[str, ...]) -> bool:
    folded = tuple(p.casefold() for p in parts)
    return any(folded[i:i + 2] == _HISTORY_PARTS for i in range(len(folded) - 1))


def _holds_history(directory: Path) -> bool:
    """True when *directory* is, is inside, or contains a ``vol3/history`` archive.

    Follows symlinks like vol's own import walk does (a link to a history dir
    counts), with a visited ``(st_dev, st_ino)`` set against link loops.
    Raises :class:`CapabilityError` when the walk exceeds
    :data:`HISTORY_WALK_MAX_DIRS` directories or :data:`HISTORY_WALK_MAX_DEPTH` levels.
    """
    import os

    if _is_history_path(directory.parts):
        return True
    visited = set()
    base_depth = len(directory.parts)
    for root, dirs, _files in os.walk(directory, followlinks=True):
        here = Path(root)
        stat = here.stat()
        if (stat.st_dev, stat.st_ino) in visited:
            dirs[:] = []
            continue
        visited.add((stat.st_dev, stat.st_ino))
        if len(visited) > HISTORY_WALK_MAX_DIRS or len(here.parts) - base_depth > HISTORY_WALK_MAX_DEPTH:
            raise _invalid(f"plugin directory {directory} is too large to check for a "
                           f"vol3/history archive (> {HISTORY_WALK_MAX_DIRS} directories or "
                           f"> {HISTORY_WALK_MAX_DEPTH} levels); pass a narrower directory",
                           "vol3.exec.plugin_dir_too_large")
        if _is_history_path(here.parts) or _is_history_path(here.resolve().parts):
            return True
    return False


def _exec_dirs(values: Any, what: str, *, plugin_dirs: bool) -> List[Path]:
    """Existing, absolute, ``;``-free directories (``-p`` ones also history-free)."""
    from memdiver.engine.vol3_subproc import semicolon_paths

    items = [values] if isinstance(values, (str, Path)) else list(values or ())
    dirs: List[Path] = []
    for item in items:
        directory = Path(item).expanduser().resolve()
        if semicolon_paths([directory]):
            raise _invalid(f"{what} may not contain ';' (vol separates -p / -s "
                           f"directories with it): {directory}", "vol3.exec.semicolon_in_path")
        if not directory.is_dir():
            raise _not_found(what, directory)
        if plugin_dirs and _holds_history(directory):
            raise _invalid(f"{what} {directory} is or contains a vol3/history archive of "
                           "replaced plugins; pass <case>/vol3/plugins instead",
                           "vol3.exec.history_dir")
        dirs.append(directory)
    return dirs


def require_launcher(vol_bin: Optional[str], vol_python: Optional[str], *,
                     purpose: str, code: str) -> Any:
    """The stock ``vol`` launcher, else UNSUPPORTED: "<purpose> needs a stock vol launcher: ..."."""
    from memdiver.engine import vol3_subproc

    launcher = vol3_subproc.resolve_launcher(vol_bin=vol_bin, vol_python=vol_python)
    if launcher is None:
        raise CapabilityError(
            f"{purpose} needs a stock vol launcher: "
            + vol3_subproc.launcher_report(vol_bin=vol_bin, vol_python=vol_python),
            category=ErrorCategory.UNSUPPORTED, code=code)
    return launcher


def _exec_args(args: Any) -> List[str]:
    """Plugin arguments as strings; vol GLOBAL options (``-p``, ``--log=``...) are refused."""
    from memdiver.engine.vol3_subproc import refuse_global_options

    if args is None:
        return []
    if isinstance(args, str) or not all(isinstance(a, (str, int, float)) for a in args):
        raise _invalid("args must be a list of strings (vol plugin arguments)",
                       "vol3.exec.bad_args")
    values = [str(a) for a in args]
    try:
        refuse_global_options(values)
    except ValueError as exc:
        raise _invalid(str(exc), "vol3.exec.global_option") from exc
    return values


def _dir_state(directory: Path) -> Dict[str, Tuple[int, int]]:
    """``name -> (mtime_ns, size)`` of every entry directly in *directory*."""
    state: Dict[str, Tuple[int, int]] = {}
    for entry in directory.iterdir():
        try:
            st = entry.stat()
        except OSError:
            continue
        state[entry.name] = (st.st_mtime_ns, st.st_size)
    return state


def _written_since(directory: Path, before: Dict[str, Tuple[int, int]]) -> List[str]:
    """Entries of *directory* that are new or changed (mtime/size) since *before*.

    A user-supplied ``out_dir`` may already hold files from earlier runs: those are
    not this run's output and must not be reported as such.
    """
    return sorted(name for name, state in _dir_state(directory).items()
                  if before.get(name) != state)


def _exec_run(launcher: Any, plugin: str, image: Path, *, out_dir: Path,
              timeout_s: int, **kwargs: Any) -> Any:
    import subprocess  # nosec B404 - only for TimeoutExpired

    from memdiver.engine import vol3_subproc

    try:
        return vol3_subproc.run_named_plugin(launcher, plugin, image, output_dir=out_dir,
                                             timeout=int(timeout_s), **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise CapabilityError(f"vol {plugin} exceeded {timeout_s} s", status=504,
                              category=ErrorCategory.PRECONDITION,
                              code="vol3.exec.timeout") from exc
    except (RuntimeError, ValueError) as exc:  # bad name, ';', output cap, bad JSON
        raise _invalid(f"vol3 exec {plugin}: {exc}", "vol3.exec.failed") from exc


def _exec_command(plugin: str, image: Path, dirs: List[Path],
                  symbols: List[Path], plugin_args: List[str], out_dir: Optional[Path]) -> str:
    """The copy-pasteable ``vol`` line (no ``-o`` for the discarded scratch directory).

    The same :class:`~memdiver.engine.vol3_subproc.VolSpec` the run is built
    from, rendered by its ``display_command`` (a bare ``vol``, no launcher path).
    """
    from memdiver.engine import vol3_subproc

    return vol3_subproc.named_plugin_spec(
        plugin, image, plugin_dirs=dirs, symbol_dirs=symbols, plugin_args=plugin_args,
        output_dir=out_dir).display_command()


def vol3_exec_result(plugin: str, image_path: str, *, plugin_dirs: Any = (),
                     symbol_dirs: Any = (), args: Optional[List[str]] = None,
                     include_memdiver_plugins: bool = True,
                     timeout_s: int = DEFAULT_EXEC_TIMEOUT_S,
                     max_rows: int = DEFAULT_EXEC_MAX_ROWS,
                     vol_bin: Optional[str] = None, vol_python: Optional[str] = None,
                     out_dir: Optional[str] = None) -> ServiceResult:
    """Run a Volatility 3 plugin by NAME under the stock ``vol`` launcher.

    ``vol -q -r json [-s <symbol_dirs> --offline] -p <dirs> [-o <out_dir>]
    -f <image_path> <plugin> <args...>`` in a subprocess
    (:func:`memdiver.engine.vol3_subproc.run_named_plugin`): the same command
    an analyst types, e.g. ``msl.info`` over an ``.msl`` or a synthesized
    plugin from ``<case>/vol3/plugins``. With *include_memdiver_plugins* the
    installed ``memdiver/vol3plugins`` directory (``.msl`` layer, ``msl.*``,
    ``linux.*`` secrets plugins) is the first ``-p`` directory. A plugin
    directory that is or contains ``vol3/history`` is refused (vol would
    import every archived version), as is ``;`` in any ``-p`` / ``-s`` path.
    *out_dir* receives files a plugin writes; without it they go to a
    temporary directory that is discarded. *args* follow the plugin name;
    vol GLOBAL options there (any single-dash option, any ``--name`` that
    abbreviates a global such as ``--plugin-dirs`` / ``--log``) are refused,
    because vol reads globals from the whole command line. Path arguments a
    PLUGIN itself takes (``--oracle-sample <dir>``, ``--dump-dir``...) are NOT
    checked against the server's read sandbox: they are opaque plugin values. The launcher and its interpreter
    come from *vol_bin* / *vol_python*, else ``MEMDIVER_VOL3_BIN`` /
    ``MEMDIVER_VOL3_PYTHON``, else ``vol`` on ``PATH``.

    A plugin that FAILS is a finding, not an exception: ``ok: false`` with
    ``returncode`` and ``stderr_tail``. Raises :class:`CapabilityError` for bad
    input (NOT_FOUND paths, ``;`` / history dirs, a malformed plugin name, a
    vol global option in *args*),
    no launcher (UNSUPPORTED) and a timeout (504).
    """
    import tempfile

    if not plugin or not str(plugin).strip():
        raise _invalid("plugin is required (a vol plugin name, e.g. msl.info)",
                       "vol3.exec.plugin_required")
    image = Path(image_path).expanduser().resolve()
    if not image.is_file():
        raise _not_found("image", image)
    dirs = _exec_dirs(plugin_dirs, "plugin directory", plugin_dirs=True)
    if include_memdiver_plugins:
        from memdiver.app.tools_pipeline import vol3_plugin_dir
        package_dir = Path(vol3_plugin_dir()["path"])
        dirs = [package_dir] + [d for d in dirs if d != package_dir]
    symbols = _exec_dirs(symbol_dirs, "symbol directory", plugin_dirs=False)
    plugin_args = _exec_args(args)
    launcher = require_launcher(vol_bin, vol_python, purpose="vol3 exec",
                                code="vol3.exec.no_launcher")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="memdiver_vol3_exec_") as scratch:
        target = Path(out_dir).expanduser().resolve() if out_dir else Path(scratch)
        target.mkdir(parents=True, exist_ok=True)
        before = _dir_state(target)
        run = _exec_run(launcher, plugin, image, out_dir=target, timeout_s=timeout_s,
                        plugin_dirs=dirs, symbol_dirs=symbols, plugin_args=plugin_args)
        output_files = _written_since(target, before)
    cap = max(0, int(max_rows))
    return ServiceResult.ok({
        "ok": run.returncode == 0, "returncode": run.returncode, "plugin": plugin,
        "image_path": str(image), "plugin_dirs": [str(d) for d in dirs],
        "symbol_dirs": [str(d) for d in symbols], "args": plugin_args,
        "rows": run.rows[:cap], "row_count": len(run.rows), "truncated": len(run.rows) > cap,
        "stderr_tail": run.stderr_tail[-EXEC_STDERR_ECHO:], "framework": run.framework,
        "vol_command": _exec_command(plugin, image, dirs, symbols, plugin_args,
                                     target if out_dir else None),
        "launcher": launcher.describe(), "elapsed_s": round(time.monotonic() - started, 3),
        "out_dir": str(target) if out_dir else None, "output_files": output_files,
    })


__all__ = ["SHIM_FILE", "vol3_scaffold_result", "vol3_check_result",
           "vol3_write_config_result", "vol3_import_parquet_result", "vol3_exec_result"]
