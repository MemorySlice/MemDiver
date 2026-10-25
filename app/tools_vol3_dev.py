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


__all__ = ["SHIM_FILE", "vol3_scaffold_result", "vol3_check_result",
           "vol3_write_config_result", "vol3_import_parquet_result"]
