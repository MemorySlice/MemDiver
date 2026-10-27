"""Run Volatility 3 plugins inside MemDiver over an :class:`ImageContext` (plan T2.1).

Three operations, all transport-free (producers in ``app/tools_vol3.py`` wrap them):

* :func:`list_plugins` — the bundled plugins of one OS family (``linux.*``);
* :func:`describe_plugin` — a plugin's *user* requirements as a JSON-schema-like
  list (the ones the context satisfies — kernel module, layers, symbol tables,
  version pins — are hidden);
* :func:`run_plugin` — construct the plugin against the context's already
  stacked kernel (``construct_plugin`` with no automagic: the context was
  built by MemDiver, including the LA57 self-test that vol3's own stacker gets
  wrong) and collect the TreeGrid into a :class:`PluginRunResult`.

A :class:`PluginRunResult` keeps the coordinate system of every address column
(P2): ``"(V)"`` columns are kernel VAs, ``"(P)"`` physical, address-named
``Hex`` columns of a plugin with a ``PID`` column are process VAs of that row's
pid. vol3 object offsets are DE-canonical; every kernel VA is canonicalized
before it leaves this module. Absent cells (``UnreadableValue`` ...) become
``None`` with a reason — never ``0`` (P3). The result converts to a
``pyarrow.Table`` for the case data lake (vol3 2.27 has no Parquet renderer)
and to analysis-record entries (D4).

vol3 contexts are not thread-safe: every call here holds ``ImageContext.lock``.
The engine module that EMITS plugins (``engine/vol3_verify.py``) keeps its own
hand-built path; this module never changes it, it only reuses its loader.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import io
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence,
                    Tuple)

from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Requirement classes the image context satisfies; never shown to a user.
_CONTEXT_REQUIREMENTS = frozenset({
    "ModuleRequirement", "TranslationLayerRequirement", "SymbolTableRequirement",
    "VersionRequirement", "PluginRequirement", "LayerListRequirement",
})
#: snake_case name tokens that mark a ``Hex`` column as an address.
_ADDRESS_TOKENS = frozenset({
    "offset", "addr", "address", "base", "start", "end", "ptr", "pointer",
    "va", "vaddr", "pa", "paddr", "location",
})
_SUFFIX_SPACE = (("(p)", AddressSpace.PHYSICAL), ("(v)", AddressSpace.KERNEL_VA))
DEFAULT_ROW_LIMIT = 100_000
DEFAULT_TIMEOUT_S = 300.0


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


# -- plugin catalogue ------------------------------------------------------------

@dataclass(frozen=True)
class PluginInfo:
    """One plugin as vol3's CLI names it (``linux.pslist.PsList``)."""

    name: str
    description: str
    version: Tuple[int, ...]
    cls: Any = field(repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "version": ".".join(str(v) for v in self.version)}


def _plugin_classes() -> List[Any]:
    from memdiver.core.image.context import require_volatility3
    require_volatility3()
    import volatility3.plugins as vol_plugins
    from volatility3 import framework
    from volatility3.framework import interfaces
    framework.require_interface_version(2, 0, 0)
    framework.import_files(vol_plugins, True)
    return list(framework.class_subclasses(interfaces.plugins.PluginInterface))


def _cli_name(cls: Any) -> Optional[str]:
    module = getattr(cls, "__module__", "")
    for prefix in ("volatility3.plugins.", "volatility3.framework.plugins."):
        if module.startswith(prefix):
            return f"{module[len(prefix):]}.{cls.__name__}"
    return None


def _first_doc_line(cls: Any) -> str:
    doc = (cls.__doc__ or "").strip()
    return doc.splitlines()[0].strip() if doc else ""


def list_plugins(os_family: str = "linux") -> List[PluginInfo]:
    """Bundled plugins whose CLI name starts with ``<os_family>.``, sorted."""
    found: Dict[str, PluginInfo] = {}
    for cls in _plugin_classes():
        name = _cli_name(cls)
        if name is None or not name.startswith(f"{os_family}."):
            continue
        found[name] = PluginInfo(name, _first_doc_line(cls),
                                 tuple(getattr(cls, "_version", ()) or ()), cls)
    return [found[k] for k in sorted(found)]


def resolve_plugin(name: str, os_family: str = "linux") -> PluginInfo:
    """Find a plugin by full CLI name (``linux.pslist.PsList``) or module (``linux.pslist``)."""
    wanted = (name or "").strip()
    if not wanted:
        raise _invalid("plugin name is required", "vol3.plugin_required")
    catalogue = list_plugins(os_family)
    exact = [p for p in catalogue if p.name == wanted]
    by_module = [p for p in catalogue if p.name.rsplit(".", 1)[0] == wanted]
    matches = exact or by_module
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise _invalid(f"plugin name {wanted!r} is ambiguous: "
                       f"{', '.join(p.name for p in matches)}", "vol3.plugin_ambiguous")
    raise CapabilityError(f"unknown {os_family} plugin {wanted!r}",
                          category=ErrorCategory.NOT_FOUND, code="vol3.plugin_unknown")


def plugin_from_source(source: str, module_name: Optional[str] = None) -> PluginInfo:
    """Load a user plugin from source text (unsandboxed, like every plugin; D7)."""
    from memdiver.engine.vol3_verify import load_plugin_class
    name = module_name or f"memdiver_user_plugin_{uuid.uuid4().hex[:12]}"
    cls = load_plugin_class(source, name)
    return PluginInfo(f"user.{cls.__name__}", _first_doc_line(cls),
                      tuple(getattr(cls, "_version", ()) or ()), cls)


# -- requirements ----------------------------------------------------------------

_TYPE_OF = {"IntRequirement": "integer", "StringRequirement": "string",
            "BooleanRequirement": "boolean", "URIRequirement": "string",
            "ListRequirement": "array", "ChoiceRequirement": "string"}


def _requirement_schema(req: Any) -> Dict[str, Any]:
    kind = type(req).__name__
    entry: Dict[str, Any] = {"name": req.name, "type": _TYPE_OF.get(kind, "string"),
                             "requirement": kind, "description": req.description or "",
                             "optional": bool(req.optional), "default": _json_default(req.default)}
    if kind == "ListRequirement":
        element = getattr(req, "element_type", str)
        entry["items"] = {"type": {int: "integer", bool: "boolean"}.get(element, "string")}
        entry["min_elements"] = getattr(req, "min_elements", 0)
        entry["max_elements"] = getattr(req, "max_elements", None) or None
    if kind == "ChoiceRequirement":
        entry["choices"] = list(getattr(req, "choices", []))
    return entry


def _json_default(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_default(v) for v in value]
    return str(value)


def user_requirements(cls: Any) -> List[Any]:
    """Requirements a user fills in (the context satisfies the rest)."""
    return [r for r in cls.get_requirements()
            if type(r).__name__ not in _CONTEXT_REQUIREMENTS]


def describe_plugin(info: PluginInfo) -> Dict[str, Any]:
    """Name, description, version and the user requirements as a schema list."""
    reqs = [_requirement_schema(r) for r in user_requirements(info.cls)]
    hidden = sorted({type(r).__name__ for r in info.cls.get_requirements()}
                    & _CONTEXT_REQUIREMENTS)
    return {**info.to_dict(), "requirements": reqs, "satisfied_by_context": hidden}


def _coerce_scalar(req_kind: str, element: Any, value: Any, name: str) -> Any:
    try:
        if req_kind == "BooleanRequirement" or element is bool:
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)
        if req_kind == "IntRequirement" or element is int:
            if isinstance(value, str):
                return int(value, 0)
            if isinstance(value, bool):
                raise ValueError("boolean is not an integer")
            return int(value)
    except (TypeError, ValueError) as exc:
        raise _invalid(f"argument {name!r}: {exc}", "vol3.bad_argument") from exc
    return str(value)


def coerce_arguments(cls: Any, args: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate ``args`` against the user requirements; unknown names are refused."""
    reqs = {r.name: r for r in user_requirements(cls)}
    unknown = sorted(set(args or {}) - set(reqs))
    if unknown:
        raise _invalid(f"unknown plugin argument(s): {', '.join(unknown)}; "
                       f"accepted: {', '.join(sorted(reqs)) or 'none'}", "vol3.unknown_argument")
    out: Dict[str, Any] = {}
    for name, value in (args or {}).items():
        req = reqs[name]
        kind = type(req).__name__
        if value is None:
            continue
        if kind == "ListRequirement":
            items = value if isinstance(value, (list, tuple)) else [value]
            element = getattr(req, "element_type", str)
            out[name] = [_coerce_scalar(kind, element, v, name) for v in items]
        else:
            out[name] = _coerce_scalar(kind, None, value, name)
        if kind == "ChoiceRequirement" and out[name] not in req.choices:
            raise _invalid(f"argument {name!r} must be one of {req.choices}", "vol3.bad_argument")
    return out


# -- column -> Location heuristics ----------------------------------------------

@dataclass(frozen=True)
class ColumnSpec:
    """One output column: vol3 name, Arrow-ish type, and its address space if any."""

    name: str
    type: str                       # int | hex | str | bytes | datetime | bool | float | multi
    space: Optional[str] = None     # AddressSpace value for address columns

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "type": self.type, "space": self.space}


def _column_type(vol_type: Any) -> str:
    from volatility3.framework.renderers import format_hints
    checks = ((format_hints.Hex, "hex"), (format_hints.Bin, "int"),
              (format_hints.MultiTypeData, "multi"), (format_hints.HexBytes, "bytes"),
              (bool, "bool"), (int, "int"), (float, "float"), (bytes, "bytes"),
              (_dt.datetime, "datetime"), (str, "str"))
    for klass, label in checks:
        if isinstance(vol_type, type) and issubclass(vol_type, klass):
            return label
    return "str"


def _name_tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]


def guess_space(name: str, col_type: str, has_pid_column: bool,
                has_kernel: bool) -> Optional[str]:
    """The address space of a column, or ``None`` when it is not an address."""
    if col_type not in ("hex", "int"):
        return None
    lowered = name.lower().replace(" ", "")
    for suffix, space in _SUFFIX_SPACE:
        if lowered.endswith(suffix):
            return space.value
    if col_type != "hex" or not (set(_name_tokens(name)) & _ADDRESS_TOKENS):
        return None
    if has_pid_column and "offset" not in _name_tokens(name):
        return AddressSpace.PROCESS_VA.value
    return (AddressSpace.KERNEL_VA if has_kernel else AddressSpace.PHYSICAL).value


def canonicalize_masked_kernel_va(value: Optional[int]) -> Optional[int]:
    """Sign-extend a kernel VA that vol3 printed DE-canonical, without a layer.

    vol3 masks object offsets to the VA width (``0x01424db6…`` on LA57,
    ``0x0000ffff8…`` on 4-level). A kernel address always has the top bit of its
    width set, so ``[2^56, 2^57)`` is a masked 57-bit VA and ``[2^47, 2^48)`` a
    masked 48-bit one; anything else is returned unchanged.
    """
    if value is None or value < 0:
        return value
    for bits in (57, 48):
        if (1 << (bits - 1)) <= value < (1 << bits):
            return value | ((1 << 64) - (1 << bits))
    return value


def _find_pid_column(names: Sequence[str]) -> Optional[int]:
    for index, name in enumerate(names):
        if name.strip().lower() == "pid":
            return index
    return None


def column_specs(grid_columns: Sequence[Any], has_kernel: bool,
                 overrides: Optional[Dict[str, Optional[str]]] = None) -> List[ColumnSpec]:
    """Specs for a TreeGrid's columns; ``overrides`` (name -> space|None) win."""
    names = [c.name for c in grid_columns]
    has_pid = _find_pid_column(names) is not None
    valid = {s.value for s in AddressSpace}
    specs = []
    for col in grid_columns:
        kind = _column_type(col.type)
        space = guess_space(col.name, kind, has_pid, has_kernel)
        if overrides and col.name in overrides:
            space = overrides[col.name]
            if space is not None and space not in valid:
                raise _invalid(f"unknown address space {space!r} for column {col.name!r}",
                               "vol3.bad_location")
        specs.append(ColumnSpec(col.name, kind, space))
    return specs


# -- run --------------------------------------------------------------------------

@dataclass
class PluginRunResult:
    """Rows of one plugin run with typed columns, tree depth and absent reasons."""

    plugin: str
    columns: List[ColumnSpec]
    rows: List[List[Any]]                     # cell values; None where absent
    depths: List[int]
    absent: List[Dict[str, str]]              # per row: column -> absent-value class
    elapsed_s: float
    truncated: bool = False
    stop_reason: Optional[str] = None         # "row_limit" | "timeout" | None
    diagnostics: List[str] = field(default_factory=list)
    capture_id: Optional[str] = None
    files: List[str] = field(default_factory=list)

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def location_columns(self) -> Dict[str, str]:
        return {c.name: c.space for c in self.columns if c.space}

    def location(self, row_index: int, column: str) -> Optional[Location]:
        """The :class:`Location` of one cell, or ``None`` (absent / not an address)."""
        names = [c.name for c in self.columns]
        spec = self.columns[names.index(column)]
        value = self.rows[row_index][names.index(column)]
        if spec.space is None or value is None:
            return None
        space = AddressSpace(spec.space)
        pid = None
        if space is AddressSpace.PROCESS_VA:
            pid_index = _find_pid_column(names)
            pid = None if pid_index is None else self.rows[row_index][pid_index]
            if pid is None:
                return None
        return Location(space, int(value), capture_id=self.capture_id, pid=pid)

    def to_dict(self, max_rows: Optional[int] = None) -> Dict[str, Any]:
        rows = self.rows if max_rows is None else self.rows[:max_rows]
        return {"plugin": self.plugin, "capture_id": self.capture_id,
                "columns": [c.to_dict() for c in self.columns],
                "rows": [{"depth": self.depths[i], "values": [_json_cell(v) for v in row],
                          "absent": self.absent[i]} for i, row in enumerate(rows)],
                "row_count": self.row_count, "rows_returned": len(rows),
                "truncated": self.truncated, "stop_reason": self.stop_reason,
                "elapsed_s": round(self.elapsed_s, 3), "diagnostics": list(self.diagnostics),
                "files": list(self.files)}

    def to_arrow(self) -> Any:
        """A ``pyarrow.Table``: plugin columns + ``depth`` + ``absent`` (JSON)."""
        return _to_arrow(self)


def _json_cell(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return value


class _Stop(Exception):
    """Raised from the visitor/progress callback to end population early."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _DeadlineExceeded(BaseException):
    """Raised from a layer read once the run's wall-clock budget is spent.

    Deliberately a ``BaseException``: vol3's ``DataLayerInterface.scan`` wraps its
    whole body in ``except Exception`` and silently stops yielding, so an
    ``Exception`` subclass raised from a read never reaches the runner.
    """


CANCEL_POLL_INTERVAL_S = 0.25


class _CancelPoll:
    """Throttled view of a cancel callable.

    ``cancel`` is typically a multiprocessing-event proxy (a round trip per
    call), so it is asked at most once per ``interval`` seconds. Once it has
    answered True the answer is latched.
    """

    def __init__(self, cancel: Optional[Callable[[], bool]],
                 interval: float = CANCEL_POLL_INTERVAL_S) -> None:
        self._cancel, self._interval = cancel, interval
        self._next_poll = 0.0
        self._fired = False

    def __call__(self) -> bool:
        if self._cancel is None:
            return False
        if self._fired:
            return True
        now = time.monotonic()
        if now < self._next_poll:
            return False
        self._next_poll = now + self._interval
        self._fired = bool(self._cancel())
        return self._fired


@contextlib.contextmanager
def _read_deadline_guard(context: Any, deadline: float,
                         cancelled: Optional[Callable[[], bool]] = None) -> Iterator[None]:
    """Make every layer read in ``context`` raise ``_DeadlineExceeded`` after ``deadline``
    (reason ``"timeout"``) or once ``cancelled()`` is true (reason ``"cancelled"``).

    A scanner that seldom reports progress never sees the progress-callback
    deadline; its reads are the one place it must pass through. Original read
    methods are restored on exit. The caller holds ``image_ctx.lock``, so the
    temporary instance-level wrapping is not observed by another run.

    Scope limit: this guard is entered only AFTER the plugin is constructed.
    Construction (``_construct``, which runs automagic) happens outside the
    read deadline and is bounded only by the progress-callback deadline.
    """
    wrapped: List[Tuple[Any, bool, Any]] = []

    def guarded(original: Callable[..., Any]) -> Callable[..., Any]:
        def read(*args: Any, **kwargs: Any) -> Any:
            if time.monotonic() > deadline:
                raise _DeadlineExceeded("timeout")
            if cancelled is not None and cancelled():
                raise _DeadlineExceeded("cancelled")
            return original(*args, **kwargs)
        return read

    try:
        for name in list(context.layers):
            layer = context.layers[name]
            had_own = "read" in vars(layer)
            wrapped.append((layer, had_own, vars(layer).get("read")))
            layer.read = guarded(layer.read)
        yield
    finally:
        for layer, had_own, own in reversed(wrapped):
            if had_own:
                layer.read = own
            else:
                vars(layer).pop("read", None)


class _OutputFiles:
    """vol3 ``open_method`` factory: write into ``out_dir`` or discard (and say so)."""

    def __init__(self, out_dir: Optional[Path], diagnostics: List[str]) -> None:
        self.out_dir = out_dir
        self.written: List[str] = []
        self.diagnostics = diagnostics

    def handler_class(self) -> Any:
        from volatility3.framework import interfaces
        owner = self

        class _Handler(interfaces.plugins.FileHandlerInterface):
            def __init__(self, filename: str) -> None:
                super().__init__(filename)
                self._buffer = io.BytesIO()

            def writable(self) -> bool:
                return True

            def write(self, data: Any) -> int:
                return self._buffer.write(data)

            def close(self) -> None:
                if not self.closed:
                    owner.commit(self.preferred_filename, self._buffer.getvalue())
                # vol3's FileHandlerInterface.close is an abstract no-op: without
                # RawIOBase.close the handler never reads as closed and IOBase.__del__
                # commits the file a second time.
                io.RawIOBase.close(self)

        return _Handler

    def commit(self, filename: str, data: bytes) -> None:
        from volatility3.framework import interfaces
        safe = interfaces.plugins.FileHandlerInterface.sanitize_filename(filename) or "output.bin"
        if self.out_dir is None:
            self.diagnostics.append(f"file output {safe!r} discarded (no output directory)")
            return
        self.out_dir.mkdir(parents=True, exist_ok=True)
        target = self.out_dir / safe
        counter = 1
        while target.exists():
            target = self.out_dir / f"{counter}_{safe}"
            counter += 1
        target.write_bytes(data)
        self.written.append(str(target))


def _layer_for_requirements(image_ctx: Any) -> str:
    return image_ctx.kernel.layer_name if image_ctx.has_kernel else image_ctx.physical_layer


def _configure(image_ctx: Any, cls: Any, base: str, args: Dict[str, Any]) -> None:
    """Point every context requirement at the context's kernel; set user args."""
    from memdiver.core.image.context import KERNEL_MODULE
    config = image_ctx.context.config
    path = f"{base}.{cls.__name__}"
    for req in cls.get_requirements():
        kind = type(req).__name__
        if kind == "ModuleRequirement":
            if not image_ctx.has_kernel:
                raise CapabilityError(
                    f"{cls.__name__} needs a kernel profile; this view has none",
                    category=ErrorCategory.PRECONDITION, code="vol3.needs_kernel")
            config[f"{path}.{req.name}"] = KERNEL_MODULE
        elif kind == "TranslationLayerRequirement":
            config[f"{path}.{req.name}"] = _layer_for_requirements(image_ctx)
        elif kind == "SymbolTableRequirement" and image_ctx.has_kernel:
            config[f"{path}.{req.name}"] = image_ctx.kernel.symbol_table_name
    for name, value in args.items():
        config[f"{path}.{name}"] = value


def _convert_cell(value: Any, kind: str) -> Any:
    from volatility3.framework.renderers import format_hints
    if isinstance(value, format_hints.MultiTypeData):
        if value.converted_int:
            return bytes(value).decode(value.encoding, errors="replace")
        return bytes(value).decode(value.encoding, errors="replace").split("\x00")[0]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (_dt.datetime, float, str)):
        return value
    return str(value)


class _Collector:
    """TreeGrid visitor: converts cells, canonicalizes kernel VAs, enforces caps."""

    def __init__(self, specs: List[ColumnSpec], canonical: Callable[[int], int],
                 limit: int, deadline: float,
                 cancelled: Optional[Callable[[], bool]] = None) -> None:
        self.specs, self.canonical = specs, canonical
        self.limit, self.deadline = limit, deadline
        self.cancelled = cancelled
        self.rows: List[List[Any]] = []
        self.depths: List[int] = []
        self.absent: List[Dict[str, str]] = []

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise _Stop("timeout")
        if self.cancelled is not None and self.cancelled():
            raise _Stop("cancelled")

    def __call__(self, node: Any, accumulator: Any) -> Any:
        from volatility3.framework import interfaces
        if len(self.rows) >= self.limit:
            raise _Stop("row_limit")
        self.check()
        cells: List[Any] = []
        absent: Dict[str, str] = {}
        for spec, value in zip(self.specs, node.values):
            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                cells.append(None)
                absent[spec.name] = type(value).__name__
                continue
            cell = _convert_cell(value, spec.type)
            if spec.space == AddressSpace.KERNEL_VA.value and isinstance(cell, int):
                cell = self.canonical(cell)
            cells.append(cell)
        self.rows.append(cells)
        self.depths.append(int(node.path_depth) - 1)
        self.absent.append(absent)
        return accumulator


def run_plugin(image_ctx: Any, info: PluginInfo, args: Optional[Dict[str, Any]] = None, *,
               limit: int = DEFAULT_ROW_LIMIT, timeout_s: float = DEFAULT_TIMEOUT_S,
               column_overrides: Optional[Dict[str, Optional[str]]] = None,
               capture_id: Optional[str] = None, out_dir: Optional[Path] = None,
               progress: Optional[Callable[[float, str], None]] = None,
               cancel: Optional[Callable[[], bool]] = None) -> PluginRunResult:
    """Run one plugin against ``image_ctx`` under a row cap and a wall-clock budget.

    The budget is checked between rows and inside vol3's progress callback
    (scanners report progress), so a long scan stops too; a stopped run is
    returned with ``truncated=True`` and its ``stop_reason`` — never as a
    silently short success. ``cancel`` (polled at most every
    ``CANCEL_POLL_INTERVAL_S``) stops the run the same way with reason
    ``"cancelled"``.
    """
    coerced = coerce_arguments(info.cls, args)
    started = time.monotonic()
    # Reasons a run was stopped from inside vol3. vol3's layer scan CATCHES every
    # exception raised by its progress callback and simply stops yielding, so a
    # timed-out scan would otherwise come back as a complete, short result.
    stops: List[str] = []
    diagnostics: List[str] = []
    files = _OutputFiles(out_dir, diagnostics)
    cancelled = _CancelPoll(cancel)
    with image_ctx.lock:
        plugin, base = _construct(image_ctx, info, coerced, files, started + timeout_s,
                                  stops, progress, cancelled)
        specs: List[ColumnSpec] = []
        collector = _Collector(specs, int, limit, started + timeout_s, cancelled)
        try:
            with _read_deadline_guard(image_ctx.context, started + timeout_s, cancelled):
                try:
                    grid = plugin.run()
                    specs = column_specs(grid.columns, image_ctx.has_kernel, column_overrides)
                    canonical = image_ctx.canonical_kernel_va if image_ctx.has_kernel else int
                    collector = _Collector(specs, canonical, limit, started + timeout_s,
                                           cancelled)
                    stop = _populate(grid, collector) or (stops[0] if stops else None)
                except _DeadlineExceeded as exc:
                    # raised before the grid existed (a plugin that works eagerly in run())
                    stop = _deadline_reason(exc)
        finally:
            forget_config(image_ctx, base)
    return PluginRunResult(info.name, specs, collector.rows, collector.depths, collector.absent,
                           time.monotonic() - started, truncated=stop is not None,
                           stop_reason=stop, diagnostics=diagnostics, capture_id=capture_id,
                           files=files.written)


def _construct(image_ctx: Any, info: PluginInfo, args: Dict[str, Any], files: _OutputFiles,
               deadline: float, stops: List[str],
               progress: Optional[Callable[[float, str], None]],
               cancelled: Optional[Callable[[], bool]] = None) -> Tuple[Any, str]:
    """Configure under a fresh config path and construct; ``stops`` collects stop reasons.

    On any failure the config subtree is removed before the error propagates.
    """
    from volatility3.framework import exceptions, plugins
    base = f"memdiver_runs.r{uuid.uuid4().hex[:12]}"

    def on_progress(percent: float, description: Optional[str] = None) -> None:
        if time.monotonic() > deadline:
            stops.append("timeout")
            raise _Stop("timeout")
        if cancelled is not None and cancelled():
            stops.append("cancelled")
            raise _Stop("cancelled")
        if progress is not None:
            progress(float(percent), description or "")

    try:
        _configure(image_ctx, info.cls, base, args)
        return plugins.construct_plugin(image_ctx.context, [], info.cls, base, on_progress,
                                        files.handler_class()), base
    except exceptions.UnsatisfiedException as exc:
        forget_config(image_ctx, base)
        missing = ", ".join(sorted(p.rsplit(".", 1)[-1] for p in exc.unsatisfied))
        raise _invalid(f"{info.name}: unsatisfied requirement(s): {missing}",
                       "vol3.unsatisfied") from exc
    except BaseException:
        forget_config(image_ctx, base)
        raise


def _populate(grid: Any, collector: _Collector) -> Optional[str]:
    try:
        grid.populate(collector, None, fail_on_errors=True)
    except _Stop as stop:
        return stop.reason
    except _DeadlineExceeded as exc:
        return _deadline_reason(exc)
    return None


def _deadline_reason(exc: BaseException) -> str:
    return "cancelled" if exc.args and exc.args[0] == "cancelled" else "timeout"


def forget_config(image_ctx: Any, base: str) -> None:
    """Drop a run's config subtree so repeated runs do not accumulate state.

    vol3's ``del config[branch]`` raises ``KeyError`` for a branch, so every
    leaf under ``base`` is deleted one by one.
    """
    config = image_ctx.context.config
    for key in [k for k in config if k.startswith(base + ".")]:
        del config[key]



# -- Arrow + annotations ----------------------------------------------------------

def _arrow_type(kind: str, values: Iterable[Any]) -> Any:
    import pyarrow as pa
    if kind == "hex":
        return pa.uint64()
    if kind == "int":
        present = [v for v in values if v is not None]
        if present and max(present) > 2**63 - 1 and min(present) >= 0:
            return pa.uint64()
        return pa.int64()
    return {"bool": pa.bool_(), "float": pa.float64(), "bytes": pa.binary(),
            "datetime": pa.timestamp("us", tz="UTC")}.get(kind, pa.string())


def _arrow_value(kind: str, value: Any) -> Any:
    if value is None:
        return None
    if kind == "datetime" and isinstance(value, _dt.datetime) and value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    if kind == "hex" and isinstance(value, int) and value < 0:
        return value & 0xFFFF_FFFF_FFFF_FFFF
    return value


def _to_arrow(result: PluginRunResult) -> Any:
    import json

    import pyarrow as pa
    data: Dict[str, Any] = {}
    for index, spec in enumerate(result.columns):
        column = [_arrow_value(spec.type, row[index]) for row in result.rows]
        data[spec.name] = pa.array(column, type=_arrow_type(spec.type, column))
    data["depth"] = pa.array(result.depths, type=pa.int32())
    data["absent"] = pa.array([json.dumps(a, sort_keys=True) if a else None
                               for a in result.absent], type=pa.string())
    return pa.table(data)


def table_name(plugin: str) -> str:
    """Case table name: ``linux.pslist.PsList`` -> ``vol3__linux_pslist``."""
    module = plugin.rsplit(".", 1)[0] if plugin.count(".") >= 2 else plugin
    return "vol3__" + re.sub(r"[^a-z0-9]+", "_", module.lower()).strip("_")


def rows_to_annotations(result: PluginRunResult, column: str, *, author: str = "tool:vol3",
                        rows: Optional[Sequence[int]] = None,
                        label_column: Optional[str] = None,
                        run_ref: Optional[str] = None) -> List[Any]:
    """One ``plugin_row`` entry per selected row whose ``column`` is an address."""
    from memdiver.analysis.record import PLUGIN_ROW, AnalysisEntry, Support
    if result.capture_id is None:
        raise _invalid("the run has no capture_id; cannot file annotations", "vol3.no_capture")
    names = [c.name for c in result.columns]
    if column not in names:
        raise _invalid(f"column {column!r} is not in the result", "vol3.bad_column")
    entries = []
    for index in (range(result.row_count) if rows is None else rows):
        location = result.location(index, column)
        if location is None:
            continue
        label = (str(result.rows[index][names.index(label_column)])
                 if label_column in names else f"{result.plugin} {column}")
        payload = {"plugin": result.plugin, "column": column,
                   "row": {n: _json_cell(v) for n, v in zip(names, result.rows[index])}}
        support = (Support("vol3_run", run_ref),) if run_ref else ()
        entries.append(AnalysisEntry(capture_id=result.capture_id, kind=PLUGIN_ROW,
                                     author=author, locations=(location,), label=label,
                                     payload=payload, support=support))
    return entries
