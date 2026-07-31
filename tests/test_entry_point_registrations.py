"""Tests for register-call-based out-of-tree plugin discovery.

These exercise ``core.plugin_discovery.load_entry_point_registrations`` and its
wiring into the three register-call-based extension points that were previously
in-tree only: dump sources (``register_dump_source``), binary formats
(``register_format``) and pipeline stages (``register_stage``).

Unlike the subclass-based groups (see ``tests/test_entry_point_discovery.py``),
these points self-register via a module-level ``register_*`` call. An entry point
therefore resolves to either a **module** (imported for its side effect) or a
**callable** (invoked to self-register). We fake the advertisement by
monkeypatching ``importlib.metadata.entry_points`` — the exact API
``plugin_discovery._select_entry_points`` calls — so no real package install is
required.

Covered per group:
  (a) a callable entry point is invoked and its ``register_*`` call takes effect;
  (b) a module entry point's import side effect (its ``register_*`` call) takes
      effect;
  (c) a genuine no-op (returns 0, registers nothing) when nothing is advertised.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterator, List, Tuple

from memdiver.core import dump_source as ds
from memdiver.core.binary_formats.format_descriptor import (
    FORMAT_ENTRY_POINT_GROUP,
    FormatDescriptor,
    get_default_registry,
    register_format,
)
from memdiver.core.dump_source import (
    DUMP_SOURCE_ENTRY_POINT_GROUP,
    open_dump,
    register_dump_source,
)
from memdiver.core.plugin_discovery import load_entry_point_registrations
from memdiver.app.pipeline import pipeline_runner as pr
from memdiver.app.pipeline.pipeline_runner import (
    STAGE_ENTRY_POINT_GROUP,
    Stage,
    get_pipeline_stages,
    register_stage,
)


# --------------------------------------------------------------------------- #
# Fakes mimicking the importlib.metadata entry-point API.
# --------------------------------------------------------------------------- #
class _FakeEntryPoint:
    """Mimics ``importlib.metadata.EntryPoint``: has ``.name`` and ``.load()``.

    ``on_load`` models a module's *import side effect*: real modules run their
    module-scope ``register_*`` call when imported, and ``.load()`` is what
    triggers that import. Callable entry points leave ``on_load`` unset and let
    the loader invoke the returned object instead.
    """

    def __init__(self, name: str, obj, on_load=None) -> None:
        self.name = name
        self._obj = obj
        self._on_load = on_load

    def load(self):
        if self._on_load is not None:
            self._on_load()
        return self._obj


class _FakeEntryPoints:
    """Mimics the modern ``entry_points()`` result: ``.select(group=...)``."""

    def __init__(self, mapping: dict) -> None:
        self._mapping = mapping

    def select(self, group: str):
        return list(self._mapping.get(group, []))


def _install_entry_points(monkeypatch, mapping: dict) -> None:
    """Route ``importlib.metadata.entry_points()`` through a fake mapping."""
    monkeypatch.setattr(
        importlib.metadata, "entry_points", lambda: _FakeEntryPoints(mapping)
    )


# --------------------------------------------------------------------------- #
# Registry isolation helpers (register_* mutates module-global state).
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def _isolated_dump_source_registry():
    saved = list(ds._DUMP_SOURCE_REGISTRY)
    try:
        yield
    finally:
        ds._DUMP_SOURCE_REGISTRY[:] = saved


@contextlib.contextmanager
def _isolated_format_registry():
    reg = get_default_registry()
    saved_order = list(reg._order)
    saved_by_name = dict(reg._by_name)
    try:
        yield reg
    finally:
        reg._order[:] = saved_order
        reg._by_name.clear()
        reg._by_name.update(saved_by_name)


@contextlib.contextmanager
def _isolated_stage_registry():
    saved = list(pr._STAGE_REGISTRY)
    try:
        yield
    finally:
        pr._STAGE_REGISTRY[:] = saved


# --------------------------------------------------------------------------- #
# Dummy out-of-tree dump source.
# --------------------------------------------------------------------------- #
class _DummyDumpSource:
    """Minimal DumpSource-shaped object; open_dump only *constructs* it."""

    def __init__(self, path: Path, **_: Any) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "dummy_ep_fmt"

    @property
    def size(self) -> int:  # pragma: no cover - not exercised by dispatch
        return 0

    def size_for(self, view: str = "raw") -> int:  # pragma: no cover
        return 0

    def open(self) -> None:  # pragma: no cover
        pass

    def close(self) -> None:  # pragma: no cover
        pass

    def __enter__(self):  # pragma: no cover
        return self

    def __exit__(self, *exc: Any) -> None:  # pragma: no cover
        pass

    def read_range(self, offset: int, length: int, view: str = "raw") -> bytes:  # pragma: no cover
        return b""

    def find_all(self, needle: bytes, view: str = "raw") -> List[int]:  # pragma: no cover
        return []

    def iter_ranges(self, *a: Any, **k: Any) -> Iterator[Tuple[int, int, Any]]:  # pragma: no cover
        return iter(())

    def metadata(self) -> Dict[str, Any]:  # pragma: no cover
        return {"format": "dummy_ep_fmt"}


def _detect_dummy(path: Path, header: bytes) -> bool:
    return header[:9] == b"DUMMYSRC\x00"


def _register_dummy_source() -> None:
    register_dump_source(_detect_dummy, _DummyDumpSource, priority=50)


# --------------------------------------------------------------------------- #
# (a) callable entry point / (b) module entry point — dump sources.
# --------------------------------------------------------------------------- #
def test_dump_source_callable_entry_point_registers(monkeypatch, tmp_path):
    with _isolated_dump_source_registry():
        ep = _FakeEntryPoint("dummy_source", _register_dummy_source)
        _install_entry_points(monkeypatch, {DUMP_SOURCE_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(DUMP_SOURCE_ENTRY_POINT_GROUP)
        assert count == 1

        dump = tmp_path / "x.dummy"
        dump.write_bytes(b"DUMMYSRC\x00" + b"\x00" * 10)
        assert isinstance(open_dump(dump), _DummyDumpSource)


def test_dump_source_module_entry_point_registers(monkeypatch, tmp_path):
    with _isolated_dump_source_registry():
        module = ModuleType("memdiver._synthetic_source_module")
        ep = _FakeEntryPoint("dummy_pkg", module, on_load=_register_dummy_source)
        _install_entry_points(monkeypatch, {DUMP_SOURCE_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(DUMP_SOURCE_ENTRY_POINT_GROUP)
        assert count == 1

        dump = tmp_path / "y.dummy"
        dump.write_bytes(b"DUMMYSRC\x00" + b"\x00" * 10)
        assert isinstance(open_dump(dump), _DummyDumpSource)


def test_dump_source_builtins_intact_after_discovery(monkeypatch, tmp_path):
    """Built-in dispatch is unchanged by out-of-tree discovery."""
    with _isolated_dump_source_registry():
        ep = _FakeEntryPoint("dummy_source", _register_dummy_source)
        _install_entry_points(monkeypatch, {DUMP_SOURCE_ENTRY_POINT_GROUP: [ep]})
        load_entry_point_registrations(DUMP_SOURCE_ENTRY_POINT_GROUP)

        # A plain raw file that matches no specific detector still hits the
        # built-in raw fallback rather than the dummy source.
        raw = tmp_path / "plain.dump"
        raw.write_bytes(b"\x00" * 32)
        assert type(open_dump(raw)).__name__ == "RawDumpSource"


# --------------------------------------------------------------------------- #
# (a)/(b) formats.
# --------------------------------------------------------------------------- #
def _register_dummy_format() -> None:
    register_format(FormatDescriptor(
        name="dummy_ep_format",
        magics=(("dummy_ep_format", 0, b"DUMMYFMT"),),
    ))


def test_format_callable_entry_point_registers(monkeypatch):
    with _isolated_format_registry() as reg:
        ep = _FakeEntryPoint("dummy_format", _register_dummy_format)
        _install_entry_points(monkeypatch, {FORMAT_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(FORMAT_ENTRY_POINT_GROUP)
        assert count == 1

        assert reg.detect(b"DUMMYFMT" + b"\x00" * 8) == "dummy_ep_format"
        # Built-in detection is unchanged.
        assert reg.detect(b"\x7fELF" + b"\x02" + b"\x00" * 12) == "elf64"


def test_format_module_entry_point_registers(monkeypatch):
    with _isolated_format_registry() as reg:
        module = ModuleType("memdiver._synthetic_format_module")
        ep = _FakeEntryPoint("dummy_pkg", module, on_load=_register_dummy_format)
        _install_entry_points(monkeypatch, {FORMAT_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(FORMAT_ENTRY_POINT_GROUP)
        assert count == 1
        assert reg.detect(b"DUMMYFMT" + b"\x00" * 8) == "dummy_ep_format"


# --------------------------------------------------------------------------- #
# (a)/(b) pipeline stages.
# --------------------------------------------------------------------------- #
def _dummy_stage_run(state) -> None:  # pragma: no cover - never executed here
    pass


def _register_dummy_stage() -> None:
    register_stage(Stage(name="dummy_ep_stage", run=_dummy_stage_run))


def test_stage_callable_entry_point_registers(monkeypatch):
    with _isolated_stage_registry():
        ep = _FakeEntryPoint("dummy_stage", _register_dummy_stage)
        _install_entry_points(monkeypatch, {STAGE_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(STAGE_ENTRY_POINT_GROUP)
        assert count == 1

        names = [s.name for s in get_pipeline_stages()]
        assert "dummy_ep_stage" in names
        # Built-in stages remain present and ordered.
        assert names[:3] == ["consensus", "search_reduce", "brute_force"]


def test_stage_module_entry_point_registers(monkeypatch):
    with _isolated_stage_registry():
        module = ModuleType("memdiver._synthetic_stage_module")
        ep = _FakeEntryPoint("dummy_pkg", module, on_load=_register_dummy_stage)
        _install_entry_points(monkeypatch, {STAGE_ENTRY_POINT_GROUP: [ep]})

        count = load_entry_point_registrations(STAGE_ENTRY_POINT_GROUP)
        assert count == 1
        assert "dummy_ep_stage" in [s.name for s in get_pipeline_stages()]


# --------------------------------------------------------------------------- #
# (c) genuine no-op when nothing is advertised.
# --------------------------------------------------------------------------- #
def test_no_entry_points_is_a_noop(monkeypatch):
    _install_entry_points(monkeypatch, {})  # nothing advertised in any group

    for group in (
        DUMP_SOURCE_ENTRY_POINT_GROUP,
        FORMAT_ENTRY_POINT_GROUP,
        STAGE_ENTRY_POINT_GROUP,
    ):
        assert load_entry_point_registrations(group) == 0


def test_noop_leaves_registries_at_builtins_only(monkeypatch, tmp_path):
    _install_entry_points(monkeypatch, {})

    with _isolated_dump_source_registry():
        load_entry_point_registrations(DUMP_SOURCE_ENTRY_POINT_GROUP)
        raw = tmp_path / "plain.dump"
        raw.write_bytes(b"\x00" * 32)
        assert type(open_dump(raw)).__name__ == "RawDumpSource"

    with _isolated_format_registry() as reg:
        load_entry_point_registrations(FORMAT_ENTRY_POINT_GROUP)
        assert reg.detect(b"DUMMYFMT" + b"\x00" * 8) is None

    with _isolated_stage_registry():
        load_entry_point_registrations(STAGE_ENTRY_POINT_GROUP)
        assert "dummy_ep_stage" not in [s.name for s in get_pipeline_stages()]
