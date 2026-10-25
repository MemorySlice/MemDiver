"""``Vol3LayerSource``: a DumpSource over one view of a full memory image (plan T1.2).

The source opens a ``.mdview`` descriptor and asks a *layer adapter* for two
things only — the view's run table and the bytes of captured runs. The real
adapters (physical / kernel / process over Volatility 3 layers) are built by
:mod:`memdiver.core.image.context`; tests inject a fake one. Nothing here
imports Volatility.

Views mirror :class:`~memdiver.core.dump_source.MslDumpSource` so the hex
workspace, scanners and consensus code need no special case:

* ``"vas"`` (default) — the packed stream of CAPTURED runs; scanners use it, so
  they never walk a 2^57-byte sparse address space.
* ``"va"`` — the view's address space from :meth:`va_span_start`, padded so a
  window keeps its alignment; :meth:`read_range_valid` says which bytes are real.
* ``"raw"`` — the bytes of the image file itself.

New producers should prefer :meth:`read_location`, which returns a
:class:`~memdiver.core.location.ReadResult` with reasoned coverage (P2/P3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Sequence, Tuple

from memdiver.core.image.run_index import LayerRun, RunIndex, RunState
from memdiver.core.image.view_descriptor import ViewDescriptor, ViewKind
from memdiver.core.location import AddressSpace, Location, ReadResult

#: Largest single adapter read / search window, in bytes.
CHUNK = 8 * 1024 * 1024

#: Largest integer a JavaScript ``number`` holds exactly. The web workspace
#: addresses the ``"va"`` view with plain numbers, so a view whose last address
#: exceeds this (a kernel view spans ~2^56, its addresses 2^63+) must not be
#: offered: the browser would silently round every offset it displays.
JS_SAFE_INTEGER = 2 ** 53 - 1

_SPACE_FOR_VIEW = {ViewKind.PHYSICAL: AddressSpace.PHYSICAL,
                   ViewKind.KERNEL: AddressSpace.KERNEL_VA,
                   ViewKind.PROCESS: AddressSpace.PROCESS_VA}


class LayerAdapter(Protocol):
    """What a :class:`Vol3LayerSource` needs from the layer behind a view."""

    def runs(self) -> Sequence[LayerRun]:
        """The view's run table (any order; must not overlap)."""
        ...

    def read(self, address: int, length: int) -> bytes:
        """Exactly ``length`` bytes from inside ONE captured run."""
        ...

    def describe(self) -> Dict[str, Any]:
        """JSON-safe facts about the layer (class, DTB, paging levels, ...)."""
        ...

    def close(self) -> None:
        ...


AdapterFactory = Callable[[ViewDescriptor, Path], LayerAdapter]


def _default_adapter_factory(descriptor: ViewDescriptor, path: Path) -> LayerAdapter:
    from memdiver.core.image.context import adapter_for  # lazy: imports Volatility
    return adapter_for(descriptor, path)


class Vol3LayerSource:
    """DumpSource for a ``.mdview`` descriptor (physical, kernel or process view)."""

    SUPPORTED_VIEWS: Tuple[str, ...] = ("raw", "vas", "va")
    DISTINCT_VIEWS: Tuple[str, ...] = ("vas", "va", "raw")

    def __init__(self, path: Path, adapter_factory: Optional[AdapterFactory] = None) -> None:
        self._path = Path(path)
        self._factory = adapter_factory or _default_adapter_factory
        self._descriptor: Optional[ViewDescriptor] = None
        self._adapter: Optional[LayerAdapter] = None
        self._index: Optional[RunIndex] = None

    # -- identity -----------------------------------------------------------
    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "image_view"

    @property
    def size(self) -> int:
        return self.size_for("vas")

    @property
    def descriptor(self) -> ViewDescriptor:
        if self._descriptor is None:
            self._descriptor = ViewDescriptor.read(self._path)
        return self._descriptor

    def size_for(self, view: str = "vas") -> int:
        if view == "raw":
            return self._image_path().stat().st_size
        if self._index is None:
            return 0
        return self._index.span_size if view == "va" else self._index.vas_size

    # -- lifecycle ----------------------------------------------------------
    def open(self) -> None:
        if self._adapter is not None:
            return
        adapter = self._factory(self.descriptor, self._path)
        self._index = RunIndex(adapter.runs())
        self._adapter = adapter
        self._restrict_views_to_exact_addresses()

    def close(self) -> None:
        if self._adapter is not None:
            self._adapter.close()
        self._adapter = None
        self._index = None
        self._drop_view_overrides()

    def __enter__(self) -> "Vol3LayerSource":
        self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- reads --------------------------------------------------------------
    def read_range(self, offset: int, length: int, view: str = "vas") -> bytes:
        return self.read_range_valid(offset, length, view)[0]

    def read_range_valid(self, offset: int, length: int,
                         view: str = "vas") -> Tuple[bytes, List[Tuple[int, int]]]:
        """``(data, result-relative captured runs)`` — only ``"va"`` ever pads."""
        if view == "raw":
            data = self._read_raw(offset, length)
        elif view == "vas":
            data = self._read_vas(offset, length)
        elif view == "va":
            return self._read_va(offset, length)
        else:
            raise ValueError(f"unsupported view {view!r}")
        return data, ([(0, len(data))] if data else [])

    def read_all(self, view: str = "vas") -> bytes:
        return self.read_range(0, self.size_for(view), view)

    def read_location(self, address: int, length: int) -> ReadResult:
        """Read ``[address, address+length)`` in the view's own address space."""
        index, adapter = self._require_open()
        buf = bytearray(length)
        for start, size, state in index.pieces(address, length):
            if state is RunState.CAPTURED:
                buf[start - address:start - address + size] = adapter.read(start, size)
        return ReadResult(self.location(address), bytes(buf), index.coverage(address, length))

    def location(self, address: int) -> Location:
        """A :class:`Location` for ``address`` in this view's coordinate system."""
        desc = self.descriptor
        return Location(_SPACE_FOR_VIEW[desc.view], address, capture_id=desc.capture_id,
                        pid=desc.pid, view=self._path.name)

    # -- search -------------------------------------------------------------
    def find_all(self, needle: bytes, view: str = "vas") -> List[int]:
        return list(self._iter_matches(needle, view))

    def find_first(self, needle: bytes, view: str = "vas") -> Optional[int]:
        return next(self._iter_matches(needle, view), None)

    # -- run table ----------------------------------------------------------
    def iter_ranges(self) -> Iterator[Tuple[int, int, bytes]]:
        """``(va, length, bytes)`` per captured stretch, in chunks of at most CHUNK."""
        index, adapter = self._require_open()
        for run in index.captured:
            for start in range(run.va_start, run.va_start + run.length, CHUNK):
                size = min(CHUNK, run.va_start + run.length - start)
                yield start, size, adapter.read(start, size)

    def captured_runs(self) -> Tuple[Tuple[int, int, int], ...]:
        """``(va_start, length, vas_offset)`` per captured run (no bytes)."""
        index, _ = self._require_open()
        return tuple((r.va_start, r.length, r.vas_offset) for r in index.captured)

    def layer_runs(self) -> Tuple[LayerRun, ...]:
        """The full run table (captured AND failed/not-resident runs, with state)."""
        index, _ = self._require_open()
        return index.runs

    def vmas(self) -> List[Any]:
        """VMAs of a process view (``[]`` for physical/kernel views)."""
        _, adapter = self._require_open()
        listing = getattr(adapter, "vmas", None)
        return list(listing()) if callable(listing) else []

    def va_span_start(self) -> Optional[int]:
        return self._index.span_start if self._index is not None else None

    def metadata(self) -> Dict[str, Any]:
        desc = self.descriptor
        out: Dict[str, Any] = {"format": self.format_name, "path": str(self._path),
                               **desc.to_dict(), "capture_id": desc.capture_id,
                               "raw_size": self.size_for("raw")}
        if self._index is not None and self._adapter is not None:
            out.update(vas_size=self.size_for("vas"), va_size=self.size_for("va"),
                       va_span_start=self._index.span_start,
                       layer=self._adapter.describe())
        return out

    # -- internals ----------------------------------------------------------
    def _restrict_views_to_exact_addresses(self) -> None:
        """Hide ``"va"`` when its addresses exceed what a JS number holds.

        Shadows the class-level view tuples with instance attributes (read by
        ``core.dump_source.supported_views`` / ``distinct_views`` through
        ``getattr``), so a kernel view is never offered, nor served, as "va".
        """
        index = self._index
        if index is None or index.span_start + index.span_size <= JS_SAFE_INTEGER:
            return
        self.SUPPORTED_VIEWS = tuple(v for v in type(self).SUPPORTED_VIEWS if v != "va")
        self.DISTINCT_VIEWS = tuple(v for v in type(self).DISTINCT_VIEWS if v != "va")

    def _drop_view_overrides(self) -> None:
        self.__dict__.pop("SUPPORTED_VIEWS", None)
        self.__dict__.pop("DISTINCT_VIEWS", None)

    def _require_open(self) -> Tuple[RunIndex, LayerAdapter]:
        if self._index is None or self._adapter is None:
            raise RuntimeError(f"{self.name} is not open")
        return self._index, self._adapter

    def _image_path(self) -> Path:
        return self.descriptor.image_path(self._path)

    def _read_raw(self, offset: int, length: int) -> bytes:
        with open(self._image_path(), "rb") as fh:
            fh.seek(offset)
            return fh.read(max(length, 0))

    def _read_vas(self, offset: int, length: int) -> bytes:
        index, adapter = self._require_open()
        return b"".join(adapter.read(va, size) for va, size in index.vas_pieces(offset, length))

    def _read_va(self, offset: int, length: int) -> Tuple[bytes, List[Tuple[int, int]]]:
        index, adapter = self._require_open()
        length = max(min(length, index.span_size - offset), 0)
        base = index.span_start + offset
        buf, runs = bytearray(length), []
        for start, size, state in index.pieces(base, length):
            if state is RunState.CAPTURED:
                buf[start - base:start - base + size] = adapter.read(start, size)
                runs.append((start - base, size))
        return bytes(buf), runs

    def _iter_matches(self, needle: bytes, view: str) -> Iterator[int]:
        """Matches inside captured runs only — never across a gap between runs."""
        if not needle:
            return
        if view == "raw":
            yield from _scan(self._read_raw, 0, self.size_for("raw"), needle)
            return
        index, adapter = self._require_open()
        for run in index.captured:
            for hit in _scan(adapter.read, run.va_start, run.length, needle):
                yield (run.vas_offset + hit - run.va_start if view == "vas"
                       else hit - index.span_start)


def _scan(read: Callable[[int, int], bytes], start: int, length: int,
          needle: bytes) -> Iterator[int]:
    """Absolute offsets of ``needle`` in ``[start, start+length)``, read CHUNK at a time."""
    overlap, cursor, end = len(needle) - 1, start, start + length
    while cursor < end:
        size = min(CHUNK + overlap, end - cursor)
        data = read(cursor, size)
        pos = data.find(needle)
        while pos != -1:
            if pos < CHUNK or cursor + CHUNK >= end:  # tail is the next window's
                yield cursor + pos
            pos = data.find(needle, pos + 1)
        cursor += CHUNK
