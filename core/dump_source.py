"""DumpSource implementations and auto-detect factory."""

import itertools
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)

from .dump_io import DumpReader, find_all_offsets, find_first_offset

logger = logging.getLogger("memdiver.core.dump_source")

ViewMode = Literal["raw", "vas", "va"]


@runtime_checkable
class DumpSource(Protocol):
    """Structural contract shared by every dump-format source.

    Historically each concrete source (:class:`RawDumpSource`,
    :class:`MslDumpSource`, :class:`core.dump_sources.gcore.GCoreDumpSource`
    and the ``_RegionedRawSource`` subclasses) re-implemented this contract
    independently, documented only in prose. This Protocol makes it explicit
    so callers can type against ``DumpSource`` and new sources have a checklist
    to satisfy.

    It is ``runtime_checkable``: ``isinstance(obj, DumpSource)`` succeeds for
    any object exposing the members below (presence only — the check does not
    inspect signatures). All built-in sources satisfy it.

    Note on ``read_all``: only :class:`RawDumpSource` and
    :class:`MslDumpSource` provide a ``read_all(view)`` convenience that
    materialises the whole view into ``bytes``. The regioned-raw and gcore
    sources deliberately omit it (their views can be multi-GB and are meant to
    be streamed via :meth:`iter_ranges` / sliced via :meth:`read_range`), so
    ``read_all`` is NOT part of this universal structural contract. General
    callers must feature-test with ``hasattr`` before calling.

    Caveat — some engine paths still assume ``read_all``: the raw (non-MSL)
    branch of the consensus builder (:func:`app.pipeline.pipeline_runner._build_consensus`)
    calls ``read_all()`` on every source. A source lacking it (gcore / regioned
    raw) therefore cannot currently be fed into that raw-consensus path. This is
    a pre-existing engine assumption, not a guarantee of this Protocol; migrating
    that path onto :meth:`iter_ranges` is a tracked follow-up.
    """

    # -- Identity / metadata ------------------------------------------------
    @property
    def path(self) -> Path:
        """Filesystem path of the backing dump file."""
        ...

    @property
    def name(self) -> str:
        """Basename of the backing dump file."""
        ...

    @property
    def format_name(self) -> str:
        """Short format identifier (e.g. ``"raw"``, ``"msl"``, ``"gcore"``)."""
        ...

    @property
    def size(self) -> int:
        """Default size in bytes (the format's canonical view for scanners)."""
        ...

    def size_for(self, view: str = ...) -> int:
        """Size in bytes of the requested byte *view* (``"raw"``/``"vas"``…)."""
        ...

    # -- Lifecycle / context manager ---------------------------------------
    def open(self) -> None:
        """Acquire underlying resources (mmap, reader, region tables)."""
        ...

    def close(self) -> None:
        """Release resources acquired by :meth:`open`."""
        ...

    def __enter__(self) -> "DumpSource":
        ...

    def __exit__(self, *exc: Any) -> Any:
        ...

    # -- Data access --------------------------------------------------------
    def read_range(self, offset: int, length: int, view: str = ...) -> bytes:
        """Read ``length`` bytes starting at ``offset`` within *view*."""
        ...

    def find_all(self, needle: bytes, view: str = ...) -> List[int]:
        """Return all offsets of ``needle`` within *view* (may overlap)."""
        ...

    # NOTE: ``find_first`` is deliberately NOT a member of this Protocol.
    # This Protocol is ``runtime_checkable``, and such a check verifies method
    # PRESENCE, so adding a member here would instantly make every existing
    # duck-typed or third-party source registered via
    # :func:`register_dump_source` fail ``isinstance(obj, DumpSource)``. (A
    # default body would not help: Protocol defaults are only inherited by
    # explicit subclasses, and the isinstance check still only looks at
    # attribute presence.) Every built-in source implements ``find_first``
    # anyway; callers must go through the tolerant module-level helper
    # :func:`find_first_in`, which falls back to ``find_all`` for sources that
    # predate it.

    def iter_ranges(self, *args: Any, **kwargs: Any) -> Iterator[Tuple[int, int, Any]]:
        """Iterate captured ranges.

        The third tuple element varies by source (inline ``bytes`` for MSL, a
        file offset ``int`` for the region-table sources); callers that need
        uniform bytes should use :meth:`read_range`.
        """
        ...

    def metadata(self) -> Dict[str, Any]:
        """Return a JSON-serialisable descriptor of the dump."""
        ...


def _find_all_in_bytes(data: bytes, needle: bytes) -> List[int]:
    """Overlapping-aware byte search over *data* (delegates to the shared
    :func:`core.dump_io.find_all_offsets` helper used by ``DumpReader``)."""
    return find_all_offsets(data, needle)


def _find_first_in_bytes(data: bytes, needle: bytes) -> Optional[int]:
    """Presence-only byte search over *data* (delegates to the shared
    :func:`core.dump_io.find_first_offset` helper used by ``DumpReader``)."""
    return find_first_offset(data, needle)


def find_first_in(
    source: Any, needle: bytes, view: "str | None" = None,
) -> Optional[int]:
    """Presence-only search over a dump *source*, tolerant of older sources.

    Returns the first offset of ``needle`` in the requested *view*, or ``None``
    when it does not occur. Uses the source's own ``find_first`` when it has
    one (a single ``.find()`` with an early exit — the cheap path a
    corpus-scale "is this secret present?" sweep needs); otherwise falls back
    to the first element of ``find_all``, so a custom source registered via
    :func:`register_dump_source` keeps working without implementing a new
    method.

    This fallback is the reason ``find_first`` is NOT part of the
    :class:`DumpSource` Protocol: that Protocol is ``runtime_checkable``, so
    widening it would break ``isinstance(obj, DumpSource)`` for every existing
    duck-typed source. Prefer this helper over calling the method directly.

    ``view`` is forwarded only when the caller supplies it, so each
    implementation keeps its own default view (``"raw"`` for
    :class:`RawDumpSource` and the region-table sources, ``"vas"`` for
    :class:`MslDumpSource`).
    """
    kwargs = {} if view is None else {"view": view}
    finder = getattr(source, "find_first", None)
    if callable(finder):
        return finder(needle, **kwargs)
    hits = source.find_all(needle, **kwargs)
    return hits[0] if hits else None


class RawDumpSource:
    """DumpSource for raw binary .dump files."""

    def __init__(self, path: Path):
        self._path = path
        self._reader = DumpReader(path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "raw"

    @property
    def size(self) -> int:
        return self._reader.size

    @staticmethod
    def _check_view(view: ViewMode) -> None:
        """Reject an unknown view, as every other source already does.

        A flat dump has no region table, so its raw and virtual views coincide
        and ``"vas"``/``"va"`` are accepted as aliases of ``"raw"``. What is NOT
        acceptable is silently treating a TYPO as the default: this class backs
        every plain ``.dump``/``.bin`` in the corpus, so a caller that passed
        ``view="vsa"`` used to get raw-view results here while the very same
        typo is a loud ``ValueError`` on MSL, gcore and the regioned sources.
        A corpus sweep that mixes formats would then get silently
        format-dependent behaviour from one argument.
        """
        if view not in ("raw", "vas", "va"):
            raise ValueError(
                f"Unknown view: {view!r} (expected 'raw'; 'vas'/'va' are "
                "accepted as aliases because a flat dump's views coincide)"
            )

    def size_for(self, view: ViewMode = "raw") -> int:
        self._check_view(view)
        return self._reader.size

    def open(self) -> None:
        self._reader.open()

    def close(self) -> None:
        self._reader.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def _ensure_open(self) -> None:
        if self._reader._mmap is None:
            self._reader.open()

    def read_all(self, view: ViewMode = "raw") -> bytes:
        self._check_view(view)
        self._ensure_open()
        return self._reader.read_all()

    def read_range(self, offset: int, length: int, view: ViewMode = "raw") -> bytes:
        self._check_view(view)
        self._ensure_open()
        return self._reader.read_range(offset, length)

    def find_all(self, needle: bytes, view: ViewMode = "raw") -> List[int]:
        self._check_view(view)
        self._ensure_open()
        return self._reader.find_all(needle)

    def find_first(self, needle: bytes, view: ViewMode = "raw") -> Optional[int]:
        self._check_view(view)
        self._ensure_open()
        return self._reader.find_first(needle)

    def iter_ranges(self) -> Iterator[Tuple[int, int, bytes]]:
        data = self.read_all()
        if data:
            yield (0, len(data), data)

    def metadata(self) -> Dict[str, Any]:
        return {"format": "raw", "path": str(self._path)}


class MslDumpSource:
    """DumpSource for Memory Slice (.msl) files.

    Exposes two byte views of the same file: ``view="raw"`` reads the
    .msl container bytes directly (file/block headers, payloads, hash
    chain), and ``view="vas"`` reads a flattened projection of captured
    memory regions ordered by base address. Scanners default to VAS;
    UI endpoints pass ``view="raw"`` to inspect the container.
    """

    def __init__(self, path: Path, *,
                 key: "bytes | None" = None,
                 passphrase: "bytes | None" = None,
                 kem_private_key: "bytes | None" = None):
        self._path = path
        self._reader = None
        self._size: int = -1
        # Cached (span_start, span_size) for the sparse "va" view; None until
        # first computed. Derived from region base addresses, which are fixed
        # for a reader's lifetime.
        self._va_span_cache: "Tuple[int, int] | None" = None
        # close() is a no-op when True; reader lifetime is owned by the
        # caller (see borrow_reader).
        self._borrowed: bool = False
        self._raw_reader: "DumpReader | None" = None
        # Key material for encrypted .msl files (spec §10); None for plaintext.
        self._key = key
        self._passphrase = passphrase
        self._kem_private_key = kem_private_key

    @classmethod
    def borrow_reader(cls, path: Path, reader) -> "MslDumpSource":
        """Construct an MslDumpSource around an already-open MslReader.

        The resulting source borrows the reader; close() is a no-op and the
        reader's lifecycle stays with the caller. Used by the reader cache
        service to hand out DumpSource handles backed by pooled readers
        without double-opening the file.
        """
        source = cls(Path(path))
        source._reader = reader
        source._size = -1
        source._borrowed = True
        return source

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "msl"

    @property
    def size(self) -> int:
        # VAS size preserved as the default for scanner back-compat;
        # UI callers use size_for("raw") for the container size.
        return self.size_for("vas")

    def size_for(self, view: ViewMode = "vas") -> int:
        if view == "raw":
            try:
                return self._path.stat().st_size
            except OSError:
                return 0
        if view == "va":
            # Full virtual-address span (sparse); served on demand, never
            # materialized. Zero when there is no open reader / no regions.
            return self._va_span()[1]
        if self._reader is None:
            return 0
        if self._size < 0:
            # The "vas" stream is the flattened concatenation of CAPTURED
            # page runs only (see read_range/iter_ranges), so its size is the
            # sum of captured-run lengths — NOT the sum of region_size, which
            # over-counts FAILED/UNMAPPED pages that contribute zero bytes.
            # (For all-CAPTURED imports the two are equal.) iter_ranges yields
            # zero-copy memoryviews, so summing lengths does not read data.
            self._size = sum(rng_len for _va, rng_len, _chunk in self.iter_ranges())
        return self._size

    def _va_span(self) -> Tuple[int, int]:
        """Return the cached ``(span_start, span_size)`` of the "va" view.

        ``span_start = min(region.base_addr)`` and
        ``span_end = max(region.base_addr + region.region_size)`` over all
        regions; the span is ``span_end - span_start``. This can be huge
        (the process VA range) and is intentionally NOT materialized —
        :meth:`_read_range_va` serves slices on demand.
        """
        if self._va_span_cache is None:
            if self._reader is None:
                return (0, 0)
            regions = self._reader.collect_regions()
            if not regions:
                self._va_span_cache = (0, 0)
            else:
                start = min(r.base_addr for r in regions)
                end = max(r.base_addr + r.region_size for r in regions)
                self._va_span_cache = (start, max(0, end - start))
        return self._va_span_cache

    def _ensure_raw_reader(self) -> DumpReader:
        """Lazily open a DumpReader over the raw .msl container bytes."""
        if self._raw_reader is None:
            self._raw_reader = DumpReader(self._path)
        if self._raw_reader._mmap is None:
            self._raw_reader.open()
        return self._raw_reader

    @staticmethod
    def _require_vas(view: ViewMode) -> None:
        """Defensive guard for the else-branch of view dispatch.

        The public API is typed `ViewMode = Literal["raw", "vas"]`, but
        dynamic callers can still pass a bad value at runtime. Rather
        than silently executing the VAS branch for `view="garbage"`,
        surface the error.
        """
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")

    def open(self) -> None:
        from memdiver.msl.reader import MslReader
        self._reader = MslReader(
            self._path, key=self._key, passphrase=self._passphrase,
            kem_private_key=self._kem_private_key,
        )
        self._reader.open()
        self._size = -1
        self._va_span_cache = None

    @property
    def tag_status(self):
        """AEAD tag-verification status of the underlying reader (spec §10).
        TagStatus.NOT_ENCRYPTED for plaintext files."""
        from memdiver.msl.enums import TagStatus
        return self._reader.tag_status if self._reader is not None else TagStatus.NOT_ENCRYPTED

    def close(self) -> None:
        if self._raw_reader is not None:
            self._raw_reader.close()
            self._raw_reader = None
        if self._borrowed:
            # Reader ownership stays with the external holder; just detach.
            self._reader = None
            self._size = -1
            self._va_span_cache = None
            return
        if self._reader:
            self._reader.close()
            self._reader = None
        self._size = -1
        self._va_span_cache = None

    def get_reader(self):
        """Return the underlying MslReader (must be opened first)."""
        if self._reader is None:
            raise RuntimeError("MslDumpSource not opened; use context manager")
        return self._reader

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def read_all(self, view: ViewMode = "vas") -> bytes:
        if view == "raw":
            return self._ensure_raw_reader().read_all()
        self._require_vas(view)
        return b"".join(chunk for _, _, chunk in self.iter_ranges())

    def read_range(self, offset: int, length: int, view: ViewMode = "vas") -> bytes:
        if view == "raw":
            return self._ensure_raw_reader().read_range(offset, length)
        if view == "va":
            return self._read_range_va(offset, length)
        self._require_vas(view)
        result, flat_pos = bytearray(), 0
        for _va, rng_len, chunk in self.iter_ranges():
            rng_end = flat_pos + rng_len
            if rng_end <= offset:
                flat_pos = rng_end
                continue
            if flat_pos >= offset + length:
                break
            s, e = max(0, offset - flat_pos), min(rng_len, offset + length - flat_pos)
            result.extend(chunk[s:e])
            flat_pos = rng_end
        return bytes(result)

    def _read_range_va(self, offset: int, length: int) -> bytes:
        """Serve the sparse full-VA view on demand (see class docstring).

        ``offset`` is relative to the VA span start (``_va_span()[0]``), so
        the requested VA window is ``[span_start + offset, +length)``. Returns
        a zero-filled buffer of ``length`` bytes with CAPTURED pages copied in
        at their VA-relative positions; FAILED/UNMAPPED/gap positions stay
        ``0x00``. Callers rely on ``/page-states`` — not the byte values — to
        tell real captured bytes from filler. The full span is never
        materialized; only the overlapping captured runs are copied.
        """
        if length <= 0 or self._reader is None:
            return b""
        span_start, _span_size = self._va_span()
        req_start = span_start + offset
        req_end = req_start + length
        buf = bytearray(length)
        for vaddr, clen, chunk in self.iter_ranges():
            c_end = vaddr + clen
            if c_end <= req_start:
                continue
            if vaddr >= req_end:
                break  # iter_ranges is ascending by VA — nothing further overlaps
            ov_start = max(vaddr, req_start)
            ov_end = min(c_end, req_end)
            buf[ov_start - req_start:ov_end - req_start] = \
                chunk[ov_start - vaddr:ov_end - vaddr]
        return bytes(buf)

    def find_all(self, needle: bytes, view: ViewMode = "vas") -> List[int]:
        if view == "raw":
            return self._ensure_raw_reader().find_all(needle)
        self._require_vas(view)
        if self._reader is None:
            return []
        offsets = []
        flat_offset = 0
        for _vaddr, _length, chunk in self.iter_ranges():
            for idx in _find_all_in_bytes(chunk, needle):
                offsets.append(flat_offset + idx)
            flat_offset += len(chunk)
        return offsets

    def find_first(self, needle: bytes, view: ViewMode = "vas") -> Optional[int]:
        """First offset of ``needle`` in *view*, or ``None`` (presence query).

        Mirrors :meth:`find_all` exactly, including its per-captured-run
        semantics: each run is searched on its own, so a needle straddling the
        boundary between two captured runs is not reported by either method.
        The only difference is the early exit - iteration stops at the first
        hit, so a present secret costs one partial pass rather than a full
        VAS projection.
        """
        if view == "raw":
            return self._ensure_raw_reader().find_first(needle)
        self._require_vas(view)
        if self._reader is None:
            return None
        flat_offset = 0
        for _vaddr, _length, chunk in self.iter_ranges():
            idx = _find_first_in_bytes(chunk, needle)
            if idx is not None:
                return flat_offset + idx
            flat_offset += len(chunk)
        return None

    def va_to_vas_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a flat VAS offset.

        Returns the offset into the ``view="vas"`` byte stream where the
        captured bytes for ``va`` live, or ``None`` if ``va`` falls
        outside any captured page.
        """
        if self._reader is None:
            return None
        flat_pos = 0
        for vaddr, length, _chunk in self.iter_ranges():
            if vaddr <= va < vaddr + length:
                return flat_pos + (va - vaddr)
            flat_pos += length
        return None

    def va_to_file_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a file offset in the .msl container.

        Returns the file offset of the MEMORY_REGION or MODULE_ENTRY
        block header whose address range contains ``va``. Landing on
        the block header (rather than the middle of a payload) gives
        a useful forensic anchor in raw view.
        """
        if self._reader is None:
            return None
        for region in self._reader.collect_regions():
            if region.base_addr <= va < region.base_addr + region.region_size:
                return region.block_header.file_offset
        for mod in self._reader.collect_modules():
            if mod.base_addr <= va < mod.base_addr + mod.module_size:
                return mod.block_header.file_offset
        return None

    def iter_ranges(self) -> Iterator[Tuple[int, int, bytes]]:
        if self._reader is None:
            return
        from memdiver.msl.page_map import iter_captured_ranges
        regions = self._reader.collect_regions()
        regions.sort(key=lambda r: r.base_addr)
        for region in regions:
            page_data = self._get_region_page_data(region)
            for vaddr, length, chunk in iter_captured_ranges(
                region.page_states, page_data,
                region.base_addr, region.page_size,
            ):
                yield (vaddr, length, bytes(chunk))

    def metadata(self) -> Dict[str, Any]:
        if self._reader is None:
            return {
                "format": "msl",
                "path": str(self._path),
                "raw_size": self.size_for("raw"),
            }
        hdr = self._reader.file_header
        return {
            "format": "msl",
            "path": str(self._path),
            "dump_uuid": str(hdr.dump_uuid),
            "pid": hdr.pid,
            "os_type": hdr.os_type,
            "arch_type": hdr.arch_type,
            "version": f"{hdr.version_major}.{hdr.version_minor}",
            "raw_size": self.size_for("raw"),
            "vas_size": self.size_for("vas"),
            # Sparse full virtual-address view (Phase 2). va_size is the total
            # span (span_end - span_start); va_span_start is the base VA so a
            # UI can map a "va" offset back to an absolute virtual address.
            "va_size": self.size_for("va"),
            "va_span_start": self._va_span()[0],
        }

    def _get_region_page_data(self, region) -> bytes:
        from .msl_helpers import get_region_page_data
        return get_region_page_data(self._reader, region)

# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------
#
# ``open_dump`` used to be a hand-maintained if/elif chain. The registry
# replaces that chain with an ordered, extensible list so new dump formats can
# be supported without editing ``open_dump``. Each entry pairs a *detector*
# (does this file look like my format?) with a *factory* (build the source).
#
# A detector is ``detector(path, header_bytes) -> bool``; ``header_bytes`` is
# the first :data:`_HEADER_PROBE_LEN` bytes of the file (empty on read error).
#
# A factory is ``factory(path, **key_material) -> DumpSource``. It is always
# called with the ``key`` / ``passphrase`` / ``kem_private_key`` keyword
# arguments ``open_dump`` received; factories that do not use key material
# simply accept and ignore ``**_`` (see the built-in wrappers below).
#
# Entries are tried in descending ``priority``; ties break by registration
# order (stable). The built-ins reserve high priorities to preserve the exact
# legacy precedence (MSL > ELF core > gdb suffix > lldb suffix > raw). A custom
# source registered with the default ``priority=0`` therefore slots in *after*
# every built-in specific detector but *before* the always-matching raw
# fallback — the intended "add a new format" position.

DetectorFn = Callable[[Path, bytes], bool]
DumpSourceFactory = Callable[..., DumpSource]  # called as factory(path, **key_material)

_HEADER_PROBE_LEN = 18

# Priority tiers for the built-in sources (see module comment above).
_PRIORITY_MSL = 100
_PRIORITY_ELF_CORE = 90
_PRIORITY_GDB_RAW = 80
_PRIORITY_LLDB_RAW = 70
_PRIORITY_RAW_FALLBACK = -1_000_000  # always-matching catch-all; stays last


@dataclass(frozen=True)
class _DumpSourceEntry:
    """One (detector, factory) registration with its dispatch priority."""

    priority: int
    order: int  # registration sequence; stable tie-breaker within a priority
    detector: DetectorFn
    factory: DumpSourceFactory


_DUMP_SOURCE_REGISTRY: List[_DumpSourceEntry] = []
_registration_counter = itertools.count()


def register_dump_source(
    detector: DetectorFn,
    factory: DumpSourceFactory,
    *,
    priority: int = 0,
) -> None:
    """Register a dump-source detector/factory pair for :func:`open_dump`.

    ``detector(path, header_bytes) -> bool`` decides whether *path* is this
    format; ``header_bytes`` holds the file's first
    :data:`_HEADER_PROBE_LEN` bytes. ``factory(path, **key_material)`` builds
    the source and is invoked with the ``key`` / ``passphrase`` /
    ``kem_private_key`` keywords ``open_dump`` received (accept ``**_`` to
    ignore them).

    ``priority`` orders detection: higher is tried first, ties break by
    registration order. The default (``0``) places a custom source after all
    built-in specific detectors but ahead of the always-matching raw fallback,
    which is the correct slot for a genuinely new format. Pass a higher value
    to pre-empt a built-in detector.
    """
    entry = _DumpSourceEntry(
        priority=priority,
        order=next(_registration_counter),
        detector=detector,
        factory=factory,
    )
    _DUMP_SOURCE_REGISTRY.append(entry)
    # Keep the list ready-sorted so open_dump can iterate directly.
    _DUMP_SOURCE_REGISTRY.sort(key=lambda e: (-e.priority, e.order))


# -- Built-in detectors ------------------------------------------------------


def _detect_msl(path: Path, header: bytes) -> bool:
    from memdiver.msl.enums import FILE_MAGIC
    return header[:8] == FILE_MAGIC


def _detect_elf_core(path: Path, header: bytes) -> bool:
    # ELF core dump: \x7fELF magic + e_type == ET_CORE (4) at offset 16.
    # e_type's byte order follows EI_DATA (header[5]): 1=ELFDATA2LSB
    # (little-endian), 2=ELFDATA2MSB (big-endian). Reading it unconditionally
    # little-endian would misdetect big-endian cores.
    if header[:4] == b"\x7fELF" and len(header) >= 18:
        byteorder = "big" if header[5] == 2 else "little"
        return int.from_bytes(header[16:18], byteorder) == 4  # ET_CORE
    return False


def _detect_gdb_raw(path: Path, header: bytes) -> bool:
    name = path.name
    return name.endswith("gdb_raw.bin") and not name.endswith("lldb_raw.bin")


def _detect_lldb_raw(path: Path, header: bytes) -> bool:
    return path.name.endswith("lldb_raw.bin")


def _detect_raw_fallback(path: Path, header: bytes) -> bool:
    return True  # opaque catch-all; always matches, registered lowest priority


# -- Built-in factories ------------------------------------------------------
#
# All accept ``**key_material`` for a uniform call site; only the MSL factory
# consumes it (encrypted .msl containers, spec §10).


def _make_msl(path: Path, **key_material: Any) -> DumpSource:
    return MslDumpSource(
        path,
        key=key_material.get("key"),
        passphrase=key_material.get("passphrase"),
        kem_private_key=key_material.get("kem_private_key"),
    )


def _make_gcore(path: Path, **_: Any) -> DumpSource:
    from memdiver.core.dump_sources.gcore import GCoreDumpSource
    return GCoreDumpSource(path)


def _make_gdb_raw(path: Path, **_: Any) -> DumpSource:
    from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
    return GdbRawDumpSource(path)


def _make_lldb_raw(path: Path, **_: Any) -> DumpSource:
    from memdiver.core.dump_sources.lldb_raw import LldbRawDumpSource
    return LldbRawDumpSource(path)


def _make_raw(path: Path, **_: Any) -> DumpSource:
    return RawDumpSource(path)


def _register_builtin_sources() -> None:
    """Register the built-in sources, preserving the legacy dispatch order."""
    register_dump_source(_detect_msl, _make_msl, priority=_PRIORITY_MSL)
    register_dump_source(_detect_elf_core, _make_gcore, priority=_PRIORITY_ELF_CORE)
    register_dump_source(_detect_gdb_raw, _make_gdb_raw, priority=_PRIORITY_GDB_RAW)
    register_dump_source(_detect_lldb_raw, _make_lldb_raw, priority=_PRIORITY_LLDB_RAW)
    register_dump_source(_detect_raw_fallback, _make_raw, priority=_PRIORITY_RAW_FALLBACK)


#: Entry-point group under which out-of-tree packages advertise dump sources.
#: Each advertised entry point is a module (imported for its
#: ``register_dump_source`` side effects) or a callable (invoked to
#: self-register). See ``docs/contributing/adding_dump_source.md``.
DUMP_SOURCE_ENTRY_POINT_GROUP = "memdiver.dump_sources"

#: Guards one-time out-of-tree discovery so it runs at most once, adding zero
#: overhead to normal :func:`open_dump` calls.
_ENTRY_POINTS_LOADED = False


def _load_entry_point_sources_once() -> None:
    """Load out-of-tree dump sources exactly once, after the built-ins.

    Additive and failure-isolated: a silent no-op when nothing is installed.
    """
    global _ENTRY_POINTS_LOADED  # noqa: PLW0603
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    from memdiver.core.plugin_discovery import load_entry_point_registrations
    load_entry_point_registrations(DUMP_SOURCE_ENTRY_POINT_GROUP)


_register_builtin_sources()
_load_entry_point_sources_once()


def open_dump(path: Path, *,
              key: "bytes | None" = None,
              passphrase: "bytes | None" = None,
              kem_private_key: "bytes | None" = None) -> "RawDumpSource | MslDumpSource | GdbRawDumpSource | LldbRawDumpSource | GCoreDumpSource | DumpSource":  # noqa: F821
    """Auto-detect dump format and return appropriate DumpSource.

    Detection runs through the extensible detector registry (see
    :func:`register_dump_source`), which preserves the legacy dispatch order:
      1. MSL container (magic bytes).
      2. ELF core dump (``\\x7fELF`` with ``e_type == ET_CORE``) — handled
         by :class:`core.dump_sources.gcore.GCoreDumpSource`. Checked
         before filename-based regioned-raw detection so an unusually
         named ELF core still takes the correct branch.
      3. Regioned raw flavours by filename suffix (``.gdb_raw.bin`` /
         ``.lldb_raw.bin``), optionally resolved from a ``.maps`` path.
      4. Fallback: opaque :class:`RawDumpSource`.

    Custom sources registered via :func:`register_dump_source` are consulted
    according to their priority (default: after the built-in specific
    detectors, before the raw fallback).

    Key material (key / passphrase / kem_private_key) is forwarded to
    encrypted .msl containers (spec §10); it is ignored for other formats.
    """
    path = Path(path)
    name = path.name

    # Convenience: user pointed at the .maps sidecar — redirect to its .bin.
    if name.endswith("gdb_raw.maps") or name.endswith("lldb_raw.maps"):
        bin_candidate = path.with_suffix(".bin")
        if bin_candidate.exists():
            path = bin_candidate

    try:
        with open(path, "rb") as f:
            header = f.read(_HEADER_PROBE_LEN)
    except OSError:
        header = b""

    for entry in _DUMP_SOURCE_REGISTRY:
        # Isolate a faulty (e.g. third-party) detector: log and skip it rather
        # than aborting dispatch for every file. Mirrors the failure-isolation
        # policy in core/plugin_discovery.py.
        try:
            matched = entry.detector(path, header)
        except Exception:  # noqa: BLE001 - a bad detector must not break open_dump
            logger.warning(
                "dump-source detector %r raised; skipping it",
                getattr(entry.detector, "__name__", entry.detector),
                exc_info=True,
            )
            continue
        if matched:
            return entry.factory(
                path, key=key, passphrase=passphrase,
                kem_private_key=kem_private_key,
            )

    # The raw fallback always matches, so this is unreachable in practice; kept
    # for defensive parity with the pre-registry behaviour.
    return RawDumpSource(path)
