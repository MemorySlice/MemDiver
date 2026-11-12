"""Memory Slice (``.msl``) layers, so stock ``vol -f capture.msl <plugin>`` works.

``vol -p <this dir> -f capture.msl ...`` stacks two layers on the file (the stacker is
``memdiver_stackers.MslStacker``)::

    FileLayer     the .msl container on disk
    MslVasLayer   the flat "vas" byte stream, then one trailing zero region
    MslLayer      the captured process's virtual address space

``MslVasLayer`` offsets are MemDiver's own ``view="vas"`` offsets byte for byte
(``MslDumpSource.read_range(offset, n, view="vas")``): the CAPTURED page runs concatenated
in region base-address order. A hit at vas offset X in either tool is the same byte. The
zero region after the stream backs NotResident pages and is never part of MemDiver's view.

``MslLayer`` maps every CAPTURED run at its virtual address onto that stream and every
NotResident page onto the zero region. Failed and Unmapped pages are left out, so reading
them raises ``InvalidAddressException``: a scan can never report a hit in bytes the capture
did not hold. Its metadata carries ``msl``, ``msl_os``, ``msl_arch``, ``architecture`` and
``pid``, and deliberately NO ``os`` key, not even the inherited ``"Unknown"``. A process slice
is not a kernel image, so the Windows stacker and the OS symbol automagic must leave it alone.

Known limitation: Volatility's scanners never carry their overlap across a segment whose
stream offsets are not contiguous with the previous one. A captured run and the NotResident
pages right after it are adjacent in VA but not in the stream (the zero region lives after
the vas stream, and vas offsets must stay MemDiver's), so a scan misses a match that starts
in captured bytes and ends in the NotResident zeros. ``read`` across that edge is correct.
Abutting CAPTURED runs that are contiguous in the stream are joined and scan as one range.

Encrypted containers
--------------------
Key material comes from the ``MslVasLayer`` options ``key_file`` / ``kem_key_file``, or
from the environment: ``MEMDIVER_MSL_KEY_FILE``, ``MEMDIVER_MSL_KEM_KEY_FILE`` and
``MEMDIVER_MSL_PASSPHRASE``. Nothing is read unless the capture is actually encrypted, and
a key FILE path taken from the environment is written into the layer config only once it
opened the capture (so ``--save-config`` replays without the environment). The passphrase
is read from the environment only, so ``--save-config`` never writes a secret. It is decoded by MemDiver's
``core.key_material.from_files`` and opened through ``memdiver.open_dump``, the same path
the MemDiver CLI takes. A locked container fails with one log line naming the remedy.

Without MemDiver
----------------
Installing MemDiver into vol's Python stays the preferred setup. When ``import memdiver``
fails, captures are opened by ``msl_slim`` (this directory, standard library only) instead,
behind the same two layers: same layer names, stream offsets, VAs, page states and
unreadable pages, proven byte for byte against MemDiver by
``tests/test_vol3plugins_msl_slim.py``. One INFO line per opened capture names the reader.
The slim reader serves plaintext, uncompressed captures; an encrypted or zstd/lz4
compressed one fails with one log line saying ``pip install memdiver``. ``reader`` is then
an ``msl_slim.MslSlimReader`` (a subset of ``MslReader``): ``msl.info``, ``msl.vasmap``,
``msl.pagemap``, ``msl.modules``, ``msl.keyhints``, ``msl.threads`` and ``msl.verify`` run on
it (``msl.verify`` needs the ``blake3`` package for the default BLAKE3 chain); only
``--parallelism processes`` still needs MemDiver.

Class path and ``-c`` replay
----------------------------
Volatility saves a layer's class as ``f"{cls.__module__}.{cls.__name__}"`` and resolves it
on replay through ``sys.modules`` alone (``ClassRequirement.unsatisfied``), never by
importing. ``vol -p <this dir>`` imports this file as ``volatility3.plugins.msl_layer``.
MemDiver imports it in-process as ``memdiver.vol3plugins.msl_layer``. Two names would mean
two class paths, and a config saved in one context would not replay in the other.

So the layer classes have one class path, :data:`CANONICAL_MODULE`, which is the name
stock vol gives this file. When the module is imported under any other name,
:func:`_adopt_canonical_name` registers it in ``sys.modules`` under that name too and
stamps it on the classes' ``__module__``. If vol already loaded it there first, the import
hands back vol's copy, so a process never holds two ``MslLayer`` classes. This uses
``sys.modules`` only and imports nothing, so the import rule holds.

* A config saved by ``vol -p <dir> --save-config`` or written in-process by MemDiver names
  ``volatility3.plugins.msl_layer.MslLayer``. Stock ``vol -p <dir> -c config.json <plugin>``
  replays it without ``-f``, because vol imports this file under that name at startup.
* When vol's plugin import later walks this directory, ``framework.import_file`` skips the
  module that is already registered.

Pickling (``--parallelism processes``): a spawned worker is a fresh interpreter whose
``volatility3.plugins.__path__`` does not contain this directory, so it cannot import
``volatility3.plugins.msl_layer``. The layers therefore pickle through
:func:`_rebuild_layer`, published under :data:`MEMDIVER_MODULE`, which the editable MemDiver
install can always import; that import registers the canonical name again. The open capture
is never pickled: the copy reopens it from the config, key files and environment.

Import rule (see the package docstring): only the standard library and ``volatility3`` at
module level. MemDiver (about 0.9 s to import) is imported inside :func:`open_slice`, and
``msl_slim`` only when MemDiver is missing.
"""

import bisect
import collections
import hashlib
import hmac
import logging
import os
import secrets
import sys
import threading
from typing import (Any, Callable, Dict, Iterable, List, NamedTuple, Optional,
                    Tuple)
from urllib import parse, request

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import segmented

vollog = logging.getLogger(__name__)

#: The one module name the layer classes answer to (see "Class path" above).
CANONICAL_MODULE = "volatility3.plugins.msl_layer"
#: The name MemDiver imports this file under; always importable, so pickles point here.
MEMDIVER_MODULE = "memdiver.vol3plugins.msl_layer"

KEY_FILE_ENV = "MEMDIVER_MSL_KEY_FILE"
KEM_KEY_FILE_ENV = "MEMDIVER_MSL_KEM_KEY_FILE"
PASSPHRASE_ENV = "MEMDIVER_MSL_PASSPHRASE"  # nosec B105 -- an env var NAME, not a secret

#: ``MslVasLayer`` options that name a key file, with the variable each falls back to.
KEY_FILE_OPTIONS = (("key_file", KEY_FILE_ENV), ("kem_key_file", KEM_KEY_FILE_ENV))

#: Decompressed region blocks kept per open capture (compressed ``.msl`` only).
#: Plugins chase pointers across regions; MemDiver's reader keeps only the most recent block.
BLOCK_CACHE_BYTES = 256 * 1024 * 1024

#: Open captures kept in the process-wide cache; the least recently used is closed beyond it.
MAX_OPEN_SLICES = 8

#: MSL page state ``0b11`` (spec section 7): mapped, never touched, content zero.
PAGE_STATE_NOT_RESIDENT = 0b11

#: MSL ``ArchType`` code (X86, X86_64, ARM64, ARM32) -> Volatility's ``architecture`` name.
_VOL_ARCHITECTURE = {0x0000: "Intel32", 0x0001: "Intel64", 0x0002: "AArch64", 0x0003: "ARM"}

_LOCKED_REMEDY = (
    f"set {KEY_FILE_ENV} (raw key file), {PASSPHRASE_ENV} or {KEM_KEY_FILE_ENV}, "
    "or the MslVasLayer key_file / kem_key_file option"
)

#: (va, mapped offset, length): one piece of the VA space and where it lives in the stream.
Span = Tuple[int, int, int]


class MslLayerException(exceptions.LayerException):
    """A ``.msl`` that cannot be served as a layer. ``str()`` is the one-line reason."""


class MslLockedException(MslLayerException):
    """An encrypted ``.msl`` opened without usable key material."""


class MslRegion(NamedTuple):
    """One mapping of the captured process (VAS map entry, else memory region)."""

    start: int
    end: int
    protection: int
    region_type: int
    path: str


class MslSlice:
    """One opened ``.msl`` and the tables both layers read through.

    :func:`open_slice` hands the same instance to every layer that reads the same file
    version with the same key material; it is read-only after construction.
    """

    def __init__(self, source: Any) -> None:
        self.source = source
        self.reader = source.get_reader()
        index = self.reader.captured_run_index()
        span_of = self.reader.run_span
        self.runs = index.runs
        self.vas_starts = index.vas_starts
        self.spans = tuple(span_of(run) for run in index.runs)
        self.vas_size = sum(run.length for run in index.runs)
        self.holes = tuple(
            (run.vas_offset + span, run.vas_offset + run.length)
            for run, span in zip(index.runs, self.spans)
            if span < run.length
        )
        not_resident = list(
            _page_spans(self.reader.collect_regions(), PAGE_STATE_NOT_RESIDENT)
        )
        self.zero_size = max((length for _va, length in not_resident), default=0)
        self.va_segments = _coalesce(_flatten(
            [(va, self.vas_size, length) for va, length in not_resident]
            + [(run.va_start, run.vas_offset, span_of(run)) for run in index.by_va]
        ))
        self._blocks: "collections.OrderedDict[int, bytes]" = collections.OrderedDict()
        self._block_bytes = 0
        self._lock = threading.Lock()
        self.closed = False

    @property
    def stream_size(self) -> int:
        """Bytes in the vas stream plus the trailing zero region."""
        return self.vas_size + self.zero_size

    def piece(self, position: int, end: int) -> Tuple[Optional[bytes], int]:
        """``(data, size)`` of the readable run starting at ``position`` (``data`` None: unreadable)."""
        if position < 0:
            return None, min(end, 0) - position
        if position < self.vas_size:
            i = bisect.bisect_right(self.vas_starts, position) - 1
            run, span = self.runs[i], self.spans[i]
            begin = position - run.vas_offset
            if begin < span:
                size = min(span - begin, end - position)
                return self._run_bytes(run, begin, size), size
            return None, min(run.vas_offset + run.length, end) - position
        if position < self.stream_size:
            size = min(self.stream_size, end) - position
            return bytes(size), size
        return None, end - position

    def is_readable(self, offset: int, end: int) -> bool:
        if offset < 0 or end > self.stream_size:
            return False
        return not any(lo < end and offset < hi for lo, hi in self.holes)

    def _run_bytes(self, run: Any, begin: int, size: int) -> bytes:
        if run.block is None:
            return bytes(self.reader.read_view(run.buf_offset + begin, size))
        start = run.buf_offset + begin
        return self._payload(run.block)[start:start + size]

    def _payload(self, block: Any) -> bytes:
        """Decompressed payload of a compressed region block, from a byte-bounded LRU."""
        with self._lock:
            payload = self._blocks.get(block.file_offset)
            if payload is not None:
                self._blocks.move_to_end(block.file_offset)
                return payload
        payload = self.reader.read_block_payload(block)
        with self._lock:
            cached = self._blocks.get(block.file_offset)
            if cached is not None:  # another thread decompressed it meanwhile
                return cached
            self._blocks[block.file_offset] = payload
            self._block_bytes += len(payload)
            while self._block_bytes > BLOCK_CACHE_BYTES and len(self._blocks) > 1:
                _offset, evicted = self._blocks.popitem(last=False)
                self._block_bytes -= len(evicted)
        return payload

    def describe(self) -> Dict[str, Any]:
        """``MslLayer`` metadata (no ``os`` key, see the module docstring)."""
        ArchType, OSType = _header_enums()
        header = self.reader.file_header
        meta: Dict[str, Any] = {
            "msl": True,
            "msl_os": _enum_name(OSType, header.os_type),
            "msl_arch": _enum_name(ArchType, header.arch_type),
            "architecture": _VOL_ARCHITECTURE.get(header.arch_type, "Unknown"),
            "pid": header.pid,
            "msl_dump_uuid": str(header.dump_uuid),
            "msl_path": str(self.source.path),
        }
        identities = self.reader.collect_process_identity()
        if identities:
            meta["ppid"] = identities[0].ppid
            if identities[0].exe_path:
                meta["msl_exe_path"] = identities[0].exe_path
        return meta

    def region_map(self) -> List[MslRegion]:
        """The file's effective VAS map (spec 5.8), else its memory regions, by address."""
        vas_map = self.reader.effective_vas_map()
        if vas_map is not None:
            rows = [
                MslRegion(e.base_addr, e.base_addr + e.region_size, e.protection,
                          e.region_type, e.mapped_path)
                for e in vas_map.entries
            ]
        else:
            rows = [
                MslRegion(r.base_addr, r.base_addr + r.region_size, r.protection,
                          r.region_type, "")
                for r in self.reader.collect_regions()
            ]
        return sorted(rows)

    def close(self) -> None:
        self.closed = True
        with self._lock:
            self._blocks.clear()
            self._block_bytes = 0
        self.source.close()


def _header_enums() -> Tuple[Any, Any]:
    """``(ArchType, OSType)``: MemDiver's enums, else the slim reader's identical copies."""
    try:
        from memdiver.msl.enums import ArchType, OSType
    except ImportError:
        from .msl_slim import ArchType, OSType
    return ArchType, OSType


def _enum_name(enum_type: Any, code: int) -> str:
    try:
        return enum_type(code).name.lower()
    except ValueError:
        return f"0x{code:04x}"


def _page_spans(regions: Iterable[Any], state: Any) -> Iterable[Tuple[int, int]]:
    """``(va, length)`` of every run of pages in ``state``, region by region."""
    for region in regions:
        page_size = region.page_size
        for interval in region.page_intervals:
            if interval.state == state and interval.count:
                yield (region.base_addr + interval.start_page * page_size,
                       interval.count * page_size)


def _flatten(spans: List[Span]) -> List[Span]:
    """Sorted, non-overlapping segments from ``spans``, a later span winning an overlap.

    Callers list NotResident spans before captured runs (captured bytes win) and captured
    runs in VA order (the later run wins, as in MemDiver's ``"va"`` view). Real captures
    have no overlaps at all, so that case is a sort and one linear check.
    """
    spans = [span for span in spans if span[2] > 0]
    ordered = sorted(spans)
    if all(a[0] + a[2] <= b[0] for a, b in zip(ordered, ordered[1:])):
        return ordered
    starts: List[int] = []
    ends: List[int] = []
    segments: List[Span] = []
    for va, mapped, length in spans:
        end = va + length
        lo = bisect.bisect_right(ends, va)
        hi = bisect.bisect_left(starts, end)
        pieces: List[Span] = []
        if lo < hi and segments[lo][0] < va:
            first_va, first_mapped, _ = segments[lo]
            pieces.append((first_va, first_mapped, va - first_va))
        pieces.append((va, mapped, length))
        if lo < hi and ends[hi - 1] > end:
            last_va, last_mapped, _ = segments[hi - 1]
            pieces.append((end, last_mapped + end - last_va, ends[hi - 1] - end))
        segments[lo:hi] = pieces
        starts[lo:hi] = [piece[0] for piece in pieces]
        ends[lo:hi] = [piece[0] + piece[2] for piece in pieces]
    return segments


def _coalesce(segments: List[Span]) -> List[Span]:
    """Join neighbours that are contiguous in BOTH the VA space and the stream.

    Volatility's scanner never carries its overlap across a segment boundary, so a match
    straddling two abutting captured runs (e.g. adjacent regions) would be missed. Joined,
    the runs scan as one range, which is what MemDiver's ``"va"`` search does for them too.
    """
    joined: List[Span] = []
    for va, mapped, length in segments:
        if joined:
            last_va, last_mapped, last_length = joined[-1]
            if last_va + last_length == va and last_mapped + last_length == mapped:
                joined[-1] = (last_va, last_mapped, last_length + length)
                continue
        joined.append((va, mapped, length))
    return joined


# --------------------------------------------------------------------- opening captures

_open_slices: "collections.OrderedDict[Tuple[Any, ...], MslSlice]" = collections.OrderedDict()
_opening: Dict[Tuple[Any, ...], threading.Lock] = {}
_open_lock = threading.Lock()
#: Per-process salt: the cache key must not be an offline-guessable digest of a passphrase.
_CACHE_SALT = secrets.token_bytes(32)


def _material_tag(*materials: Optional[bytes]) -> str:
    """Salted HMAC over the key material, length-prefixed so no two tuples collide."""
    mac = hmac.new(_CACHE_SALT, digestmod=hashlib.sha256)
    for material in materials:
        mac.update(b"\0" if material is None
                   else b"\1" + len(material).to_bytes(8, "little") + material)
    return mac.hexdigest()


def _cached_slice(cache_key: Tuple[Any, ...]) -> Optional[MslSlice]:
    """Caller holds ``_open_lock``."""
    opened = _open_slices.get(cache_key)
    if opened is None or opened.closed:
        return None
    _open_slices.move_to_end(cache_key)
    return opened


def _remember_slice(cache_key: Tuple[Any, ...], opened: MslSlice) -> None:
    """Caller holds ``_open_lock``. Closes the least recently used beyond the bound."""
    _open_slices[cache_key] = opened
    _open_slices.move_to_end(cache_key)
    while len(_open_slices) > MAX_OPEN_SLICES:
        _key, evicted = _open_slices.popitem(last=False)
        evicted.close()  # layers still holding it reopen on their next read


def open_slice(path: str, key: Optional[bytes] = None, passphrase: Optional[bytes] = None,
               kem_private_key: Optional[bytes] = None) -> MslSlice:
    """The opened capture at ``path`` (cached per file version and key material).

    Raises :class:`MslLayerException` with a one-line reason for anything that cannot be
    served: not an MSL file, locked (:class:`MslLockedException`) or tampered encryption,
    no readable pages. Opening and decrypting run outside the process-wide lock.
    """
    try:
        stat = os.stat(path)
    except OSError as excp:
        raise MslLayerException(os.path.basename(path), f"cannot open .msl: {excp}") from excp
    cache_key = (os.path.realpath(path), stat.st_size, stat.st_mtime_ns,
                 _material_tag(key, passphrase, kem_private_key))
    with _open_lock:
        opened = _cached_slice(cache_key)
        if opened is not None:
            return opened
        opening = _opening.setdefault(cache_key, threading.Lock())
    with opening:
        with _open_lock:
            opened = _cached_slice(cache_key)
        if opened is None:
            opened = _open_new_slice(path, key=key, passphrase=passphrase,
                                     kem_private_key=kem_private_key)
            with _open_lock:
                _remember_slice(cache_key, opened)
                _opening.pop(cache_key, None)
    return opened


def open_capture(path: str,
                 load_key_material: Callable[[], Dict[str, Optional[bytes]]]) -> MslSlice:
    """:func:`open_slice`, calling ``load_key_material`` only if the capture is encrypted."""
    try:
        return open_slice(path)
    except MslLockedException:
        return open_slice(path, **load_key_material())


def reader_for(path: str, **key_material: Optional[bytes]) -> Any:
    """The cached, opened ``MslReader`` for ``path`` (key material as in :func:`open_slice`)."""
    return open_slice(path, **key_material).reader


def close_slices() -> None:
    """Close every cached capture (tests, or a long-lived in-process host)."""
    with _open_lock:
        for opened in _open_slices.values():
            opened.close()
        _open_slices.clear()


def memdiver_importable() -> bool:
    """Whether ``import memdiver`` works, i.e. whether MemDiver's reader opens captures."""
    try:
        import memdiver  # noqa: F401
    except ImportError:
        return False
    return True


def _open_new_slice(path: str, **key_material: Optional[bytes]) -> MslSlice:
    """Open ``path`` with MemDiver's reader, or with ``msl_slim`` when MemDiver is absent."""
    if not memdiver_importable():
        return _open_slim_slice(path)
    vollog.info("MSL reader: MemDiver (memdiver.open_dump) for %s", path)
    return _open_memdiver_slice(path, **key_material)


def _open_slim_slice(path: str) -> MslSlice:
    """``path`` through the standard-library reader (see "Without MemDiver" above).

    Never raises :class:`MslLockedException`: key material cannot help without MemDiver, so
    an encrypted capture fails at once with the install hint instead of reading key files.
    """
    from pathlib import Path

    from . import msl_slim

    path = str(Path(path))  # the spelling MemDiver's source reports as msl_path
    name = os.path.basename(path)
    vollog.info("MSL reader: msl_slim (standard-library fallback, MemDiver is not "
                "importable) for %s", path)
    try:
        source = msl_slim.MslSlimSource(path).open()
    except (OSError, msl_slim.MslSlimError) as excp:
        raise MslLayerException(name, f"{name}: cannot open .msl: {excp}") from excp
    return _serveable(name, source)


def _serveable(name: str, source: Any) -> MslSlice:
    """The slice over an opened ``source``; closes it when nothing can be served."""
    try:
        opened = MslSlice(source)
    except BaseException:
        source.close()
        raise
    if opened.stream_size == 0:
        source.close()
        raise MslLayerException(name, f"{name}: no captured or NotResident pages to map")
    return opened


def _open_memdiver_slice(path: str, **key_material: Optional[bytes]) -> MslSlice:
    from pathlib import Path

    from memdiver.core.dump_source import MslDumpSource, open_dump
    from memdiver.core.service_result import KeyStatus
    from memdiver.msl.enums import TagStatus

    name = os.path.basename(path)
    source = open_dump(Path(path), **key_material)
    if not isinstance(source, MslDumpSource):
        raise MslLayerException(name, f"{name}: not a Memory Slice (.msl) file")
    try:
        source.open()
    except (OSError, ValueError) as excp:  # MslParseError is a ValueError
        source.close()
        raise MslLayerException(name, f"{name}: cannot open .msl: {excp}") from excp
    status = KeyStatus.from_source(source)
    if not status.decrypted:
        source.close()
        error = (MslLockedException if status.tag_status == TagStatus.MISSING_KEY
                 else MslLayerException)
        raise error(name, f"{name}: {status.hint}; {_LOCKED_REMEDY}")
    return _serveable(name, source)


def file_path_of(context: interfaces.context.ContextInterface, layer_name: str) -> str:
    """Local path behind ``layer_name``, from its ``location`` config (``file://`` only)."""
    layer = context.layers[layer_name]
    location = layer.config.get("location", None)
    if not location:
        raise MslLayerException(
            layer_name, f"{layer_name}: MSL layers need a file layer with a location")
    parsed = parse.urlparse(location)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise MslLayerException(
            layer_name, f"{location}: MSL layers read local files only (file:// locations)")
    return request.url2pathname(parsed.path)


def _key_material(config: Any) -> Tuple[Dict[str, Optional[bytes]], Dict[str, str]]:
    """``(open_dump kwargs, key-file options taken from the environment)``.

    Layer options win over the environment. Called only for encrypted captures.
    """
    from memdiver.core.key_material import from_files

    paths: Dict[str, Optional[str]] = {}
    from_env: Dict[str, str] = {}
    for option, env in KEY_FILE_OPTIONS:
        paths[option] = config.get(option, None)
        if not paths[option] and os.environ.get(env):
            paths[option] = from_env[option] = os.path.abspath(os.environ[env])
    try:
        material = from_files(paths["key_file"], os.environ.get(PASSPHRASE_ENV) or None,
                              paths["kem_key_file"])
    except OSError as excp:
        raise MslLayerException("MslVasLayer", f"cannot read MSL key file: {excp}") from excp
    return material, from_env


# ----------------------------------------------------------------------------- layers


class _OwnMetadataOnly:
    """Shared by both layers: own metadata only, and a pickle any interpreter can load.

    Every stock layer, the ``FileLayer`` underneath included, carries ``"os": "Unknown"``,
    and the Windows stacker accepts ``"Unknown"``. Not chaining keeps ``os`` out entirely.
    """

    def __reduce__(self) -> Tuple[Any, ...]:
        # (factory, args, state): the object exists before its state is restored, which is
        # what lets pickle and deepcopy handle the context <-> layer reference cycle.
        return (_rebuild_layer, (type(self).__name__,), self.__getstate__())

    _direct_metadata = {"architecture": "Unknown"}

    @property
    def metadata(self) -> interfaces.objects.ReadOnlyMapping:
        return interfaces.objects.ReadOnlyMapping(
            collections.ChainMap(self._metadata, self._direct_metadata))


class MslVasLayer(_OwnMetadataOnly, interfaces.layers.DataLayerInterface):
    """MemDiver's flat ``"vas"`` stream of a ``.msl``, then a zero region for NotResident pages."""

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str,
                 name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["base_layer"]
        self._slice: Optional[MslSlice] = None
        _ = self._capture  # a bad file fails here, at construction, not on the first read

    @property
    def _capture(self) -> MslSlice:
        """The open capture, (re)opened from the config, key files and environment."""
        if self._slice is None or self._slice.closed:
            env_key_files: Dict[str, str] = {}

            def load_key_material() -> Dict[str, Optional[bytes]]:
                material, from_env = _key_material(self.config)
                env_key_files.update(from_env)
                return material

            try:
                path = file_path_of(self.context, self._base_layer)
                self._slice = open_capture(path, load_key_material)
            except MslLayerException as excp:
                vollog.error(str(excp))
                raise
            self._persist_options(env_key_files)
        return self._slice

    def _persist_options(self, options: Dict[str, str]) -> None:
        """Record key FILE paths that opened the capture, so a saved config replays."""
        for option, value in options.items():
            self.context.config[interfaces.configuration.path_join(
                self.config_path, option)] = value
        if options:
            self._config_cache = None

    def __getstate__(self) -> Dict[str, Any]:
        """Never copy the open capture (an mmap): ``context.clone()`` deep-copies layers
        and ``--parallelism processes`` pickles them. The copy reopens it on first use, from
        the open-capture cache in this process; no key material is ever pickled."""
        state = self.__dict__.copy()
        state["_slice"] = None
        return state

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="base_layer", description="The .msl file", optional=False),
            requirements.StringRequirement(
                name="key_file", description="Raw key file for an encrypted .msl",
                optional=True),
            requirements.StringRequirement(
                name="kem_key_file", description="KEM private key file for an encrypted .msl",
                optional=True),
        ]

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self._capture.stream_size - 1

    @property
    def zero_region_offset(self) -> int:
        """Stream offset of the zero region (MemDiver's vas size)."""
        return self._capture.vas_size

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if length <= 0:
            raise ValueError("Length must be positive")
        return self._capture.is_readable(offset, offset + length)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        chunks = []
        position, end = offset, offset + length
        while position < end:
            data, size = self._capture.piece(position, end)
            if data is None:
                if not pad:
                    raise exceptions.InvalidAddressException(
                        self.name, position, f"MSL stream offset 0x{position:x} is not captured")
                data = bytes(size)
            chunks.append(data)
            position += size
        return b"".join(chunks)

    def write(self, offset: int, data: bytes) -> None:
        raise exceptions.LayerException(self.name, "MSL captures are read-only")

    def va_segments(self) -> List[Span]:
        """``(va, stream offset, length)`` for every readable piece of the VA space."""
        return list(self._capture.va_segments)

    def describe(self) -> Dict[str, Any]:
        return self._capture.describe()

    def region_map(self) -> List[MslRegion]:
        return self._capture.region_map()

    @property
    def reader(self) -> Any:
        """The open ``MslReader`` behind this layer (decrypted when the capture is encrypted).

        Read-only and shared through the open-capture cache: use it for the container's
        other blocks (modules, key hints, process identity ...), never close it.
        """
        return self._capture.reader


class MslLayer(_OwnMetadataOnly, segmented.SegmentedLayer):
    """Virtual address space of the process captured in a ``.msl``.

    CAPTURED runs read their bytes, NotResident pages read as zeros, and Failed or
    Unmapped pages raise ``InvalidAddressException``.
    """

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str,
                 name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path, name, metadata)
        self._metadata = {**self._vas_layer().describe(), **self._metadata}

    def _vas_layer(self) -> MslVasLayer:
        layer = self.context.layers[self._base_layer]
        if not hasattr(layer, "va_segments"):
            raise MslLayerException(self.name, f"{self.name}: base layer must be an MslVasLayer")
        return layer

    def _load_segments(self) -> None:
        self._segments = [(va, mapped, length, length)
                          for va, mapped, length in self._vas_layer().va_segments()]

    def region_map(self) -> List[MslRegion]:
        """The captured process's mappings (see :meth:`MslSlice.region_map`)."""
        return self._vas_layer().region_map()

    @property
    def reader(self) -> Any:
        """The open ``MslReader`` (see :attr:`MslVasLayer.reader`; never close it)."""
        return self._vas_layer().reader


def _rebuild_layer(class_name: str) -> Any:
    """Unpickle a layer (see "Pickling" in the module docstring); pickle restores its state."""
    cls = globals()[class_name]
    return cls.__new__(cls)


def _adopt_canonical_name() -> None:
    """One module object and one class path, whatever name imported this file first.

    The first copy loaded owns :data:`CANONICAL_MODULE`; a later import under the other
    name gets that copy back. :data:`MEMDIVER_MODULE` is never pre-registered (that would
    fake a half-imported ``memdiver`` package); pickling imports it, which lands here.
    """
    for cls in (MslVasLayer, MslLayer):
        cls.__module__ = CANONICAL_MODULE
    _rebuild_layer.__module__ = MEMDIVER_MODULE
    owner = sys.modules.setdefault(CANONICAL_MODULE, sys.modules[__name__])
    sys.modules[__name__] = owner


_adopt_canonical_name()
