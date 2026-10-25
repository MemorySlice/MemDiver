"""ASLR-aware region alignment for cross-dump variance analysis.

Normalizes memory regions to module-relative offsets so that byte-level
variance analysis works across ASLR-relocated dumps. Only CAPTURED pages
participate in alignment.

Two key schemes share the one intersection routine (:func:`align_dumps`):

* ``mod:``/``anon:`` keys from :func:`build_dump_region_map` — module+offset,
  ASLR-invariant, available when the dump carries a module table (``.msl``).
* ``va:`` keys from :func:`build_va_page_index` — absolute virtual address,
  available whenever the dump carries a VA map at all (an ELF core's PT_LOAD
  table, a regioned raw dump's ``/proc/<pid>/maps`` sidecar).

:class:`AlignmentCoverage` reports what either scheme (or the flat-offset
fallback that uses neither) actually managed to compare.
"""

import bisect
import logging
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

logger = logging.getLogger("memdiver.core.region_align")
#: ASLR-invariant module+offset alignment (:func:`align_dumps` below): the
#: strongest correspondence, available when every source carries a module map.
ALIGNMENT_MODULE_OFFSET = "module_offset"

#: Alignment by absolute virtual address, from a source that exposes a VA map
#: (an ELF core's PT_LOAD table, a regioned raw dump's ``.maps`` sidecar).
ALIGNMENT_VIRTUAL_ADDRESS = "virtual_address"

#: The FALLBACK: raw file offsets truncated to ``min(len(b))``, byte 0 against
#: byte 0. Correct only when the dumps genuinely share a layout. The
#: ``bytes_discarded`` / ``sizes_differed`` counters reported alongside it are
#: what make an unsafe use visible instead of silent.
ALIGNMENT_FILE_OFFSET = "file_offset"

#: The closed vocabulary, strongest correspondence first.
#:
#: THE ONE SPELLING of each method in the repo. It lives here, in the lowest
#: layer that owns the alignment arithmetic, rather than in the consensus
#: engine or beside the ``consensus_runs.alignment_method`` column, because
#: both of those need it and neither should import the other: persistence
#: importing the analysis engine is the wrong direction, and a second copy in
#: either place is a vocabulary that agrees today and drifts later.
ALIGNMENT_METHODS = (
    ALIGNMENT_MODULE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
    ALIGNMENT_FILE_OFFSET,
)


@dataclass(frozen=True)
class NormalizedRegion:
    """A memory region identified by an ASLR-invariant key."""
    key: str
    captured_pages: Mapping[int, bytes]  # page_offset_in_region -> page_data
    page_size: int
    source_base_addr: int
    region_type: int
    #: Stored-region classification (``msl.region_select.RegionInfo``) when
    #: the map was built with a view filter; lets :func:`align_dumps` apply a
    #: filter again. ``None`` for unfiltered builds and for ``va:`` keys.
    info: Optional[Any] = None
    #: Where this region's page bytes live (``read_into(region, page_off,
    #: skip, dest) -> filled``) when ``captured_pages`` holds references
    #: rather than bytes. ``None`` for maps built from plain byte dicts, which
    #: :func:`read_aligned_range` then reads directly.
    data_source: Optional[Any] = field(default=None, compare=False, repr=False)

    def read_page_into(self, page_off: int, skip: int, dest: memoryview) -> int:
        """Copy ``page[skip:skip + len(dest)]`` into *dest*; return bytes filled.

        Fewer than ``len(dest)`` only where the page itself is short (a
        container truncated mid-payload) -- the caller zero-fills the rest.
        """
        if self.data_source is not None:
            return self.data_source.read_into(self, page_off, skip, dest)
        chunk = self.captured_pages[page_off][skip:skip + len(dest)]
        dest[:len(chunk)] = chunk
        return len(chunk)

    def materialize(self) -> Dict[int, bytes]:
        """This region's ``{page_offset: page_bytes}`` as a plain dict.

        Reads only this region's pages, so a consumer that needs one region's
        bytes never pays for the whole dump.
        """
        return {off: bytes(self.captured_pages[off]) for off in self.captured_pages}


#: DumpRegionMap.classification_basis values.
BASIS_STORED_TYPE = "stored_type"      # stored region_type / protection only
BASIS_MAPPING_NAMES = "mapping_names"  # plus trusted VAS_MAP mapping names

#: Diagnostic code for a filtered alignment that mixes classification bases
#: (see :func:`classification_basis_diagnostic`). Stable: surfaces (and the
#: web UI's localized banner) key on it, never on the message text.
CLASSIFICATION_BASIS_MIXED = "classification_basis_mixed"


@dataclass
class DumpRegionMap:
    """All normalized regions from a single dump.

    ``classification_basis`` says how the dump's regions are categorised
    (:data:`BASIS_STORED_TYPE` or :data:`BASIS_MAPPING_NAMES`); ``filtered``
    is True when a view filter was applied while building the map.
    """
    dump_index: int
    regions: Dict[str, NormalizedRegion] = field(default_factory=dict)
    classification_basis: str = BASIS_STORED_TYPE
    filtered: bool = False


@dataclass(frozen=True)
class AlignedSlice:
    """A page-aligned slice ready for variance computation.

    ``data`` is a sequence of each dump's page bytes; for maps built over page
    references it is a :class:`LazySliceData` that reads a page only when it
    is indexed.
    """
    key: str
    page_offset: int
    page_size: int
    source_vaddrs: List[int]
    data: Sequence[bytes]


class LazySliceData(Sequence):
    """``[dump_0_page, dump_1_page, ...]`` of one aligned slice, read on access.

    Compares equal to the list of the same bytes, so callers that used to get
    a plain list (``slice.data == [...]``, ``slice.data[0]``) keep working.
    """

    __slots__ = ("_regions", "_page_off")

    def __init__(self, regions: List["NormalizedRegion"], page_off: int) -> None:
        self._regions = regions
        self._page_off = page_off

    def __len__(self) -> int:
        return len(self._regions)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        return self._regions[index].captured_pages[self._page_off]

    def __eq__(self, other) -> bool:
        if isinstance(other, (list, tuple, LazySliceData)):
            return list(self) == list(other)
        return NotImplemented

    def __repr__(self) -> str:
        return f"LazySliceData(n={len(self)}, page_offset={self._page_off:#x})"


def _normalize_path(path: str) -> str:
    """Normalize module path for cross-platform matching."""
    return path.replace("\\", "/").lower()


def build_module_lookup(modules) -> Tuple[List[int], List[Tuple[int, int, str]]]:
    """Build sorted module intervals for binary search.

    Returns:
        (starts, intervals) where starts is sorted base_addr list for bisect,
        intervals is [(base, end, normalized_path), ...] parallel to starts.
    """
    intervals = []
    for m in modules:
        intervals.append((m.base_addr, m.base_addr + m.module_size, _normalize_path(m.path)))
    intervals.sort()
    # Warn on overlaps
    for i in range(len(intervals) - 1):
        if intervals[i][1] > intervals[i + 1][0]:
            logger.warning("Module overlap: %s and %s", intervals[i][2], intervals[i + 1][2])
    starts = [iv[0] for iv in intervals]
    return starts, intervals


def find_owning_module(
    region_base: int, module_starts: List[int],
    module_intervals: List[Tuple[int, int, str]],
) -> Optional[Tuple[str, int]]:
    """Find the module containing a region via binary search.

    Returns:
        (normalized_path, region_offset_from_module_base) or None.
    """
    if not module_starts:
        return None
    idx = bisect.bisect_right(module_starts, region_base) - 1
    if idx < 0:
        return None
    base, end, path = module_intervals[idx]
    if base <= region_base < end:
        return (path, region_base - base)
    return None


def _captured_page_offsets(region) -> Dict[int, int]:
    """``{page_offset_in_region: offset_in_captured_data_stream}``.

    The data stream is the region's CAPTURED pages concatenated in page order
    (what :func:`memdiver.core.msl_helpers.get_region_page_data` returns), so
    this is the same walk ``iter_captured_ranges`` makes, minus the bytes.
    """
    from memdiver.msl.enums import PageState
    from memdiver.msl.page_map import PageInterval, _states_to_intervals

    ps = region.page_size
    src = region.page_intervals or region.page_states
    if not src:
        return {}
    intervals = src if isinstance(src[0], PageInterval) else _states_to_intervals(src)
    result: Dict[int, int] = {}
    data_offset = 0
    for iv in intervals:
        if iv.state != PageState.CAPTURED:
            continue
        start = iv.start_page * ps
        for p in range(0, iv.count * ps, ps):
            result[start + p] = data_offset + p
        data_offset += iv.count * ps
    return result


def _reopen_reader(reader):
    """A private MslReader on *reader*'s file, with the same key material."""
    from memdiver.msl.reader import MslReader

    clone = MslReader(
        reader.path, key=getattr(reader, "_key", None),
        passphrase=getattr(reader, "_passphrase", None),
        kem_private_key=getattr(reader, "_kem_private", None),
    )
    clone.open()
    return clone


def _reader_is_closed(reader) -> bool:
    return (hasattr(reader, "_mmap") and getattr(reader, "_mmap", None) is None
            and getattr(reader, "path", None) is not None)


class _ReaderHandle:
    """One region map's access to its reader, plus the one decompressed block.

    A region map outlives the ``with`` block that opened its reader in some
    callers (the old maps held copied bytes). A closed reader is therefore
    transparently re-opened -- privately, same path and key material, closed
    when the handle is collected -- instead of serving empty pages.

    Compressed MEMORY_REGION blocks have no random access, so the most
    recently decompressed payload is kept; at most one per handle.
    """

    def __init__(self, reader) -> None:
        self._reader = reader
        self._reopened = None
        self._cached_block: Optional[int] = None
        self._cached_payload: bytes = b""

    def reader(self):
        if not _reader_is_closed(self._reader):
            return self._reader
        if self._reopened is None:
            # Key material is request-scoped: never silently re-decrypt an
            # encrypted dump after its owner closed the reader.
            from memdiver.msl.enums import TagStatus
            if getattr(self._reader, "tag_status", None) not in (
                    None, TagStatus.NOT_ENCRYPTED):
                raise RuntimeError(
                    f"{self._reader.path}: encrypted reader was closed; keep it "
                    "open while reading lazy region data")
            self._reopened = _reopen_reader(self._reader)
            weakref.finalize(self, self._reopened.close)
        return self._reopened

    def view(self, offset: int, length: int) -> memoryview:
        reader = self.reader()
        read_view = getattr(reader, "read_view", None)
        if read_view is not None:
            return read_view(offset, length)
        return memoryview(reader.read_bytes(offset, length))

    def decompressed_payload(self, hdr) -> bytes:
        key = int(hdr.file_offset)
        if self._cached_block != key:
            self._cached_payload = b""  # drop the old one before inflating
            self._cached_payload = self.reader().read_block_payload(hdr)
            self._cached_block = key
        return self._cached_payload


class _MslRegionData:
    """Zero-copy page references into one MSL region's captured data stream.

    Uncompressed: views into the reader's buffer (the mmap, or -- for an
    encrypted file -- a freshly decrypted copy of just the requested range) at ``payload + 0x20 + page map``, clamped
    exactly as :func:`~memdiver.core.msl_helpers.get_region_page_data` clamps
    (to ``captured_pages * page_size`` and to the buffer end). Compressed: the
    same offsets into the handle's decompressed payload.
    """

    __slots__ = ("_handle", "_hdr", "_head", "_length", "offsets", "page_size")

    def __init__(self, handle: _ReaderHandle, region) -> None:
        from memdiver.msl.page_map import count_captured_pages

        self._handle = handle
        self._hdr = region.block_header
        map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
        self._head = 0x20 + map_bytes
        self.page_size = region.page_size
        self._length = count_captured_pages(region.page_states) * region.page_size
        self.offsets = _captured_page_offsets(region)

    @property
    def compressed(self) -> bool:
        return bool(getattr(self._hdr, "compressed", False))

    def inflated_bytes(self) -> int:
        """Upper bound of this region's decompressed payload (0 if stored raw)."""
        if not self.compressed:
            return 0
        return self._head + self._length + int(getattr(self._hdr, "block_length", 0))

    def view(self, stream_off: int, length: int) -> memoryview:
        end = min(stream_off + length, self._length)
        if end <= stream_off:
            return memoryview(b"")
        if self.compressed:
            payload = self._handle.decompressed_payload(self._hdr)
            return memoryview(payload)[self._head + stream_off:self._head + end]
        base = int(self._hdr.payload_offset) + self._head
        return self._handle.view(base + stream_off, end - stream_off)

    def page_bytes(self, page_off: int) -> bytes:
        with self.view(self.offsets[page_off], self.page_size) as mv:
            return bytes(mv)

    def read_into(self, region, page_off: int, skip: int, dest: memoryview) -> int:
        take = min(len(dest), self.page_size - skip)
        with self.view(self.offsets[page_off] + skip, take) as mv:
            n = len(mv)
            dest[:n] = mv
        return n


class LazyCapturedPages(Mapping):
    """``{page_offset: page_bytes}`` whose bytes are read only when indexed.

    Keys (and so every intersection / count) cost metadata only; a value is a
    fresh ``bytes`` copy of exactly that page, identical to what the old eager
    map stored.
    """

    __slots__ = ("_data",)

    def __init__(self, data: _MslRegionData) -> None:
        self._data = data

    def __getitem__(self, page_off: int) -> bytes:
        return self._data.page_bytes(page_off)

    def __contains__(self, page_off) -> bool:
        return page_off in self._data.offsets

    def __iter__(self) -> Iterator[int]:
        return iter(self._data.offsets)

    def __len__(self) -> int:
        return len(self._data.offsets)

    def keys(self):
        return self._data.offsets.keys()

    def __repr__(self) -> str:
        return f"LazyCapturedPages({len(self)} pages)"


def _extract_captured_pages(
    region, reader, *, metadata_only: bool = False,
) -> Dict[int, bytes]:
    """Extract {page_offset: page_bytes} for CAPTURED pages in a region.

    page_offset is relative to region.base_addr (ASLR-invariant within region).
    When metadata_only is True, page_bytes is an empty bytes object — used by
    layout-only scans (e.g. MslIncrementalBuilder) that need the offset set
    without materializing ~dump-sized byte dicts per source.

    This is the EAGER form (every page copied); :func:`build_dump_region_map`
    now builds :class:`LazyCapturedPages` references instead. Kept for callers
    that want the bytes in hand.
    """
    from memdiver.msl.enums import PageState
    from memdiver.msl.page_map import PageInterval, iter_captured_ranges
    from memdiver.core.msl_helpers import get_region_page_data

    ps = region.page_size
    src = region.page_intervals or region.page_states
    if not src:
        return {}

    if metadata_only:
        result: Dict[int, bytes] = {}
        if isinstance(src[0], PageInterval):
            for iv in src:
                if iv.state == PageState.CAPTURED:
                    start = iv.start_page * ps
                    end = start + iv.count * ps
                    result.update(dict.fromkeys(range(start, end, ps), b""))
        else:
            result.update(
                (i * ps, b"") for i, state in enumerate(src)
                if state == PageState.CAPTURED
            )
        return result

    page_data = get_region_page_data(reader, region)
    result = {}
    for vaddr, length, chunk in iter_captured_ranges(
        src, page_data, region.base_addr, ps,
    ):
        rel_offset = vaddr - region.base_addr
        chunk_bytes = bytes(chunk)
        for p in range(0, length, ps):
            page_off = rel_offset + p
            result[page_off] = chunk_bytes[p:p + ps]
    return result


class _KeySourceFormat:
    """Lazily read the ``.msl`` classification context (only when needed).

    :meth:`get` is the IMPORT_PROVENANCE ``source_format``; :meth:`live_names`
    the trusted mapping names of a live-named (memslicer) capture, whose
    ``anon:`` key class is folded back to the legacy type.
    """

    _UNSET = object()

    def __init__(self, reader) -> None:
        self._reader = reader
        self._context: Any = self._UNSET

    def _get_context(self):
        if self._context is self._UNSET:
            from memdiver.msl.import_preview import msl_classification_context
            try:
                self._context = msl_classification_context(self._reader)
            except (AttributeError, TypeError):  # not an MslReader
                self._context = (None, None, False)
        return self._context

    def get(self) -> Optional[int]:
        return self._get_context()[0]

    def live_names(self):
        """Trusted names of a live-named file, else ``None`` (no fold)."""
        _, names, live_named = self._get_context()
        return names if live_named else None

    @property
    def classification_basis(self) -> str:
        names = self._get_context()[1]
        return BASIS_STORED_TYPE if names is None else BASIS_MAPPING_NAMES


def _legacy_live_type(region_type: int, key_source: _KeySourceFormat,
                      base_addr: Optional[int]) -> int:
    """Stored type of a live-named capture folded to the legacy key class.

    memslicer captures written before mapping names were stored typed
    regions with the old path rules (e.g. ``[anon:scudo:*]`` -> UNKNOWN);
    newer ones store name-based types (HEAP). Re-deriving the old type from
    the stored name keeps ``anon:`` keys identical between the two.
    """
    if base_addr is None:
        return region_type
    names = key_source.live_names()
    name = names.name_for(base_addr) if names is not None else None
    if name is None:
        return region_type
    from memdiver.msl.region_names import legacy_live_region_type
    return legacy_live_region_type(name)


def _anon_key_type_name(region_type: int, key_source: _KeySourceFormat,
                        base_addr: Optional[int] = None) -> str:
    """Type class of an ``anon:`` key.

    An importer-derived STACK region (ELF core / minidump) keys as ANONYMOUS
    — its pre-STACK stored type — so its key and ordinal match ``.msl``
    files imported before stacks were recorded (see
    :func:`memdiver.msl.region_select.alignment_region_type`). With
    *base_addr*, a live-named memslicer capture keys by its legacy type
    (:func:`_legacy_live_type`).
    """
    from memdiver.msl.enums import RegionType
    from memdiver.msl.region_select import alignment_region_type

    region_type = _legacy_live_type(region_type, key_source, base_addr)
    if region_type == RegionType.STACK:
        region_type = alignment_region_type(region_type, key_source.get())
    try:
        return RegionType(region_type).name
    except ValueError:
        return "UNKNOWN"


def build_dump_region_map(
    dump_index: int, reader, *, metadata_only: bool = False,
    region_filter: Optional[Any] = None,
) -> DumpRegionMap:
    """Build normalized region map for one MSL dump.

    Groups regions by ASLR-invariant keys using module metadata.

    :param region_filter: Optional analysis-time view filter
        (:class:`memdiver.msl.region_select.RegionSelection`). Excluded
        regions are dropped BEFORE ``anon:`` ordinals are assigned, so the
        ordinals of the remaining regions depend only on included regions
        (a dump whose excluded regions differ still aligns). Classification
        is :func:`memdiver.core.region_view_filter.stored_region_infos`
        (stored type + protection + module path + raw-provenance rule; STACK
        only when stored). An importer-derived STACK region keys in the
        ANONYMOUS class (:func:`_anon_key_type_name`). ``None`` or an all-category selection keeps every
        region (the historical behaviour, unchanged keys).

    Without *metadata_only*, ``captured_pages`` holds page REFERENCES
    (:class:`LazyCapturedPages`): building the map reads no page data, and
    a page's bytes are copied only when indexed or streamed through
    :func:`read_aligned_range`. Values are identical to the old eager copies.
    """
    from memdiver.core.region_view_filter import is_active, stored_region_infos

    modules = reader.collect_modules()
    mod_starts, mod_intervals = build_module_lookup(modules)
    regions = reader.collect_regions()
    infos: List[Any] = [None] * len(regions)
    if region_filter is not None and is_active(region_filter):
        all_infos = stored_region_infos(reader, regions)
        kept = [(r, i) for r, i in zip(regions, all_infos)
                if region_filter.includes(i)]
        regions = [r for r, _ in kept]
        infos = [i for _, i in kept]

    key_source = _KeySourceFormat(reader)
    rmap = DumpRegionMap(dump_index=dump_index,
                         classification_basis=key_source.classification_basis,
                         filtered=is_active(region_filter))
    anon_counters: Dict[str, int] = {}
    handle = None if metadata_only else _ReaderHandle(reader)

    for region, info in zip(regions, infos):
        owner = find_owning_module(region.base_addr, mod_starts, mod_intervals)
        if owner:
            mod_path, offset = owner
            key = f"mod:{mod_path}:{offset:#x}"
        else:
            type_name = _anon_key_type_name(region.region_type, key_source,
                                            region.base_addr)
            base_key = f"anon:{type_name}:{region.region_size:#x}"
            ordinal = anon_counters.get(base_key, 0)
            anon_counters[base_key] = ordinal + 1
            key = f"{base_key}:{ordinal}"

        data_source = None
        captured: Mapping[int, bytes]
        if handle is None:
            captured = _extract_captured_pages(region, reader, metadata_only=True)
        else:
            data_source = _MslRegionData(handle, region)
            captured = LazyCapturedPages(data_source)
        if captured:
            rmap.regions[key] = NormalizedRegion(
                key=key,
                captured_pages=captured,
                page_size=region.page_size,
                source_base_addr=region.base_addr,
                region_type=region.region_type,
                info=info,
                data_source=data_source,
            )

    if not rmap.regions:
        logger.warning("Dump %d has no captured regions", dump_index)
    return rmap


def _filter_region_map(rmap: DumpRegionMap, region_filter) -> DumpRegionMap:
    """Drop regions whose recorded classification *region_filter* excludes.

    Regions without a recorded ``info`` (unfiltered builds, ``va:`` keys) are
    kept: there is nothing to classify them by.
    """
    kept = {
        key: region for key, region in rmap.regions.items()
        if region.info is None or region_filter.includes(region.info)
    }
    return DumpRegionMap(dump_index=rmap.dump_index, regions=kept,
                         classification_basis=rmap.classification_basis,
                         filtered=True)


def classification_basis_warning(region_maps: List[DumpRegionMap]
                                 ) -> Optional[str]:
    """Warning when a FILTERED alignment mixes classification bases.

    Name-classified dumps (Android-aware categories, ``runtime``) and
    stored-type dumps split the same memory differently, so a category
    filter may keep a region in one dump and drop it in another.
    """
    if not any(rm.filtered for rm in region_maps):
        return None
    bases = {rm.classification_basis for rm in region_maps}
    if len(bases) < 2:
        return None
    named = sum(rm.classification_basis == BASIS_MAPPING_NAMES
                for rm in region_maps)
    return (f"region filter applied across dumps with different "
            f"classification bases: {named} of {len(region_maps)} dump(s) "
            f"are classified by mapping names, the rest by stored region "
            f"type only; filtered regions may not correspond across dumps")


def classification_basis_diagnostic(region_maps: List[DumpRegionMap]
                                    ) -> Optional[Any]:
    """:func:`classification_basis_warning` as a structured ``Diagnostic``.

    Code :data:`CLASSIFICATION_BASIS_MIXED`; ``details`` names which dumps
    were classified by mapping names and which by stored type only, plus a
    neutral remedy, so every surface (library, REST, MCP, CLI, web UI) can
    report the same condition without parsing the message.
    """
    message = classification_basis_warning(region_maps)
    if message is None:
        return None
    from memdiver.core.service_result import Diagnostic, Severity
    named = [rm.dump_index for rm in region_maps
             if rm.classification_basis == BASIS_MAPPING_NAMES]
    stored = [rm.dump_index for rm in region_maps
              if rm.classification_basis != BASIS_MAPPING_NAMES]
    return Diagnostic(
        code=CLASSIFICATION_BASIS_MIXED,
        message=message,
        severity=Severity.WARNING,
        details={
            "named_dumps": named,
            "stored_type_dumps": stored,
            "total_dumps": len(region_maps),
            "remedy": ("re-import the older dumps so they are classified "
                       "by mapping names"),
        },
    )


def alignment_diagnostics(region_maps: List[DumpRegionMap]) -> Tuple[Any, ...]:
    """Every structured diagnostic an alignment over *region_maps* earns."""
    diagnostic = classification_basis_diagnostic(region_maps)
    return () if diagnostic is None else (diagnostic,)


def align_dumps(
    region_maps: List[DumpRegionMap], *, region_filter: Optional[Any] = None,
) -> List[AlignedSlice]:
    """Intersect regions across dumps by key, then intersect captured pages.

    Only keys present in ALL dumps and pages captured in EVERY dump participate.

    :param region_filter: Optional view filter re-applied to maps that were
        built with classification info (see :func:`build_dump_region_map`).
        It cannot renumber ``anon:`` ordinals after the fact, so pass the
        filter to :func:`build_dump_region_map` for stable ordinals; this
        parameter only narrows an already-built set of maps.
    """
    if not region_maps:
        return []
    from memdiver.core.region_view_filter import is_active
    if is_active(region_filter):
        region_maps = [_filter_region_map(rm, region_filter) for rm in region_maps]
    basis_warning = classification_basis_warning(region_maps)
    if basis_warning:
        logger.warning(basis_warning)

    # Intersect keys across all dumps
    common_keys = set(region_maps[0].regions.keys())
    for rmap in region_maps[1:]:
        common_keys &= set(rmap.regions.keys())

    slices: List[AlignedSlice] = []
    for key in sorted(common_keys):
        regions_for_key = [rm.regions[key] for rm in region_maps]

        # Validate page_size consistency
        page_sizes = {r.page_size for r in regions_for_key}
        if len(page_sizes) > 1:
            logger.error("Page size mismatch for key '%s': %s — skipping", key, page_sizes)
            continue
        ps = regions_for_key[0].page_size

        # Intersect captured page offsets
        common_pages = set(regions_for_key[0].captured_pages.keys())
        for r in regions_for_key[1:]:
            common_pages &= set(r.captured_pages.keys())

        for page_off in sorted(common_pages):
            vaddrs = [r.source_base_addr + page_off for r in regions_for_key]
            data = LazySliceData(regions_for_key, page_off)
            slices.append(AlignedSlice(
                key=key, page_offset=page_off, page_size=ps,
                source_vaddrs=vaddrs, data=data,
            ))

    logger.info("Aligned %d page slices across %d dumps (%d common keys)",
                len(slices), len(region_maps), len(common_keys))
    return slices


# ---------------------------------------------------------------------------
# Cross-dump coverage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlignmentCoverage:
    """How much of each dump survived being put into correspondence.

    ``bytes_compared`` is the length of the one byte stream every dump
    contributed to; ``bytes_available`` is how many bytes each dump offered.
    The gap between them is what alignment threw away — the number that says
    whether a variance figure covers the dumps or only a corner of them.

    Shared by all three alignment methods so their provenance reconciles the
    same way: the module+offset and virtual-address paths build it from the
    aligned slices, the flat-offset fallback from the raw buffer lengths.
    """

    bytes_compared: int
    bytes_available: Tuple[int, ...]
    #: Structured ``Diagnostic`` notes about the alignment itself (e.g.
    #: :data:`CLASSIFICATION_BASIS_MIXED`). Excluded from equality/hash: two
    #: coverages are "the same" by their byte arithmetic alone.
    diagnostics: Tuple[Any, ...] = field(default=(), compare=False)

    @property
    def n_sources(self) -> int:
        """Number of dumps that took part."""
        return len(self.bytes_available)

    @property
    def bytes_discarded(self) -> int:
        """Input bytes never compared, summed over every dump.

        ``sum(bytes_available) == bytes_compared * n_sources + bytes_discarded``
        holds by construction, which is what makes the report auditable.
        """
        return sum(self.bytes_available) - self.bytes_compared * self.n_sources

    @property
    def sizes_differed(self) -> bool:
        """True when the dumps did not all offer the same number of bytes."""
        return len(set(self.bytes_available)) > 1

    @property
    def discarded_fraction(self) -> float:
        """``bytes_discarded`` as a share of everything offered (0.0 when empty)."""
        total = sum(self.bytes_available)
        return self.bytes_discarded / total if total else 0.0

    @classmethod
    def from_sizes(cls, sizes: Iterable[int], bytes_compared: int) -> "AlignmentCoverage":
        """Coverage for the flat path: N buffer lengths truncated to a common size."""
        return cls(bytes_compared=int(bytes_compared),
                   bytes_available=tuple(int(s) for s in sizes))

    @classmethod
    def from_alignment(
        cls, region_maps: List[DumpRegionMap], slices: List[AlignedSlice],
    ) -> "AlignmentCoverage":
        """Coverage for an :func:`align_dumps` result.

        Works for both key schemes and for metadata-only region maps (whose
        page bytes are empty), because the byte count comes from the page
        *count* times the page size rather than from the page data.
        """
        return cls(
            bytes_compared=sum(s.page_size for s in slices),
            bytes_available=tuple(captured_byte_count(rm) for rm in region_maps),
            diagnostics=alignment_diagnostics(region_maps),
        )


def captured_byte_count(region_map: DumpRegionMap) -> int:
    """Total captured bytes a dump offered to alignment."""
    return sum(
        len(region.captured_pages) * region.page_size
        for region in region_map.regions.values()
    )


# ---------------------------------------------------------------------------
# Virtual-address alignment
# ---------------------------------------------------------------------------

#: Page granularity for VA alignment. Pages are cut on ABSOLUTE virtual-address
#: boundaries, not region-relative ones: that is what makes two dumps' pages
#: line up even when one dump's region starts earlier or runs longer than the
#: other's. Mapped regions are page-aligned in practice (PT_LOAD, /proc/maps),
#: so only a region's short tail can produce a partial page.
VA_PAGE_SIZE = 4096


@dataclass(frozen=True)
class VaPageIndex:
    """One dump's VA pages, keyed for :func:`align_dumps`, plus where to read them.

    ``region_map`` carries no page bytes (the same metadata-only idiom
    :func:`build_dump_region_map` uses), so intersecting N dumps costs
    metadata rather than N dump-sized byte dicts. ``file_offsets`` maps each
    key to the offset of that page in the dump's RAW stream, which is how
    :func:`read_va_slab` materialises only the pages that survived.
    """

    region_map: DumpRegionMap
    file_offsets: Dict[str, int]


def va_page_key(page_va: int) -> str:
    """Alignment key for a VA page.

    Zero-padded hex so the lexicographic ordering :func:`align_dumps` applies
    to keys is also the numeric ordering — the aligned slab then runs in
    ascending virtual address, which is the order an analyst reads offsets in.
    """
    return f"va:{page_va:016x}"


def _aligns_by_run_table(source: Any) -> bool:
    """True for a source that publishes ``captured_runs`` for VA alignment.

    ``.msl`` and image views (``.mdview``) hand over ``(va, length,
    vas_offset)`` per CAPTURED run, to be read back through the ``"vas"``
    stream. Gcore / regioned sources keep their ``iter_ranges`` + raw-offset
    contract. FAILED / NOT_RESIDENT / unmapped addresses are in no run, so
    they never enter the alignment and are never compared as zeros.
    """
    return (getattr(source, "va_alignment_by_runs", False)
            or getattr(source, "format_name", "") == "msl") and \
        callable(getattr(source, "captured_runs", None))


def _va_alignment_ranges(source: Any, view: str):
    """``(start_va, end_va, offset)`` per captured range, plus the read view."""
    if _aligns_by_run_table(source):
        ranges = ((int(va), int(va) + int(n), int(off))
                  for va, n, off in source.captured_runs())
        return ranges, "vas"
    return source.iter_ranges(view), "raw"


def build_va_page_index(
    dump_index: int, source: Any, *,
    page_size: int = VA_PAGE_SIZE, view: str = "vas",
    region_filter: Optional[Any] = None,
) -> VaPageIndex:
    """Index one dump's mapped VA pages for cross-dump alignment.

    *source* is any dump source exposing ``iter_ranges(view)`` — which yields
    ``(start_va, end_va, file_offset)`` per captured range — and
    ``read_range(offset, length, view)``. Overlapping ranges keep their first
    occurrence, so a key always names exactly one page of one dump.

    :param dump_index: Position of this dump in the caller's source list.
    :param source: The dump source to index.
    :param page_size: Alignment granularity; see :data:`VA_PAGE_SIZE`.
    :param view: View passed to ``iter_ranges`` (VA-based for every source
        that has one; ``"raw"`` yields the same tuples).
    :param region_filter: Optional view filter. VA-aligned sources (ELF
        cores, regioned raw dumps) carry no stored region classification, so
        it cannot be applied here; a source that honours a filter itself
        (``MslDumpSource(region_filter=...)``) already yields only included
        ranges from ``iter_ranges``. Accepted so callers can pass it through
        uniformly; an active filter on an unfiltering source is logged.
    :returns: The dump's :class:`VaPageIndex`.
    """
    from memdiver.core.region_view_filter import is_active
    if (region_filter is not None and is_active(region_filter)
            and getattr(source, "region_filter", None) is None):
        logger.info(
            "Dump %d: region view filter %s ignored — source %s has no stored "
            "region classification", dump_index, region_filter.to_note(),
            type(source).__name__,
        )
    regions: Dict[str, NormalizedRegion] = {}
    file_offsets: Dict[str, int] = {}
    ranges, read_view = _va_alignment_ranges(source, view)
    pages = _VaPageData(source, file_offsets, read_view)

    for start_va, end_va, file_offset in ranges:
        start_va, end_va, file_offset = int(start_va), int(end_va), int(file_offset)
        va = start_va
        while va < end_va:
            # Cut at the next absolute page boundary, so a range that starts
            # mid-page contributes a short leading page rather than shifting
            # every page after it out of correspondence.
            chunk_end = min(end_va, va - (va % page_size) + page_size)
            key = va_page_key(va)
            if key not in regions:
                regions[key] = NormalizedRegion(
                    key=key,
                    captured_pages={0: b""},
                    page_size=chunk_end - va,
                    source_base_addr=va,
                    region_type=0,  # unused by VA keys; regions carry no type
                    data_source=pages,
                )
                file_offsets[key] = file_offset + (va - start_va)
            va = chunk_end

    rmap = DumpRegionMap(dump_index=dump_index, regions=regions)
    if not regions:
        logger.warning("Dump %d exposes no mapped VA ranges", dump_index)
    return VaPageIndex(region_map=rmap, file_offsets=file_offsets)


def read_va_slab(
    source: Any, index: VaPageIndex, slices: List[AlignedSlice], *,
    view: str = "raw",
) -> bytes:
    """Materialise one dump's aligned bytes, in slice order.

    Reads through the source's RAW stream at the offsets
    :func:`build_va_page_index` recorded, rather than through its VA/VAS view:
    ``iter_ranges`` already handed us raw offsets, and sources default their
    ``size_for`` / ``read_range`` / ``find_*`` views inconsistently — resolving
    the view here explicitly is what keeps the bytes we size and the bytes we
    read the same stream.
    """
    chunks: List[bytes] = []
    for aslice in slices:
        offset = index.file_offsets.get(aslice.key)
        if offset is None:
            raise KeyError(
                f"dump {index.region_map.dump_index} has no page for "
                f"aligned key {aslice.key!r}"
            )
        chunks.append(source.read_range(
            offset, aslice.page_size,
            "vas" if _aligns_by_run_table(source) else view))
    return b"".join(chunks)


class _VaPageData:
    """Reads a VA page's bytes through its dump's RAW stream, on demand.

    One per dump, shared by every page of that dump's :class:`VaPageIndex`;
    reads at the same offsets :func:`read_va_slab` uses.
    """

    __slots__ = ("_source", "_file_offsets", "_view")

    def __init__(self, source: Any, file_offsets: Dict[str, int],
                 view: str = "raw") -> None:
        self._source = source
        self._file_offsets = file_offsets
        self._view = view

    def read_into(self, region: NormalizedRegion, page_off: int, skip: int,
                  dest: memoryview) -> int:
        offset = self._file_offsets.get(region.key)
        if offset is None:
            raise KeyError(f"no page for aligned key {region.key!r}")
        take = min(len(dest), region.page_size - page_off - skip)
        if take <= 0:
            return 0
        data = self._source.read_range(offset + page_off + skip, take, self._view)
        n = min(len(data), take)
        dest[:n] = memoryview(data)[:n]
        return n


# ---------------------------------------------------------------------------
# Lazy aligned slab access
# ---------------------------------------------------------------------------


class AlignedLayout:
    """Where each aligned (key, page) slot sits in the flat aligned slab.

    ``entries`` is ``[(slab_offset, length, key, page_offset), ...]`` in slab
    order -- the order :func:`align_dumps` emits slices in, which is the order
    every aligned consensus has always laid its variance out in.
    """

    __slots__ = ("entries", "starts", "size")

    def __init__(self, entries: List[Tuple[int, int, str, int]]) -> None:
        self.entries = entries
        self.starts = [e[0] for e in entries]
        self.size = (entries[-1][0] + entries[-1][1]) if entries else 0

    @classmethod
    def from_slices(cls, slices: List[AlignedSlice]) -> "AlignedLayout":
        entries: List[Tuple[int, int, str, int]] = []
        offset = 0
        for aslice in slices:
            entries.append((offset, aslice.page_size, aslice.key, aslice.page_offset))
            offset += aslice.page_size
        return cls(entries)

    def va_layout(self, slices: List[AlignedSlice]) -> List[Tuple[int, int, List[int]]]:
        """``[(slab_offset, page_size, [va_per_dump...])]`` -- the consensus layout."""
        return [(e[0], e[1], list(s.source_vaddrs))
                for e, s in zip(self.entries, slices)]


def _writable_view(into) -> memoryview:
    view = memoryview(into)
    if view.format != "B" or view.ndim != 1:
        view = view.cast("B")
    if view.readonly:
        raise TypeError("into must be a writable buffer")
    return view


def read_aligned_range(
    dump_map: DumpRegionMap, layout: AlignedLayout, start: int, length: int,
    *, into: Any = None,
):
    """Fill ``aligned_slab[start:start + length]`` of one dump from page refs.

    Equivalent to slicing the slab the eager paths built (each aligned page's
    bytes concatenated in slab order), but reads only the pages that overlap
    the range. Positions a dump cannot supply -- a page cut short by a
    container truncated mid-payload -- are ZERO-filled. (Every aligned slot is
    by construction a page CAPTURED in every dump; FAILED/UNMAPPED pages never
    reach the layout, so zero-fill only ever covers truncation, where the old
    eager slab was either misaligned or rejected with a broadcast error.)

    :param into: writable buffer of at least *length* bytes (bytearray, uint8
        ndarray, memoryview); allocated as a ``bytearray`` when ``None``.
    :returns: *into*.
    :raises KeyError: when *dump_map* lacks a key the layout names.
    """
    if into is None:
        into = bytearray(length)
    dest = _writable_view(into)
    if len(dest) < length:
        raise ValueError(f"into holds {len(dest)} bytes, need {length}")
    end = start + length
    entries = layout.entries
    i = max(0, bisect.bisect_right(layout.starts, start) - 1)
    pos = start
    while pos < end and i < len(entries):
        slab_off, size, key, page_off = entries[i]
        i += 1
        if slab_off + size <= pos:
            continue
        skip = pos - slab_off
        take = min(size - skip, end - pos)
        region = dump_map.regions.get(key)
        if region is None:
            raise KeyError(
                f"dump {dump_map.dump_index} has no region for aligned key {key!r}")
        window = dest[pos - start:pos - start + take]
        filled = region.read_page_into(page_off, skip, window)
        if filled < take:
            window[filled:] = bytes(take - filled)
        pos += take
    if pos < end:
        dest[pos - start:length] = bytes(end - pos)
    return into


class AlignedSlabReader:
    """A :class:`~memdiver.core.slab_variance.SlabReader` over one dump's aligned slab.

    Serves ``[start, end)`` of the aligned coordinate space through
    :func:`read_aligned_range` into one reused buffer, so streaming a build
    holds one slab per dump, never the dump.
    """

    def __init__(self, dump_map: DumpRegionMap, layout: AlignedLayout) -> None:
        import numpy as np

        self._np = np
        self._map = dump_map
        self._layout = layout
        self.size = layout.size
        self._buffer = np.empty(0, dtype=np.uint8)

    def read_slab(self, start: int, end: int):
        width = end - start
        if self._buffer.shape[0] < width:
            self._buffer = self._np.empty(width, dtype=self._np.uint8)
        out = self._buffer[:width]
        read_aligned_range(self._map, self._layout, start, width, into=out)
        return out

    def read_prefix(self, length: int) -> bytes:
        buf = bytearray(length)
        read_aligned_range(self._map, self._layout, 0, length, into=buf)
        return bytes(buf)

    def inflated_cache_bytes(self) -> int:
        """Largest decompressed region payload this dump may hold at once."""
        sources = {id(r.data_source): r.data_source for r in self._map.regions.values()
                   if r.data_source is not None}
        return max((getattr(d, "inflated_bytes", lambda: 0)() for d in sources.values()),
                   default=0)


#: Approximate resident cost of one indexed page in a region map (dict entry
#: + int offsets), for the budget estimate. VA maps carry one
#: :class:`NormalizedRegion` + key string per page, hence the larger figure.
INDEX_BYTES_PER_PAGE = 96
VA_INDEX_BYTES_PER_PAGE = 320
#: Per aligned slot: the layout tuple and its per-dump VA list.
LAYOUT_BYTES_PER_SLICE = 160


def alignment_index_bytes(region_maps: List[DumpRegionMap], n_slices: int,
                          *, per_page: int = INDEX_BYTES_PER_PAGE) -> int:
    """Estimated RAM held by the region maps + aligned layout (metadata only)."""
    pages = sum(len(r.captured_pages) for rm in region_maps for r in rm.regions.values())
    return pages * per_page + n_slices * LAYOUT_BYTES_PER_SLICE


def stream_aligned_variance(
    region_maps: List[DumpRegionMap], layout: AlignedLayout, *,
    force: bool = False, budget: Any = None,
    chunk_positions: Optional[int] = None,
    legacy_chunk: Optional[int] = None,
    index_bytes: int = 0,
    operation: str = "aligned consensus build",
):
    """Budget-checked, slab-streamed variance + reference over an aligned slab.

    The aligned counterpart of the flat path's ``_stream_flat_variance``:
    estimate the peak (slab working set, variance vector, reference bytes,
    classification vector, metadata index, at most one decompressed region per
    dump), :func:`~memdiver.core.memory_budget.check_budget` it (raises unless
    *force*), keep the variance in RAM only when the whole estimate fits and
    otherwise in a disk-backed memmap, then walk position slabs reading each
    dump's slab from its page references.

    :param legacy_chunk: see :func:`~memdiver.core.slab_variance.plan_slabs`;
        ``None`` for the per-page MSL reference, ``CHUNK_BYTES`` for the VA
        path's ``compute_variance`` reference.
    :returns: ``(variance float32[size], reference_bytes)``.
    """
    from memdiver.core.memory_budget import check_budget, resolve_memory_budget
    from memdiver.core.slab_variance import (
        BufferSlabReader, allocate_variance_output, plan_slab_variance,
        stream_variance,
    )

    size = layout.size
    readers = [AlignedSlabReader(rm, layout) for rm in region_maps]
    if budget is None:
        budget = resolve_memory_budget()
    extra = {
        "alignment_index": index_bytes,
        "decompressed_region_cache": sum(r.inflated_cache_bytes() for r in readers),
        # read_prefix assembles the reference in a bytearray, then copies it
        # out once; that transient precedes the variance allocation.
    }
    plan = plan_slab_variance(len(readers), size, budget=budget,
                              chunk_positions=chunk_positions,
                              operation=operation, extra=extra)
    check_budget(plan.estimate, force=force, budget=budget)
    # Reference first, before the variance exists, so its one-off assembly
    # copy never coincides with the variance vector.
    reference = readers[0].read_prefix(size)
    readers[0] = BufferSlabReader(reference)
    out = allocate_variance_output(size, in_ram=plan.variance_in_ram)
    variance, _ = stream_variance(
        readers, size, out=out, chunk_positions=plan.chunk_positions,
        with_reference=False, legacy_chunk=legacy_chunk,
    )
    return variance, reference
