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
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
    captured_pages: Dict[int, bytes]  # page_offset_in_region -> page_data
    page_size: int
    source_base_addr: int
    region_type: int


@dataclass
class DumpRegionMap:
    """All normalized regions from a single dump."""
    dump_index: int
    regions: Dict[str, NormalizedRegion] = field(default_factory=dict)


@dataclass(frozen=True)
class AlignedSlice:
    """A page-aligned slice ready for variance computation."""
    key: str
    page_offset: int
    page_size: int
    source_vaddrs: List[int]
    data: List[bytes]


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


def _extract_captured_pages(
    region, reader, *, metadata_only: bool = False,
) -> Dict[int, bytes]:
    """Extract {page_offset: page_bytes} for CAPTURED pages in a region.

    page_offset is relative to region.base_addr (ASLR-invariant within region).
    When metadata_only is True, page_bytes is an empty bytes object — used by
    layout-only scans (e.g. MslIncrementalBuilder) that need the offset set
    without materializing ~dump-sized byte dicts per source.
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


def build_dump_region_map(
    dump_index: int, reader, *, metadata_only: bool = False,
) -> DumpRegionMap:
    """Build normalized region map for one MSL dump.

    Groups regions by ASLR-invariant keys using module metadata.
    """
    modules = reader.collect_modules()
    mod_starts, mod_intervals = build_module_lookup(modules)
    regions = reader.collect_regions()

    rmap = DumpRegionMap(dump_index=dump_index)
    anon_counters: Dict[str, int] = {}

    for region in regions:
        owner = find_owning_module(region.base_addr, mod_starts, mod_intervals)
        if owner:
            mod_path, offset = owner
            key = f"mod:{mod_path}:{offset:#x}"
        else:
            from memdiver.msl.enums import RegionType
            try:
                type_name = RegionType(region.region_type).name
            except ValueError:
                type_name = "UNKNOWN"
            base_key = f"anon:{type_name}:{region.region_size:#x}"
            ordinal = anon_counters.get(base_key, 0)
            anon_counters[base_key] = ordinal + 1
            key = f"{base_key}:{ordinal}"

        captured = _extract_captured_pages(region, reader, metadata_only=metadata_only)
        if captured:
            rmap.regions[key] = NormalizedRegion(
                key=key,
                captured_pages=captured,
                page_size=region.page_size,
                source_base_addr=region.base_addr,
                region_type=region.region_type,
            )

    if not rmap.regions:
        logger.warning("Dump %d has no captured regions", dump_index)
    return rmap


def align_dumps(region_maps: List[DumpRegionMap]) -> List[AlignedSlice]:
    """Intersect regions across dumps by key, then intersect captured pages.

    Only keys present in ALL dumps and pages captured in EVERY dump participate.
    """
    if not region_maps:
        return []

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
            data = [r.captured_pages[page_off] for r in regions_for_key]
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


def build_va_page_index(
    dump_index: int, source: Any, *,
    page_size: int = VA_PAGE_SIZE, view: str = "vas",
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
    :returns: The dump's :class:`VaPageIndex`.
    """
    regions: Dict[str, NormalizedRegion] = {}
    file_offsets: Dict[str, int] = {}

    for start_va, end_va, file_offset in source.iter_ranges(view):
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
        chunks.append(source.read_range(offset, aslice.page_size, view))
    return b"".join(chunks)
