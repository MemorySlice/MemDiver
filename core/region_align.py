"""ASLR-aware region alignment for cross-dump variance analysis.

Normalizes memory regions to module-relative offsets so that byte-level
variance analysis works across ASLR-relocated dumps. Only CAPTURED pages
participate in alignment.
"""

import bisect
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("memdiver.core.region_align")


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
    from msl.enums import PageState
    from msl.page_map import PageInterval, iter_captured_ranges
    from core.msl_helpers import get_region_page_data

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
            from msl.enums import RegionType
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
