"""Layout planning for regioned raw dumps (flat ``.bin`` + ``.maps`` sidecar).

A plain raw dump has no layout metadata, so it imports as ONE unclassified
region at VA 0. When a ``/proc/<pid>/maps``-style sidecar describes the bin
(the gdb_raw / lldb_raw layout, see :mod:`core.regioned_layout`), every maps
entry becomes its own region at its real virtual address, typed from its
path (:func:`core.proc_maps_parser.classify_region`) and protected from its
``perm`` column. The full path column is also the region's mapping *name*
(:mod:`msl.region_names`), which may refine its selection category and
reveals an Android process (:attr:`RegionedPlan.platform`).

This module is pure planning (no MSL writing): it is shared by
:func:`msl.importer.import_regioned_raw` and :mod:`msl.import_preview`, so the
preview cannot drift from what an import stores. :func:`plan_regioned_raw`
returns ``None`` plus a reason whenever the sidecar does not describe the bin
exactly; callers then fall back to a plain raw import (with a warning).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from memdiver.core.proc_maps_parser import MapRegion, parse_maps_file
from memdiver.core.regioned_layout import (compute_regioned_layout,
                                           find_maps_sidecar)

from .enums import PageState, Protection, RegionType
from .region_names import platform_for_names
from .region_select import RegionInfo, classify

#: Page size of a regioned raw import (Linux /proc/<pid>/maps granularity).
REGIONED_PAGE_SIZE_LOG2 = 12

# Region types a shared (``s``) mapping is recorded as SHARED_MEM from: the
# path says nothing more specific. Heap / stack / image keep their type.
_SHAREABLE_TYPES = frozenset({
    int(RegionType.ANONYMOUS), int(RegionType.MAPPED_FILE),
    int(RegionType.UNKNOWN),
})


@dataclass(frozen=True)
class RegionedEntry:
    """One maps entry as a regioned raw import writes it."""

    region: MapRegion
    bin_offset: int        # where the entry's bytes start in the .bin
    stored_len: int        # bytes of the entry present in the .bin
    captured_pages: int    # pages backed by stored bytes (tail zero-padded)
    failed_pages: int      # listed pages past a truncated .bin (last entry)
    protection: int
    region_type: int
    page_size_log2: int = REGIONED_PAGE_SIZE_LOG2

    @property
    def base_addr(self) -> int:
        return self.region.start

    @property
    def page_size(self) -> int:
        return 1 << self.page_size_log2

    @property
    def region_size(self) -> int:
        return (self.captured_pages + self.failed_pages) * self.page_size

    @property
    def captured_len(self) -> int:
        return self.captured_pages * self.page_size

    @property
    def name(self) -> Optional[str]:
        """Full mapping name (maps path column); ``None`` when empty."""
        return self.region.path or None

    @property
    def module_path(self) -> Optional[str]:
        """File backing the mapping (``None`` for anonymous / pseudo paths)."""
        return self.region.path if is_file_backed(self.region) else None

    def page_states(self) -> Optional[List[int]]:
        """Dense page map, or ``None`` when every page is CAPTURED."""
        if not self.failed_pages:
            return None
        return ([int(PageState.CAPTURED)] * self.captured_pages
                + [int(PageState.FAILED)] * self.failed_pages)

    def to_info(self) -> RegionInfo:
        """The :class:`RegionInfo` a selection sees for this entry."""
        category = classify(self.region_type, self.protection,
                            self.base_addr, self.region_size, (),
                            self.module_path, name=self.name)
        return RegionInfo(self.base_addr, self.region_size, self.protection,
                          self.region_type, category, self.module_path,
                          self.captured_len, name=self.name)


@dataclass(frozen=True)
class RegionedPlan:
    """Validated layout of a regioned raw dump."""

    maps_path: Path
    entries: List[RegionedEntry]

    @property
    def platform(self) -> str:
        """``"android"`` when the mapping names say so, else ``"linux"``."""
        return platform_for_names(e.region.path for e in self.entries)

    def infos(self) -> List[RegionInfo]:
        return [entry.to_info() for entry in self.entries]

    def file_backed_regions(self) -> List[MapRegion]:
        """Maps entries with a real backing file (module-index input)."""
        return [e.region for e in self.entries if is_file_backed(e.region)]


# -- mapping helpers ------------------------------------------------------------


def is_file_backed(region: MapRegion) -> bool:
    """True for a mapping backed by a file path (not ``[heap]`` / anonymous)."""
    return region.path.startswith("/")


def protection_from_perm(perm: str) -> int:
    """``rwxp`` -> MSL Protection bits (``-`` = absent; s/p carry no bit)."""
    perm = (perm or "").ljust(3, "-")
    prot = 0
    if perm[0] == "r":
        prot |= Protection.READ
    if perm[1] == "w":
        prot |= Protection.WRITE
    if perm[2] == "x":
        prot |= Protection.EXECUTE
    return int(prot)


def region_type_for_map(region: MapRegion) -> int:
    """Path-derived type; a shared (``s``) generic mapping is SHARED_MEM."""
    shared = len(region.perm) >= 4 and region.perm[3] == "s"
    if shared and region.region_type in _SHAREABLE_TYPES:
        return int(RegionType.SHARED_MEM)
    return int(region.region_type)


# -- planning -------------------------------------------------------------------


def _ceil_div(value: int, divisor: int) -> int:
    return -(-value // divisor)


def _check_geometry(regions: Sequence[MapRegion], page: int) -> Optional[str]:
    """Reason the listing cannot become MSL regions, or ``None`` if it can."""
    if not regions:
        return "maps sidecar lists no regions"
    previous_end = 0
    for region in regions:
        if region.end <= region.start:
            return f"empty or inverted maps entry at {region.start:#x}"
        if region.start % page:
            return f"maps entry at {region.start:#x} is not page aligned"
        if region.start < previous_end:
            return (f"maps entries overlap or are out of order at "
                    f"{region.start:#x}")
        previous_end = region.start + _ceil_div(region.size, page) * page
    return None


def _entry(region: MapRegion, bin_offset: int, stored_len: int,
           page: int, page_size_log2: int) -> RegionedEntry:
    listed_pages = _ceil_div(region.size, page)
    captured_pages = _ceil_div(stored_len, page)
    return RegionedEntry(
        region=region, bin_offset=bin_offset, stored_len=stored_len,
        captured_pages=captured_pages,
        failed_pages=listed_pages - captured_pages,
        protection=protection_from_perm(region.perm),
        region_type=region_type_for_map(region),
        page_size_log2=page_size_log2,
    )


def plan_regions(regions: Sequence[MapRegion], bin_size: int,
                 maps_path: Path,
                 page_size_log2: int = REGIONED_PAGE_SIZE_LOG2
                 ) -> Tuple[Optional[RegionedPlan], Optional[str]]:
    """(plan, None) when *regions* describe a *bin_size* bin, else (None, why).

    Consistent means the :mod:`core.regioned_layout` rules hold exactly:
    every entry is reachable in the bin, no trailing bytes are left over,
    and only the last entry may be truncated (its missing pages become
    FAILED). Entries must be page aligned, ascending and non-overlapping.
    """
    page = 1 << page_size_log2
    reason = _check_geometry(regions, page)
    if reason:
        return None, reason
    layout = compute_regioned_layout([r.size for r in regions], bin_size)
    if not layout.is_exact:
        listed = sum(r.size for r in regions)
        return None, (f"maps sidecar lists {len(regions)} region(s) totalling "
                      f"{listed} bytes but the dump holds {bin_size} bytes")
    entries = [
        _entry(region, layout.offsets[idx], layout.served(idx), page,
               page_size_log2)
        for idx, region in enumerate(regions)
    ]
    return RegionedPlan(Path(maps_path), entries), None


def plan_regioned_raw(bin_path: Path, maps_path: Path,
                      page_size_log2: int = REGIONED_PAGE_SIZE_LOG2
                      ) -> Tuple[Optional[RegionedPlan], Optional[str]]:
    """Parse *maps_path* and plan it against *bin_path* (see plan_regions)."""
    try:
        regions = parse_maps_file(maps_path)
    except (OSError, ValueError) as exc:
        return None, f"unreadable maps sidecar {Path(maps_path).name}: {exc}"
    return plan_regions(regions, Path(bin_path).stat().st_size, maps_path,
                        page_size_log2)


def resolve_maps_path(src_path: Path,
                      maps_path: Optional[Path] = None) -> Optional[Path]:
    """Explicit *maps_path* wins; else the auto-detected sidecar (or None).

    An explicit path that does not exist is a caller error (``ValueError``),
    not a silent fallback: the user named a layout and should hear it is gone.
    """
    if maps_path is not None:
        maps_path = Path(maps_path)
        if not maps_path.is_file():
            raise ValueError(f"maps file not found: {maps_path}")
        return maps_path
    return find_maps_sidecar(Path(src_path))


def fallback_warning(maps_path: Path, reason: str) -> str:
    """Warning recorded when a sidecar cannot be used."""
    return (f"memory map {Path(maps_path).name} ignored ({reason}); "
            f"imported as one unclassified raw region")
