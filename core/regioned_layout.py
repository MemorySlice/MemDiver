"""Pure layout math for flat ``.bin`` + ``.maps`` regioned raw dumps.

A regioned raw dump stores the captured regions of a ``/proc/<pid>/maps``
listing back to back, in maps order. The bin offset of region *i* is the
cumulative size of regions ``0..i-1``; the ``file_offset`` maps column is
ignored. If the bin is shorter than the listing (the producer truncated),
the last reachable region is clamped to the bin size and later regions are
unreachable; if it is longer, the excess is trailing padding.

Shared by :class:`core.dump_sources._regioned_base._RegionedRawSource`
(read-time view) and :func:`msl.importer.import_regioned_raw` (conversion),
so both agree on where every region's bytes live. Also home of the sidecar
lookup rule both use.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

#: Sidecar suffix of a regioned raw dump.
MAPS_SUFFIX = ".maps"


@dataclass(frozen=True)
class RegionedLayout:
    """Where each region of a regioned raw dump lives in its ``.bin``.

    ``offsets[i]`` is the bin offset where region *i* starts and
    ``offsets[usable_count]`` the end of the last usable region.
    """

    offsets: Tuple[int, ...]
    usable_count: int
    bin_size: int
    region_count: int
    #: Size of the last usable region per the maps listing (before clamping).
    last_listed_size: int = 0

    @property
    def covered(self) -> int:
        """Bin bytes that belong to a usable region."""
        return self.offsets[self.usable_count] if self.offsets else 0

    @property
    def padding(self) -> int:
        """Trailing bin bytes beyond the last usable region."""
        return self.bin_size - self.covered

    def served(self, idx: int) -> int:
        """Bytes of region *idx* actually present in the bin."""
        return self.offsets[idx + 1] - self.offsets[idx]

    @property
    def last_clamped(self) -> bool:
        """True when the last usable region is shorter than its listing."""
        if not self.usable_count:
            return False
        return self.served(self.usable_count - 1) < self.last_listed_size

    @property
    def is_exact(self) -> bool:
        """Every listed region is reachable and no bytes are left over.

        Only the last region may be truncated (the producer stopped early);
        this is the "consistent" layout an importer can trust.
        """
        return (self.usable_count == self.region_count
                and self.padding == 0)


def compute_regioned_layout(region_sizes: Sequence[int],
                            bin_size: int) -> RegionedLayout:
    """Cumulative bin offsets for *region_sizes*, clamped to *bin_size*."""
    cum: List[int] = [0]
    running = 0
    last_listed = 0
    for region_size in region_sizes:
        if running >= bin_size:
            break
        last_listed = region_size
        # If this region would overflow the bin, clamp — the raw writer may
        # have truncated here. Still counts as "usable" because the partial
        # bytes are legitimately present.
        if running + region_size > bin_size:
            region_size = bin_size - running
        running += region_size
        cum.append(running)
    return RegionedLayout(tuple(cum), len(cum) - 1, bin_size,
                          len(region_sizes), last_listed)


def sidecar_candidates(bin_path: Path) -> Tuple[Path, Path]:
    """``foo.gdb_raw.bin`` -> (``foo.gdb_raw.maps``, ``foo.maps``)."""
    bin_path = Path(bin_path)
    primary = bin_path.with_suffix(MAPS_SUFFIX)
    fallback = bin_path.with_suffix("").with_suffix(MAPS_SUFFIX)
    return primary, fallback


def find_maps_sidecar(bin_path: Path) -> Optional[Path]:
    """The existing sidecar ``.maps`` for *bin_path*, or ``None``.

    Same rule as ``_RegionedRawSource._resolve_maps_path``: the primary
    (suffix swapped) wins over the legacy (both suffixes dropped) spelling.
    A ``.maps`` file is never its own sidecar.
    """
    bin_path = Path(bin_path)
    if bin_path.suffix == MAPS_SUFFIX:
        return None
    for candidate in sidecar_candidates(bin_path):
        if candidate != bin_path and candidate.is_file():
            return candidate
    return None
