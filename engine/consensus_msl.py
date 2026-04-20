"""MSL-specific consensus building with ASLR-aware region alignment.

Separated from consensus.py to stay within the 200-line file limit.
Delegates region alignment to core/region_align.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

from core.region_align import build_dump_region_map
from core.variance import WelfordVariance

logger = logging.getLogger("memdiver.engine.consensus_msl")


def build_msl_consensus(
    sources: List,
    num_dumps: int,
) -> Tuple[np.ndarray, int, bytes]:
    """Build variance array from MSL sources with ASLR alignment.

    For each source, normalizes memory regions to module-relative keys,
    aligns across dumps, and computes vectorized per-byte variance on
    the intersection of CAPTURED pages. Returns
    ``(variance, total_bytes, reference_bytes)`` where ``reference_bytes``
    is the first source's aligned slab in the same order as variance.
    """
    from core.region_align import align_dumps

    region_maps = []
    for i, src in enumerate(sources):
        rmap = build_dump_region_map(i, src.get_reader())
        region_maps.append(rmap)

    slices = align_dumps(region_maps)

    if not slices:
        logger.warning("No aligned slices produced — dumps may have no common regions")
        return np.array([], dtype=np.float32), 0, b""

    total_bytes = sum(s.page_size for s in slices)
    variance = np.zeros(total_bytes, dtype=np.float32)
    reference = bytearray(total_bytes)
    n = num_dumps
    offset = 0

    for aslice in slices:
        data_mat = np.stack([
            np.frombuffer(aslice.data[d], dtype=np.uint8)
            for d in range(n)
        ]).astype(np.float32)
        chunk_var = np.var(data_mat, axis=0)
        variance[offset:offset + aslice.page_size] = chunk_var
        # Retain the first source's aligned bytes as the reference slab
        # for downstream static-mask + pattern derivation. Index 0 is
        # arbitrary but stable across callers.
        reference[offset:offset + aslice.page_size] = aslice.data[0]
        offset += aslice.page_size

    logger.info("MSL consensus: %d bytes across %d aligned slices", total_bytes, len(slices))
    return variance, total_bytes, bytes(reference)


@dataclass
class _LayoutEntry:
    """One (key, page_offset) slot in the aligned slab."""
    key: str
    page_offset: int
    page_size: int
    slab_offset: int


@dataclass
class MslIncrementalBuilder:
    """Incremental, ASLR-aware consensus across N MSL sources.

    Pre-computes the cross-dump (key, page_offset) intersection in a
    metadata-only pass, then folds one source at a time into a Welford
    accumulator. ``get_live_variance()`` is non-destructive so n-sweep
    can read variance at every N checkpoint without resetting state.
    """

    _sources: List = field(default_factory=list)
    _layout: List[_LayoutEntry] = field(default_factory=list)
    _welford: Optional[WelfordVariance] = None
    _reference: Optional[bytes] = None
    total_bytes: int = 0

    @classmethod
    def from_sources(cls, sources: List) -> "MslIncrementalBuilder":
        """Open layout across all N sources without reading page data."""
        if not sources:
            return cls()

        dump_layouts = [
            build_dump_region_map(i, src.get_reader(), metadata_only=True)
            for i, src in enumerate(sources)
        ]
        common_keys = set(dump_layouts[0].regions.keys())
        for dl in dump_layouts[1:]:
            common_keys &= set(dl.regions.keys())

        layout: List[_LayoutEntry] = []
        slab_offset = 0
        for key in sorted(common_keys):
            per_dump = [dl.regions[key] for dl in dump_layouts]
            page_sizes = {r.page_size for r in per_dump}
            if len(page_sizes) != 1:
                logger.error("Page size mismatch for key %s: %s — skipping", key, sorted(page_sizes))
                continue
            ps = next(iter(page_sizes))
            common_pages = set(per_dump[0].captured_pages.keys())
            for r in per_dump[1:]:
                common_pages &= set(r.captured_pages.keys())
            for page_off in sorted(common_pages):
                layout.append(_LayoutEntry(key, page_off, ps, slab_offset))
                slab_offset += ps

        total = slab_offset
        logger.info(
            "MslIncrementalBuilder layout: %d bytes across %d slices (%d common keys)",
            total, len(layout), len(common_keys),
        )
        return cls(
            _sources=list(sources),
            _layout=layout,
            _welford=WelfordVariance(total) if total > 0 else None,
            total_bytes=total,
        )

    def _materialize_slab(self, dump_index: int) -> bytes:
        """Read one source's aligned slab by re-decoding its page data.

        Re-reads are intentional: MSL sources are mmap-backed, so the
        kernel pages in on demand and cached reads are cheap. Caching
        full DumpRegionMaps across folds would pin ~dump_size bytes per
        source in RAM, defeating the incremental design.
        """
        rmap = build_dump_region_map(dump_index, self._sources[dump_index].get_reader())
        slab = bytearray(self.total_bytes)
        for entry in self._layout:
            page = rmap.regions[entry.key].captured_pages[entry.page_offset]
            slab[entry.slab_offset:entry.slab_offset + entry.page_size] = page
        return bytes(slab)

    def fold_next(self, dump_index: int) -> None:
        """Fold one source (identified by index into the ``sources`` list)."""
        if self._welford is None:
            raise RuntimeError("builder has no layout (empty sources or no common regions)")
        slab = self._materialize_slab(dump_index)
        self._welford.add_dump(slab)
        if self._reference is None:
            self._reference = slab

    def get_live_variance(self) -> np.ndarray:
        """Materialize the current variance without destroying the accumulator."""
        if self._welford is None:
            return np.array([], dtype=np.float32)
        return self._welford.variance()

    def get_reference(self) -> bytes:
        return self._reference or b""

    def welford_state(self):
        """Return (mean, m2, n) for persisting the Welford accumulators."""
        if self._welford is None:
            raise RuntimeError("no welford state")
        return self._welford.state_arrays()

    @property
    def num_dumps(self) -> int:
        return self._welford.num_dumps if self._welford is not None else 0


def build_msl_incremental(sources: List) -> MslIncrementalBuilder:
    """Convenience factory matching the plan's ``build_msl_incremental`` name."""
    return MslIncrementalBuilder.from_sources(sources)
