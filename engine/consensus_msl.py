"""MSL-specific consensus building with ASLR-aware region alignment.

Separated from consensus.py to stay within the 200-line file limit.
Delegates region alignment to core/region_align.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, NamedTuple, Optional, Tuple

import numpy as np

from memdiver.core.region_align import (
    AlignedLayout,
    AlignmentCoverage,
    alignment_diagnostics,
    alignment_index_bytes,
    build_dump_region_map,
    captured_byte_count,
    read_aligned_range,
    stream_aligned_variance,
)
from memdiver.core.variance import WelfordVariance

logger = logging.getLogger("memdiver.engine.consensus_msl")


def _source_filter(src, region_filter):
    """The view filter to apply to *src*: explicit beats the source's own.

    An ``MslDumpSource`` opened with ``region_filter=`` carries it, so the
    consensus paths honour a filter set at ``open_dump`` time without every
    caller threading it through again.
    """
    if region_filter is not None:
        return region_filter
    return getattr(src, "region_filter", None)


class MslConsensusResult(NamedTuple):
    """Everything the ASLR-aware build knows about what it produced.

    The tuple form :func:`build_msl_consensus` returns is a prefix of this,
    so the two stay in agreement by construction. ``coverage`` is the extra:
    how many captured bytes each dump offered versus how many survived the
    key + page intersection, which is what the caller turns into the
    ``AlignmentReport`` on the consensus vector.
    """

    variance: np.ndarray
    total_bytes: int
    reference_bytes: bytes
    layout: List[Tuple[int, int, List[int]]]
    coverage: AlignmentCoverage


def build_msl_consensus_result(
    sources: List, region_filter=None, *,
    force: bool = False, budget=None, chunk_positions: Optional[int] = None,
) -> MslConsensusResult:
    """Build the ASLR-aligned consensus and report its coverage.

    Same computation as :func:`build_msl_consensus` (which delegates here);
    this is the shape that also carries :class:`AlignmentCoverage`, so a
    caller can say how much of each dump the variance figure actually covers.

    *region_filter* (a ``RegionSelection``) restricts alignment to the
    included region categories; when ``None`` each source's own
    ``region_filter`` (set via ``open_dump(region_filter=...)``) is used.

    Lazy and slab-streamed: the region maps hold page REFERENCES (no page data
    is read to build or intersect them), the peak memory is estimated and
    checked against *budget* (``CapabilityError`` code
    ``memory_budget_exceeded`` unless *force*), and the variance is reduced
    one position slab at a time with each dump's slab read on demand. The
    estimator is the old per-page one (``np.var(axis=0)`` over a stacked
    float32 ``(N, w)`` matrix, ``w >= 2``); variance is column-local, so the
    result is bit-identical. *chunk_positions* forces the slab width (tests).
    """
    from memdiver.core.region_align import align_dumps

    num_dumps = len(sources)
    region_maps = []
    for i, src in enumerate(sources):
        rmap = build_dump_region_map(
            i, src.get_reader(),
            region_filter=_source_filter(src, region_filter),
        )
        region_maps.append(rmap)

    slices = align_dumps(region_maps)
    coverage = AlignmentCoverage.from_alignment(region_maps, slices)

    if not slices:
        logger.warning("No aligned slices produced — dumps may have no common regions")
        return MslConsensusResult(
            np.array([], dtype=np.float32), 0, b"", [], coverage,
        )

    layout = AlignedLayout.from_slices(slices)
    total_bytes = layout.size
    variance, reference = stream_aligned_variance(
        region_maps, layout, force=force, budget=budget,
        chunk_positions=chunk_positions, legacy_chunk=None,
        index_bytes=alignment_index_bytes(region_maps, len(slices)),
        operation=f"aligned .msl consensus build ({num_dumps} dumps)",
    )
    va_layout = layout.va_layout(slices)

    logger.info("MSL consensus: %d bytes across %d aligned slices", total_bytes, len(slices))
    return MslConsensusResult(
        variance, total_bytes, reference, va_layout, coverage,
    )


def build_msl_consensus(
    sources: List,
    num_dumps: int,
    *,
    return_layout: bool = False,
    region_filter=None,
    force: bool = False,
    budget=None,
):
    """Build variance array from MSL sources with ASLR alignment.

    For each source, normalizes memory regions to module-relative keys,
    aligns across dumps, and computes vectorized per-byte variance on
    the intersection of CAPTURED pages. Returns
    ``(variance, total_bytes, reference_bytes)`` where ``reference_bytes``
    is the first source's aligned slab in the same order as variance.

    When ``return_layout`` is True, a fourth element is returned: the
    per-slice VA layout ``[(slab_offset, page_size, [va_per_dump...]), ...]``
    in slab order. It lets callers map any dump's virtual address back to the
    slab index the variance/classification arrays are indexed by — the basis
    for painting the consensus overlay on a dump's ``va`` view. Kept opt-in so
    the existing 3-tuple callers (pipeline, tests) are unaffected.

    The tuple shape is retained for those callers; new code wanting the
    alignment coverage as well calls :func:`build_msl_consensus_result`, which
    this is a projection of. ``num_dumps`` is accepted (and must equal
    ``len(sources)``) for signature compatibility. ``force`` / ``budget``
    gate the memory estimate (see :func:`build_msl_consensus_result`).
    """
    result = build_msl_consensus_result(sources, region_filter=region_filter,
                                        force=force, budget=budget)
    if return_layout:
        return (result.variance, result.total_bytes,
                result.reference_bytes, result.layout)
    return result.variance, result.total_bytes, result.reference_bytes


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
    #: Explicit view filter (``RegionSelection``); ``None`` defers to each
    #: source's own ``region_filter``. Kept so ``fold_next`` re-derives the
    #: same keys the layout pass intersected.
    _region_filter: Optional[object] = None
    total_bytes: int = 0
    #: What the metadata-only intersection kept versus what each dump offered,
    #: so a caller folding through this builder can report the same alignment
    #: provenance a one-shot ``build_msl_consensus_result`` would have.
    coverage: AlignmentCoverage = AlignmentCoverage(0, ())
    #: ``_layout`` as an :class:`AlignedLayout` (built on first fold).
    _aligned: Optional[AlignedLayout] = None

    @classmethod
    def from_sources(
        cls, sources: List, region_filter=None,
    ) -> "MslIncrementalBuilder":
        """Open layout across all N sources without reading page data.

        *region_filter*: see :func:`build_msl_consensus_result`.
        """
        if not sources:
            return cls()

        dump_layouts = [
            build_dump_region_map(
                i, src.get_reader(), metadata_only=True,
                region_filter=_source_filter(src, region_filter),
            )
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
        diagnostics = alignment_diagnostics(dump_layouts)
        for diagnostic in diagnostics:
            logger.warning("%s", diagnostic.message)
        logger.info(
            "MslIncrementalBuilder layout: %d bytes across %d slices (%d common keys)",
            total, len(layout), len(common_keys),
        )
        return cls(
            _sources=list(sources),
            _layout=layout,
            _region_filter=region_filter,
            _welford=WelfordVariance(total) if total > 0 else None,
            total_bytes=total,
            coverage=AlignmentCoverage(
                bytes_compared=total,
                bytes_available=tuple(captured_byte_count(dl) for dl in dump_layouts),
                diagnostics=diagnostics,
            ),
        )

    def _aligned_layout(self) -> AlignedLayout:
        if self._aligned is None:
            self._aligned = AlignedLayout([
                (e.slab_offset, e.page_size, e.key, e.page_offset)
                for e in self._layout
            ])
        return self._aligned

    def _materialize_slab(self, dump_index: int) -> bytearray:
        """Read one source's aligned slab straight from its page references.

        Re-reads are intentional: MSL sources are mmap-backed, so the
        kernel pages in on demand and cached reads are cheap. The region map
        rebuilt per fold holds references only (metadata), and the slab is
        filled page by page from zero-copy views -- no per-fold page dict and
        no second copy of the slab. Pages a truncated container cannot
        supply are zero-filled (see :func:`read_aligned_range`).
        """
        src = self._sources[dump_index]
        rmap = build_dump_region_map(
            dump_index, src.get_reader(),
            region_filter=_source_filter(src, self._region_filter),
        )
        slab = bytearray(self.total_bytes)
        read_aligned_range(rmap, self._aligned_layout(), 0, self.total_bytes, into=slab)
        return slab

    def fold_next(self, dump_index: int) -> None:
        """Fold one source (identified by index into the ``sources`` list)."""
        if self._welford is None:
            raise RuntimeError("builder has no layout (empty sources or no common regions)")
        slab = self._materialize_slab(dump_index)
        self._welford.add_dump(slab)
        if self._reference is None:
            self._reference = bytes(slab)

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
    def diagnostics(self) -> Tuple:
        """Structured alignment diagnostics of the layout pass.

        The same ``Diagnostic`` records a one-shot build reports on its
        ``AlignmentReport`` (e.g. ``classification_basis_mixed``), so a caller
        folding through this builder can surface them too.
        """
        return tuple(self.coverage.diagnostics)

    @property
    def num_dumps(self) -> int:
        return self._welford.num_dumps if self._welford is not None else 0


def build_msl_incremental(sources: List, region_filter=None) -> MslIncrementalBuilder:
    """Convenience factory matching the plan's ``build_msl_incremental`` name."""
    return MslIncrementalBuilder.from_sources(sources, region_filter=region_filter)
