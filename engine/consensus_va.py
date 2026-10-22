"""Virtual-address consensus for dump sources that expose a VA map.

The middle path between the two that already existed. ``.msl`` dumps carry a
module table, so :mod:`engine.consensus_msl` can align them by module+offset
and be right even under ASLR. A plain ``.dump`` carries nothing, so
``ConsensusVector._build_raw`` can only line up file offsets and hope. In
between sit the captures that know *where* their bytes were mapped but not
which module owned them — an ELF core's ``PT_LOAD`` table, a regioned raw
dump's ``/proc/<pid>/maps`` sidecar. Those align by absolute virtual address.

That correspondence is exact for every page the process mapped at the same
address in every dump, and silent about the rest: a page ASLR moved simply
falls out of the intersection and is counted in
:attr:`~memdiver.core.region_align.AlignmentCoverage.bytes_discarded`.

Separated from consensus.py for the same reason consensus_msl.py is, and it
reuses the same intersection routine (``core.region_align.align_dumps``) —
only the keys differ (``va:`` instead of ``mod:``/``anon:``).
"""

from __future__ import annotations

import logging
from typing import Any, List, NamedTuple, Optional, Tuple

import numpy as np

from memdiver.core.region_align import (
    VA_INDEX_BYTES_PER_PAGE,
    AlignedLayout,
    AlignmentCoverage,
    align_dumps,
    alignment_index_bytes,
    build_va_page_index,
    read_va_slab,  # noqa: F401  (re-exported for callers of the old eager path)
    stream_aligned_variance,
)
from memdiver.core.variance import CHUNK_BYTES, compute_variance  # noqa: F401

logger = logging.getLogger("memdiver.engine.consensus_va")


class VaConsensusResult(NamedTuple):
    """Result of a virtual-address-aligned consensus build.

    Deliberately the same shape as
    :class:`~memdiver.engine.consensus_msl.MslConsensusResult` so
    ``ConsensusVector`` consumes both paths identically: an aligned slab, its
    length, the first dump's bytes in slab order, the per-slice VA layout, and
    what the alignment covered.
    """

    variance: np.ndarray
    total_bytes: int
    reference_bytes: bytes
    layout: List[Tuple[int, int, List[int]]]
    coverage: AlignmentCoverage


def supports_va_alignment(source: Any) -> bool:
    """Whether *source* opts into virtual-address alignment.

    Declared by the source class (``supports_va_alignment = True``) rather
    than sniffed from its methods: several sources expose ``iter_ranges``
    without a VA map worth aligning on, and an imported ``.msl`` must keep its
    existing flat-fallback behaviour rather than silently changing path.
    """
    return bool(getattr(source, "supports_va_alignment", False))


def build_va_consensus(
    sources: List, region_filter=None, *,
    force: bool = False, budget=None, chunk_positions: Optional[int] = None,
) -> VaConsensusResult:
    """Align N VA-mapped dumps by virtual address and compute their variance.

    Each dump is indexed into absolute-VA pages, the pages present in *every*
    dump are intersected (:func:`~memdiver.core.region_align.align_dumps`, the
    same routine the ``.msl`` path uses), and only those pages are read back
    and compared. The slab runs in ascending virtual address.

    Slab-streamed: no dump's aligned bytes are ever held whole. The peak is
    estimated and budget-checked first (``CapabilityError`` code
    ``memory_budget_exceeded`` unless *force*); each position slab is then
    read from every dump's RAW stream on demand and reduced with the same
    ``np.var`` on the same 16 MiB-compatible grid ``compute_variance`` used
    (:func:`~memdiver.core.slab_variance.plan_slabs`), so the variance is
    bit-identical.

    :param sources: Opened dump sources, each satisfying
        :func:`supports_va_alignment`.
    :param region_filter: Optional analysis-time view filter, forwarded to
        :func:`~memdiver.core.region_align.build_va_page_index`. VA sources
        carry no stored region classification, so it is a documented no-op
        for them (see that function).
    :param force: proceed even when the estimate exceeds the budget.
    :param budget: ``MemoryBudget`` / byte count; ``None`` resolves the host.
    :param chunk_positions: force the slab width (tests).
    :returns: The :class:`VaConsensusResult`; empty (with a warning logged and
        ``coverage`` still populated) when the dumps share no mapped page.
    """
    indexes = [build_va_page_index(i, src, region_filter=region_filter)
               for i, src in enumerate(sources)]
    region_maps = [ix.region_map for ix in indexes]
    slices = align_dumps(region_maps)
    coverage = AlignmentCoverage.from_alignment(region_maps, slices)

    if not slices:
        logger.warning(
            "No VA-aligned pages across %d dumps — no page is mapped at the "
            "same address in every dump", len(sources),
        )
        return VaConsensusResult(np.array([], dtype=np.float32), 0, b"", [], coverage)

    layout = AlignedLayout.from_slices(slices)
    total_bytes = coverage.bytes_compared
    variance, reference = stream_aligned_variance(
        region_maps, layout, force=force, budget=budget,
        chunk_positions=chunk_positions, legacy_chunk=CHUNK_BYTES,
        index_bytes=alignment_index_bytes(
            region_maps, len(slices), per_page=VA_INDEX_BYTES_PER_PAGE),
        operation=f"virtual-address consensus build ({len(sources)} dumps)",
    )
    va_layout = layout.va_layout(slices)

    logger.info(
        "VA consensus: %d bytes across %d aligned pages (%d dumps)",
        total_bytes, len(slices), len(sources),
    )
    return VaConsensusResult(variance, total_bytes, reference, va_layout, coverage)
