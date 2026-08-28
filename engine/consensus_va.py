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
from typing import Any, List, NamedTuple, Tuple

import numpy as np

from memdiver.core.region_align import (
    AlignmentCoverage,
    align_dumps,
    build_va_page_index,
    read_va_slab,
)
from memdiver.core.variance import compute_variance

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


def build_va_consensus(sources: List) -> VaConsensusResult:
    """Align N VA-mapped dumps by virtual address and compute their variance.

    Each dump is indexed into absolute-VA pages, the pages present in *every*
    dump are intersected (:func:`~memdiver.core.region_align.align_dumps`, the
    same routine the ``.msl`` path uses), and only those pages are read back
    and compared. The slab runs in ascending virtual address.

    :param sources: Opened dump sources, each satisfying
        :func:`supports_va_alignment`.
    :returns: The :class:`VaConsensusResult`; empty (with a warning logged and
        ``coverage`` still populated) when the dumps share no mapped page.
    """
    indexes = [build_va_page_index(i, src) for i, src in enumerate(sources)]
    region_maps = [ix.region_map for ix in indexes]
    slices = align_dumps(region_maps)
    coverage = AlignmentCoverage.from_alignment(region_maps, slices)

    if not slices:
        logger.warning(
            "No VA-aligned pages across %d dumps — no page is mapped at the "
            "same address in every dump", len(sources),
        )
        return VaConsensusResult(np.array([], dtype=np.float32), 0, b"", [], coverage)

    slabs = [
        read_va_slab(src, ix, slices) for src, ix in zip(sources, indexes)
    ]
    total_bytes = coverage.bytes_compared
    variance = compute_variance(slabs, total_bytes)

    layout: List[Tuple[int, int, List[int]]] = []
    offset = 0
    for aslice in slices:
        layout.append((offset, aslice.page_size, list(aslice.source_vaddrs)))
        offset += aslice.page_size

    logger.info(
        "VA consensus: %d bytes across %d aligned pages (%d dumps)",
        total_bytes, len(slices), len(sources),
    )
    return VaConsensusResult(variance, total_bytes, slabs[0], layout, coverage)
