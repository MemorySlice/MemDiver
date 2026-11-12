"""Page-sharing classification of sibling processes in one full image (plan S1).

MemDiver-side facade over :mod:`memdiver.vol3plugins.memdiver.frames`, the one
implementation that a stock-vol3 plugin also runs. This module only adds the
ImageContext plumbing: process adapters (whose ``page_frames()`` walk is cached),
the zero-page lookup through the loaded kernel profile, address-space dedup and
walk timing.

A shared frame is labelled, never dropped: it cannot hold a per-instance value but can
hold a group secret (e.g. a key loaded before ``fork()``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Sequence, Set

from memdiver.core.image.adapters import ProcessAdapter
from memdiver.core.image.context import ImageContext
from memdiver.vol3plugins.memdiver.frames import (  # noqa: F401 - re-exported API
    PRIVATE_CLASSES,
    SHARE_CLASSES,
    SHARED_CLASSES,
    ClassifiedPage,
    FrameClassification,
    PageFrame,
    account,
    classify_frames,
    page_frames,
    pages_at,
    private_ratio,
    zero_page_pfns,
)


@dataclass
class SiblingFrames:
    """Classification of a set of sibling processes plus how it was obtained."""

    classification: FrameClassification
    walk_seconds: Dict[int, float]
    #: pids dropped because an earlier member has the same ``mm`` (thread / vfork child).
    same_address_space: Dict[int, int] = field(default_factory=dict)

    @property
    def accounting(self) -> Dict[Any, Dict[str, int]]:
        return self.classification.accounting

    def reduction(self, pid: int) -> float:
        """Private bytes / RSS of ``pid``: the share of its memory a per-instance secret can be in."""
        return private_ratio(self.accounting[pid])


def classify_processes(image_ctx: ImageContext, pids: Sequence[int]) -> SiblingFrames:
    """Walk and classify ``pids`` of one image as one sibling group.

    Tasks sharing an ``mm`` are one member (the first pid wins): two views of one address
    space would otherwise make every page look shared.
    """
    members: Dict[Any, Any] = {}
    seconds: Dict[int, float] = {}
    seen: Dict[int, int] = {}
    duplicates: Dict[int, int] = {}
    for pid in pids:
        adapter = ProcessAdapter(image_ctx, pid)
        mm = adapter.mm_address()
        if mm in seen:
            duplicates[pid] = seen[mm]
            continue
        seen[mm] = pid
        adapter.vmas()  # VMA listing (name resolution) is not part of the page walk
        started = time.perf_counter()
        members[pid] = adapter.page_frames()
        seconds[pid] = time.perf_counter() - started
    return SiblingFrames(classify_frames(members, kernel_zero_pfns(image_ctx)), seconds,
                         duplicates)


def kernel_zero_pfns(image_ctx: ImageContext) -> Set[int]:
    """Frames of the zero page(s) of the image's kernel (empty when there is no profile)."""
    if not image_ctx.has_kernel:
        return set()
    with image_ctx.lock:
        return zero_page_pfns(image_ctx.context, image_ctx.kernel)

