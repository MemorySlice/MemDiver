"""Private-frame restriction of sibling process views for consensus (plan S4, ``frames="private"``).

N sibling processes of one full image stand in for N captures. A physical frame mapped by
two or more of them has ONE content, so it cannot hold a value that differs between them:
only frames private to one member can hold a per-instance secret
(:mod:`memdiver.core.image.page_sharing`, tier T1). :class:`PrivateFrameSource` hands the
consensus engine exactly those frames.

It wraps an opened, VA-capable view source and narrows :meth:`captured_runs` to the
private sub-runs, keeping every sub-run's ``vas_offset`` in the wrapped source's ``"vas"``
coordinate (``run.vas_offset + (sub_va - run.va)``). Nothing else changes: ``read_range``,
``va_to_vas_offset``, ``vmas``, ``path`` ... are forwarded, so the aligned layout the
consensus publishes still points into the real view and the hex overlay needs no special
case. ``core.region_align._aligns_by_run_table`` consumes the narrowed table unchanged,
under both the ``virtual_address`` and the ``module_relative`` key schemes.

The private set is a property of the MEMBER SET, not of one process: a page shared by
members 1 and 2 is private when only member 1 is analysed. :func:`restrict_to_private_frames`
therefore classifies all N views together, from one image.

Shared frames are excluded from the comparison, never denied to exist: the excluded bytes
and their classes are reported (:data:`PRIVATE_FRAMES_DIAGNOSTIC`), because a shared frame
can still hold a GROUP secret (e.g. a key loaded before ``fork()``).
"""

from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence,
                    Tuple)

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: ``frames=`` values accepted by the consensus builders.
FRAMES_ALL = "all"
FRAMES_PRIVATE = "private"
FRAMES_CHOICES = (FRAMES_ALL, FRAMES_PRIVATE)

#: Diagnostic code attached to a ``frames="private"`` consensus report.
PRIVATE_FRAMES_DIAGNOSTIC = "consensus_private_frames"

#: ``CapabilityError`` codes.
FRAMES_UNAVAILABLE = "consensus.frames_unavailable"
FRAMES_UNKNOWN = "consensus.unknown_frames"

#: The page classes whose frames are kept (mirrors ``frames.PRIVATE_CLASSES``).
_PRIVATE = frozenset({"private_dirty", "private_clean", "private_file_cow"})

#: ``(va, length, share_class)`` of one classified stretch of a member's address space.
ClassSpan = Tuple[int, int, str]

#: Classifies N opened views together: one span list per source, in source order.
FrameClassifier = Callable[[Sequence[Any]], List[List[ClassSpan]]]

Run = Tuple[int, int, int]


def validate_frames_choice(frames: str) -> None:
    """Reject a ``frames=`` value outside :data:`FRAMES_CHOICES`."""
    if frames not in FRAMES_CHOICES:
        raise CapabilityError(
            f"unknown frames {frames!r}; expected one of {', '.join(FRAMES_CHOICES)}",
            category=ErrorCategory.INVALID_INPUT, code=FRAMES_UNKNOWN)


# -- the wrapper ------------------------------------------------------------------------

class PrivateFrameSource:
    """A view source restricted to the captured bytes that lie in private frames."""

    def __init__(self, source: Any, spans: Iterable[ClassSpan]) -> None:
        self._source = source
        self._spans = _merge_spans(spans)
        self._starts = [s[0] for s in self._spans]
        self._runs: Optional[Tuple[Run, ...]] = None
        self._bytes_by_class: Optional[Dict[str, int]] = None

    @property
    def wrapped(self) -> Any:
        return self._source

    # Declared, not forwarded through ``__getattr__``: ``region_align`` and
    # ``choose_alignment`` read these with ``getattr(..., False)``.
    @property
    def supports_va_alignment(self) -> bool:
        return bool(getattr(self._source, "supports_va_alignment", False))

    @property
    def va_alignment_by_runs(self) -> bool:
        return bool(getattr(self._source, "va_alignment_by_runs", False))

    @property
    def path(self) -> Path:
        return self._source.path

    def captured_runs(self) -> Tuple[Run, ...]:
        """``(va, length, vas_offset)`` of every private sub-run of a captured run."""
        if self._runs is None:
            self._account()
        assert self._runs is not None  # nosec B101 - set by _account
        return self._runs

    def bytes_by_class(self) -> Dict[str, int]:
        """Captured bytes of the wrapped view per share class (``unclassified`` = no page)."""
        if self._bytes_by_class is None:
            self._account()
        return dict(self._bytes_by_class or {})

    def captured_bytes(self) -> int:
        return sum(self.bytes_by_class().values())

    def private_bytes(self) -> int:
        return sum(n for _, n, _ in self.captured_runs())

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not defined here: read_range(_valid), metadata,
        # vmas, layer_runs, va_span_start, va_to_vas_offset, descriptor, format_name ...
        if name.startswith("__") or name in ("_source", "_spans", "_starts"):
            raise AttributeError(name)
        return getattr(self._source, name)

    def _account(self) -> None:
        runs: List[Run] = []
        totals: Counter = Counter()
        for (va, length, off), lo, hi, share_class in _cut(self._source.captured_runs(),
                                                            self._spans, self._starts):
            totals[share_class] += hi - lo
            if share_class in _PRIVATE:
                if runs and runs[-1][0] + runs[-1][1] == lo \
                        and runs[-1][2] + runs[-1][1] == off + (lo - va):
                    prev = runs[-1]
                    runs[-1] = (prev[0], prev[1] + hi - lo, prev[2])
                else:
                    runs.append((lo, hi - lo, off + (lo - va)))
        self._runs = tuple(runs)
        self._bytes_by_class = dict(totals)


def _merge_spans(spans: Iterable[ClassSpan]) -> List[ClassSpan]:
    """Sorted, adjacent same-class spans merged; overlaps keep the first span."""
    merged: List[ClassSpan] = []
    for va, length, share_class in sorted((int(v), int(n), str(c)) for v, n, c in spans):
        if length <= 0:
            continue
        if merged:
            pva, plen, pcls = merged[-1]
            if va < pva + plen:  # overlap: trim to what the previous span left
                cut = pva + plen - va
                if cut >= length:
                    continue
                va, length = va + cut, length - cut
            if pcls == share_class and pva + plen == va:
                merged[-1] = (pva, plen + length, pcls)
                continue
        merged.append((va, length, share_class))
    return merged


def _cut(runs: Iterable[Run], spans: Sequence[ClassSpan],
         starts: Sequence[int]) -> Iterator[Tuple[Run, int, int, str]]:
    """``(run, lo, hi, class)`` pieces of every run; gaps between spans are ``unclassified``."""
    for run in runs:
        va, length = int(run[0]), int(run[1])
        cursor, end = va, va + length
        i = max(bisect.bisect_right(starts, cursor) - 1, 0)
        while cursor < end:
            span = spans[i] if i < len(spans) else None
            if span is None or span[0] >= end:
                yield run, cursor, end, "unclassified"
                break
            s_lo, s_hi = span[0], span[0] + span[1]
            if s_hi <= cursor:
                i += 1
                continue
            if s_lo > cursor:
                yield run, cursor, s_lo, "unclassified"
                cursor = s_lo
            hi = min(s_hi, end)
            yield run, cursor, hi, span[2]
            cursor = hi
            i += 1


# -- restricting a member set -----------------------------------------------------------

@dataclass
class PrivateFramesReport:
    """What ``frames="private"`` kept and excluded, per source and in total."""

    per_source: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def captured_bytes(self) -> int:
        return sum(s["captured_bytes"] for s in self.per_source)

    @property
    def private_bytes(self) -> int:
        return sum(s["private_bytes"] for s in self.per_source)

    @property
    def excluded_bytes(self) -> int:
        return self.captured_bytes - self.private_bytes

    def bytes_by_class(self) -> Dict[str, int]:
        totals: Counter = Counter()
        for s in self.per_source:
            totals.update(s["bytes_by_class"])
        return dict(totals)

    def diagnostic(self) -> Any:
        """INFO ``Diagnostic`` (:data:`PRIVATE_FRAMES_DIAGNOSTIC`) for the alignment report."""
        from memdiver.core.service_result import Diagnostic, Severity
        excluded = self.excluded_bytes
        return Diagnostic(
            code=PRIVATE_FRAMES_DIAGNOSTIC,
            message=(f"frames=private: {self.private_bytes} of {self.captured_bytes} "
                     f"captured bytes lie in frames private to one member; {excluded} "
                     f"bytes in shared/special frames were excluded from the comparison "
                     f"(they cannot hold a per-instance value, but may hold a group "
                     f"secret)"),
            severity=Severity.INFO,
            details={"captured_bytes": self.captured_bytes,
                     "private_bytes": self.private_bytes,
                     "excluded_bytes": excluded,
                     "bytes_by_class": self.bytes_by_class(),
                     "per_source": self.per_source})


def restrict_to_private_frames(
    sources: Sequence[Any], classifier: Optional[FrameClassifier] = None,
) -> Tuple[List[PrivateFrameSource], PrivateFramesReport]:
    """Wrap N process views of ONE image in :class:`PrivateFrameSource`, classified together.

    Raises ``CapabilityError`` (:data:`FRAMES_UNAVAILABLE`) unless every source is an
    opened process view (``.mdview``) of the same image with a distinct pid.
    """
    require_sibling_views(sources)
    spans = (classifier or classify_view_sources)(sources)
    wrapped = [PrivateFrameSource(src, s) for src, s in zip(sources, spans)]
    report = PrivateFramesReport([
        {"path": str(getattr(src, "path", "")), "pid": src.descriptor.pid,
         "captured_bytes": w.captured_bytes(), "private_bytes": w.private_bytes(),
         "bytes_by_class": w.bytes_by_class()}
        for src, w in zip(sources, wrapped)])
    return wrapped, report


def require_sibling_views(sources: Sequence[Any]) -> None:
    """Every source a process view of one image, each pid once (else ``CapabilityError``)."""
    from memdiver.core.image.view_descriptor import ViewKind
    descriptors = [getattr(s, "descriptor", None) for s in sources]
    if not all(d is not None and getattr(d, "view", None) is ViewKind.PROCESS
               for d in descriptors):
        _unavailable("every dump must be a process view (.mdview) of a full memory image")
    if len({d.image_sha256 for d in descriptors}) != 1:  # type: ignore[union-attr]
        _unavailable("every process view must come from the SAME memory image: frames are "
                     "physical, so sharing is only defined inside one image")
    pids = [d.pid for d in descriptors]  # type: ignore[union-attr]
    if len(set(pids)) != len(pids):
        _unavailable("each process may appear once: two views of one pid share every frame")


def _unavailable(reason: str) -> None:
    raise CapabilityError(f"frames='private' is not available for these dumps: {reason}",
                          category=ErrorCategory.UNSUPPORTED, code=FRAMES_UNAVAILABLE)


def classify_view_sources(sources: Sequence[Any]) -> List[List[ClassSpan]]:
    """Default :data:`FrameClassifier`: walk and classify the views' pids as one group."""
    from memdiver.core.image.context import image_context_for
    from memdiver.core.image.page_sharing import classify_processes
    first = sources[0]
    image_ctx = image_context_for(first.descriptor, Path(first.path))
    pids = [int(s.descriptor.pid) for s in sources]
    result = classify_processes(image_ctx, pids)
    if result.same_address_space:
        _unavailable(f"pids {sorted(result.same_address_space)} share an address space "
                     f"(mm) with another member")
    spans: Dict[int, List[ClassSpan]] = {pid: [] for pid in pids}
    for page in result.classification.pages:
        spans[page.member].append((page.va, page.length, page.share_class))
    return [spans[pid] for pid in pids]
