"""Anchor-relative consensus — compare ``object + delta`` across captures.

Flat consensus compares the byte at the same dump offset (or the same VA) in
every capture. Around a heap object that is the wrong coordinate system: the
allocator places the object at a different address in every run, so offset X
in run 1 and offset X in run 2 hold different logical contents and their
"variance" is noise (memo §4). Here every capture contributes the window
``[anchor + delta_start, anchor + delta_start + length)`` around ITS OWN
anchor -- typically the verified key the analyst already located in that
capture -- and the statistics are keyed by ``delta``, the position relative to
the anchor.

Correspondence is an INPUT, not a conclusion. Each :class:`Anchor` says which
bytes the caller asserts are "the same object" in that capture and records why
(``basis``); a needle that occurs several times per capture yields one
alternative per occurrence (see :func:`anchors_from_needles`) instead of a
silent first-hit choice.

Coverage is explicit (P3): a delta whose byte is not captured in an instance
does not contribute a zero to the statistics. Positions captured in fewer than
``min_instances`` anchors are classified :data:`UNDETERMINED`, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from memdiver.core.dump_source import find_all_in
from memdiver.core.variance import (
    ByteClass, VarianceThresholds, classify_variance, find_contiguous_runs,
)

# Class code for a delta captured in too few instances to classify honestly.
UNDETERMINED = 255
CLASS_NAMES: Dict[int, str] = {int(c): c.name.lower() for c in ByteClass}
CLASS_NAMES[UNDETERMINED] = "undetermined"
MAX_WINDOW = 1 << 20  # 1 MiB per instance keeps N windows in memory comfortably


@dataclass(frozen=True)
class Anchor:
    """One instance of the object: a capture and the anchor's position in it.

    ``offset`` is in ``view`` coordinates of that capture's DumpSource
    (``"va"``: VA minus ``va_span_start``; ``"raw"``: file offset). ``va`` is
    the absolute VA when the source has one. ``basis`` says why this position
    is asserted to be the object (P1: an interpretation carries its support).
    """

    dump_path: str
    offset: int
    view: str = "va"
    va: Optional[int] = None
    basis: str = ""


@dataclass
class InstanceWindow:
    """The bytes one anchor contributed and which of them were captured."""

    anchor: Anchor
    data: bytes
    captured: np.ndarray  # bool, one per window position

    @property
    def captured_bytes(self) -> int:
        return int(self.captured.sum())


@dataclass
class AnchorConsensus:
    """Per-delta statistics over the instances' windows."""

    delta_start: int
    length: int
    instances: List[InstanceWindow]
    variance: np.ndarray        # float32; NaN where UNDETERMINED
    classes: np.ndarray         # uint8 ByteClass codes or UNDETERMINED
    captured_count: np.ndarray  # instances that captured each delta
    distinct_values: np.ndarray  # distinct byte values among captured instances
    min_instances: int
    thresholds: Optional[VarianceThresholds] = None
    warnings: List[str] = field(default_factory=list)

    def regions(self) -> List[Dict[str, Any]]:
        """Maximal runs of one class, keyed by delta (half-open)."""
        out: List[Dict[str, Any]] = []
        for code in sorted(set(int(c) for c in np.unique(self.classes))):
            for start, end in find_contiguous_runs(self.classes, code):
                out.append(self._region_row(code, start, end))
        return sorted(out, key=lambda r: r["delta_start"])

    def _region_row(self, code: int, start: int, end: int) -> Dict[str, Any]:
        return {
            "delta_start": self.delta_start + start,
            "delta_end": self.delta_start + end,
            "length": end - start,
            "class": CLASS_NAMES[code],
            "min_captured": int(self.captured_count[start:end].min()),
            "max_distinct": int(self.distinct_values[start:end].max()),
        }

    def class_at(self, delta: int) -> str:
        return CLASS_NAMES[int(self.classes[delta - self.delta_start])]


def read_instance(source: Any, anchor: Anchor, delta_start: int,
                  length: int) -> InstanceWindow:
    """Read the window around *anchor* with a per-byte captured mask.

    A start before the view's origin is clipped and the clipped prefix is
    uncaptured, never zero-filled data.
    """
    start = anchor.offset + delta_start
    skip = max(0, -start)
    data = bytearray(length)
    captured = np.zeros(length, dtype=bool)
    if skip < length:
        chunk, runs = _read_valid(source, start + skip, length - skip, anchor.view)
        data[skip:skip + len(chunk)] = chunk
        for run_start, run_len in runs:
            captured[skip + run_start:skip + run_start + run_len] = True
    return InstanceWindow(anchor=anchor, data=bytes(data), captured=captured)


def _read_valid(source: Any, offset: int, length: int,
                view: str) -> Tuple[bytes, List[Tuple[int, int]]]:
    """``read_range_valid`` when the source has it; else a short read is the
    captured prefix (raw sources never pad)."""
    if hasattr(source, "read_range_valid"):
        return source.read_range_valid(offset, length, view)
    data = source.read_range(offset, length, view)
    return data, ([(0, len(data))] if data else [])


def anchor_consensus(windows: Sequence[InstanceWindow], *, delta_start: int,
                     min_instances: Optional[int] = None,
                     thresholds: Optional[VarianceThresholds] = None,
                     ) -> AnchorConsensus:
    """Classify every delta over the instances that captured it.

    *min_instances* defaults to ALL instances: a delta missing from one
    capture is undetermined unless the caller explicitly accepts fewer.
    """
    if len(windows) < 2:
        raise ValueError("anchor consensus needs at least 2 instances")
    length = len(windows[0].data)
    need = len(windows) if min_instances is None else int(min_instances)
    if not 2 <= need <= len(windows):
        raise ValueError(f"min_instances must be in [2, {len(windows)}], got {need}")
    values = np.stack([np.frombuffer(w.data, dtype=np.uint8) for w in windows])
    mask = np.stack([w.captured for w in windows])
    count = mask.sum(axis=0).astype(np.int32)
    variance = _masked_variance(values.astype(np.float32), mask, count)
    classes = classify_variance(np.nan_to_num(variance, nan=0.0), thresholds)
    determined = count >= need
    classes[~determined] = UNDETERMINED
    variance[~determined] = np.nan
    return AnchorConsensus(
        delta_start=delta_start, length=length, instances=list(windows),
        variance=variance, classes=classes, captured_count=count,
        distinct_values=_distinct_counts(values, mask), min_instances=need,
        thresholds=thresholds, warnings=_coverage_warnings(windows))


def _masked_variance(values: np.ndarray, mask: np.ndarray,
                     count: np.ndarray) -> np.ndarray:
    """Population variance per column over captured cells only (``np.var``
    semantics, matching ``core.variance.compute_variance``)."""
    safe = np.maximum(count, 1).astype(np.float32)
    mean = np.where(mask, values, 0.0).sum(axis=0) / safe
    sq = np.where(mask, (values - mean) ** 2, 0.0).sum(axis=0) / safe
    return np.where(count > 0, sq, np.nan).astype(np.float32)


def _distinct_counts(values: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Distinct captured byte values per delta (memo §5: enum/flag hints)."""
    present = np.zeros((256, values.shape[1]), dtype=bool)
    rows, cols = np.nonzero(mask)
    present[values[rows, cols], cols] = True
    return present.sum(axis=0).astype(np.int32)


def _coverage_warnings(windows: Sequence[InstanceWindow]) -> List[str]:
    return [f"{w.anchor.dump_path}: only {w.captured_bytes}/{len(w.data)} window "
            "bytes captured" for w in windows if w.captured_bytes < len(w.data)]


DEFAULT_MAX_HITS = 1024


@dataclass(frozen=True)
class NeedleSearch:
    """One capture's needle search: the anchors and whether the cap cut it.

    ``truncated`` means more occurrences exist than ``anchors`` holds (P3: a
    capped search must never read as "absent").
    """

    anchors: List[Anchor]
    truncated: bool
    cap: int


def search_needles(sources: Dict[str, Any], needles: Dict[str, bytes], *,
                   view: str = "va", max_hits: Optional[int] = None,
                   ) -> Dict[str, NeedleSearch]:
    """Like :func:`anchors_from_needles` but reports truncation per capture.

    Asks the source for ``max_hits + 1`` hits: the extra one proves the cap
    cut the search.
    """
    max_hits = DEFAULT_MAX_HITS if max_hits is None else int(max_hits)
    out: Dict[str, NeedleSearch] = {}
    for path, needle in needles.items():
        source = sources[path]
        _require_searchable(source, path, view)
        hits = sorted(find_all_in(source, needle, view, limit=max_hits + 1))
        truncated = len(hits) > max_hits
        hits = hits[:max_hits]
        out[path] = NeedleSearch(
            [_needle_anchor(source, path, hit, view, k, len(hits), truncated)
             for k, hit in enumerate(hits)], truncated, max_hits)
    return out


def anchors_from_needles(sources: Dict[str, Any], needles: Dict[str, bytes], *,
                         view: str = "va", max_hits: Optional[int] = None,
                         ) -> Dict[str, List[Anchor]]:
    """Every occurrence of each capture's needle, as alternative anchors.

    Several hits per capture are ALL returned (occurrence k in address order,
    the basis says so; a capped search says "of >=N (search capped)");
    choosing which one corresponds across captures is the caller's decision,
    recorded in each anchor's ``basis``. Use :func:`search_needles` to get the
    per-capture truncation flag.
    """
    return {p: r.anchors for p, r in search_needles(
        sources, needles, view=view, max_hits=max_hits).items()}


def _require_searchable(source: Any, path: str, view: str) -> None:
    """An UNOPENED ``MslDumpSource`` answers ``find_all`` with ``[]`` and
    ``va_span_start()`` with ``None`` -- "not searched" would read as "absent".
    Refuse instead of reporting zero anchors."""
    if view == "va" and getattr(source, "va_span_start", lambda: None)() is None:
        raise ValueError(f"{path}: source has no open VA view (open it first); "
                         "an empty search here would not mean 'absent'")


def _needle_anchor(source: Any, path: str, hit: int, view: str, k: int,
                   total: int, truncated: bool = False) -> Anchor:
    base = source.va_span_start() if view == "va" and hasattr(source, "va_span_start") else None
    return Anchor(dump_path=path, offset=hit, view=view,
                  va=None if base is None else base + hit,
                  basis=(f"needle occurrence {k} of \u2265{total} (search capped, {view} order)"
                        if truncated else
                        f"needle occurrence {k} of {total} ({view} order)"))
