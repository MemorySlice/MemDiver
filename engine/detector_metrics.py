"""Interval-based detection metrics for emitted detectors (YARA / patterns).

Scores a detector's *match windows* against known-true key *intervals*
(:class:`engine.truth_labels.TruthInterval`). Pure compute: no file IO, no
database, and no dependency on the scanner that produced the matches.

Why a new metric type instead of :class:`engine.convergence.DetectionMetrics`?
``engine/convergence.py`` is deliberately left untouched, because reusing it
here would be wrong on three separate counts:

1. **Wrong relation.** :func:`engine.convergence._compute_metrics` is an exact
   set intersection over individual *byte offsets*. But
   :meth:`architect.pattern_generator` builds ``wildcard_pattern`` as one flat
   wildcarded byte string spanning a whole region, so ``yara.match`` reports the
   start of the *window that contains* the key, not the key offset. An exact
   intersection therefore scores ``tp=0`` on every genuine match — a detector
   that works perfectly would report zero precision and zero recall.
2. **Wrong quantity.** Byte-set semantics makes a 96-byte match "cover" 96
   truth offsets, so precision becomes a property of how much padding the
   emitted window carries rather than of whether the detector found the key.
   Intervals are the unit the rule actually claims.
3. **Wrong shape.** ``DetectionMetrics`` has no ``fn``, no notion of tolerance,
   and is frozen into :class:`engine.convergence.ConvergencePoint`, which the
   web surface reads — widening it would be a breaking change to a published
   payload.

Precision and recall are indexed on **different sets**
--------------------------------------------------------
The match/truth relation here is genuinely many-to-many: one wildcarded window
can contain several keys (fan-out), and several overlapping rules can each fire
on the same key (fan-in). Rather than force an arbitrary one-to-one assignment,
the two error types are counted on the set each one is actually about:

* ``precision = tp_matches / matches`` is **match-indexed** — the fraction of
  the detector's own firings that landed on at least one real key.
* ``recall = covered_truths / truths`` is **truth-indexed** — the fraction of
  real keys that at least one firing landed on.

This is the standard construction for fuzzy-matched detection, and it makes
both rates bounded by ``1.0`` *by construction*: each numerator counts distinct
members of its own denominator's set. It also means the two are not two views
of one confusion matrix — you cannot recombine them into a single ``tp``.

Because that hides the many-to-one structure, :attr:`~IntervalDetectionMetrics.max_matches_per_truth`
(fan-in) and :attr:`~IntervalDetectionMetrics.max_truths_per_match` (fan-out)
are published alongside the headline numbers **precisely so that structure stays
visible** rather than being laundered into a single flattering score: a
``recall`` of 1.0 reached by one enormous window that swallows every key shows
up as ``max_truths_per_match == truths``, and duplicate detections of one key
show up as ``max_matches_per_truth > 1``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger("memdiver.engine.detector_metrics")

#: Default tolerance for the ``key_offset`` criterion, in bytes.
#: :func:`core.alignment_filter.alignment_filter` groups candidates into blocks
#: on ``alignment=16`` boundaries, so the start of a detected region can
#: legitimately sit up to 15 bytes below the true key start while still being
#: the same finding. 16 admits exactly that slack and no more.
DEFAULT_TOLERANCE_BYTES = 16

CRITERION_CONTAINMENT = "containment"
CRITERION_KEY_OFFSET = "key_offset"
CRITERION_EXACT = "exact"

#: The three criteria, headline first. All three are always returned together —
#: this is one designed report shape, not a hedge between candidate metrics:
#: ``containment`` says the rule's window did enclose the key (what a
#: wildcarded-window rule actually claims), ``key_offset`` says the rule's
#: predicted key position was right to within alignment slack, and ``exact``
#: says it was right to the byte. Reading them together is what distinguishes
#: "found the neighbourhood" from "found the key".
CRITERIA: Tuple[str, str, str] = (
    CRITERION_CONTAINMENT, CRITERION_KEY_OFFSET, CRITERION_EXACT,
)


@dataclass(frozen=True)
class IntervalDetectionMetrics:
    """Precision/recall for one criterion over one match set and truth set.

    ``matches`` is the precision denominator and ``truths`` the recall
    denominator. Note that ``matches`` is criterion-dependent: under
    ``key_offset``/``exact`` a match that carries no ``key_offset`` meta makes
    no positional claim at all, so it is *unscorable* and excluded from the
    denominator rather than charged as a false positive (see
    :func:`score_intervals`).

    Convention for empty inputs (chosen deliberately over adding a separate
    "vacuous" flag): every rate is ``0.0`` when its denominator is zero — never
    a :class:`ZeroDivisionError` — and the ``truths`` / ``matches`` counts are
    themselves the discriminator. ``recall == 0.0 and truths == 0`` means *there
    was nothing to find* (vacuous, no evidence either way); ``recall == 0.0 and
    truths > 0`` means the detector genuinely missed every key. Consumers that
    aggregate or plot must check ``truths`` before treating a zero as a failure.

    ``pairs`` holds every related ``(match_idx, truth_idx, delta)`` triple, with
    indices into the *original* ``matches``/``truths`` sequences (so unscorable
    matches leave gaps rather than renumbering). ``delta`` is the truth start
    relative to the window start for ``containment``, and ``truth_start -
    predicted_start`` for ``key_offset``/``exact`` (signed: negative means the
    prediction sat above the key).
    """

    criterion: str
    tolerance_bytes: int
    matches: int
    truths: int
    tp_matches: int
    fp_matches: int
    covered_truths: int
    missed_truths: int
    precision: float
    recall: float
    f1: float
    max_matches_per_truth: int
    max_truths_per_match: int
    pairs: Tuple[Tuple[int, int, int], ...]

    def to_dict(self) -> dict:
        """JSON-serialisable view; ``pairs`` becomes a list of 3-item lists."""
        return {
            "criterion": self.criterion,
            "tolerance_bytes": self.tolerance_bytes,
            "matches": self.matches,
            "truths": self.truths,
            "tp_matches": self.tp_matches,
            "fp_matches": self.fp_matches,
            "covered_truths": self.covered_truths,
            "missed_truths": self.missed_truths,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "max_matches_per_truth": self.max_matches_per_truth,
            "max_truths_per_match": self.max_truths_per_match,
            "pairs": [list(p) for p in self.pairs],
        }


# --------------------------------------------------------------------------- #
# Duck-typed accessors.
#
# ``matches`` are shaped like ``engine.yara_scan.RuleMatch`` (``offset``,
# ``length``, ``key_offset``, ``key_length``) but that class is deliberately NOT
# imported: anything exposing those attributes works, which keeps the metric
# module independent of whichever scanner produced the hits.
# --------------------------------------------------------------------------- #

def _int_or(value: Any, default: int = 0) -> int:
    return default if value is None else int(value)


def _match_start(match: Any) -> int:
    return _int_or(getattr(match, "offset", None))


def _match_length(match: Any) -> int:
    return _int_or(getattr(match, "length", None))


def _match_key_offset(match: Any) -> Optional[int]:
    """The match's predicted key position, relative to its own start."""
    value = getattr(match, "key_offset", None)
    return None if value is None else int(value)


def _truth_start(truth: Any) -> int:
    """Start of a truth interval (``TruthInterval.start``, or ``offset``)."""
    value = getattr(truth, "start", None)
    if value is None:
        value = getattr(truth, "offset", None)
    return _int_or(value)


def _truth_length(truth: Any) -> int:
    return _int_or(getattr(truth, "length", None))


# --------------------------------------------------------------------------- #
# Relations
# --------------------------------------------------------------------------- #

def _containment_pairs(
    matches: Sequence[Any], truths: Sequence[Any],
) -> List[Tuple[int, int, int]]:
    """``(i, j)`` when truth ``j`` lies wholly inside match window ``i``.

    ``s_i <= t_j and t_j + k_j <= s_i + l_i`` — exactly the claim a wildcarded
    window rule makes. ``delta`` is ``t_j - s_i``: where in the window the key sat.
    """
    pairs: List[Tuple[int, int, int]] = []
    for i, match in enumerate(matches):
        start = _match_start(match)
        end = start + _match_length(match)
        for j, truth in enumerate(truths):
            t_start = _truth_start(truth)
            if start <= t_start and t_start + _truth_length(truth) <= end:
                pairs.append((i, j, t_start - start))
    return pairs


def _key_offset_pairs(
    matches: Sequence[Any], truths: Sequence[Any], tolerance_bytes: int,
) -> Tuple[List[Tuple[int, int, int]], int]:
    """``(i, j)`` when match ``i``'s predicted key start is within tolerance.

    ``p_i = s_i + key_offset_i``; related iff ``|p_i - t_j| <= tolerance_bytes``.
    Returns the pairs plus the number of *scorable* matches (those carrying a
    ``key_offset`` meta at all) — matches without one make no positional claim
    and are excluded from the precision denominator.
    """
    pairs: List[Tuple[int, int, int]] = []
    scorable = 0
    for i, match in enumerate(matches):
        key_offset = _match_key_offset(match)
        if key_offset is None:
            continue
        scorable += 1
        predicted = _match_start(match) + key_offset
        for j, truth in enumerate(truths):
            delta = _truth_start(truth) - predicted
            if abs(delta) <= tolerance_bytes:
                pairs.append((i, j, delta))
    return pairs, scorable


# --------------------------------------------------------------------------- #
# Counting
# --------------------------------------------------------------------------- #

def _ratio(numerator: int, denominator: int) -> float:
    """Safe division: a zero denominator yields ``0.0``, never an exception."""
    return numerator / denominator if denominator > 0 else 0.0


def _harmonic_mean(precision: float, recall: float) -> float:
    total = precision + recall
    return 2 * precision * recall / total if total > 0 else 0.0


def _fan(pairs: Iterable[Tuple[int, int, int]], index: int) -> int:
    """Largest number of partners any single member of one side accumulated."""
    counts: dict = {}
    for pair in pairs:
        counts[pair[index]] = counts.get(pair[index], 0) + 1
    return max(counts.values()) if counts else 0


def _metrics_from_pairs(
    criterion: str,
    tolerance_bytes: int,
    pairs: Sequence[Tuple[int, int, int]],
    n_matches: int,
    n_truths: int,
) -> IntervalDetectionMetrics:
    """Apply the counting rule to one relation.

    ``tp_matches``/``fp_matches`` are match-indexed and
    ``covered_truths``/``missed_truths`` truth-indexed, so both rates are
    bounded by ``1.0`` by construction (module docstring).
    """
    tp_matches = len({p[0] for p in pairs})
    covered_truths = len({p[1] for p in pairs})
    precision = _ratio(tp_matches, n_matches)
    recall = _ratio(covered_truths, n_truths)
    return IntervalDetectionMetrics(
        criterion=criterion,
        tolerance_bytes=tolerance_bytes,
        matches=n_matches,
        truths=n_truths,
        tp_matches=tp_matches,
        fp_matches=max(n_matches - tp_matches, 0),
        covered_truths=covered_truths,
        missed_truths=max(n_truths - covered_truths, 0),
        precision=precision,
        recall=recall,
        f1=_harmonic_mean(precision, recall),
        max_matches_per_truth=_fan(pairs, 1),
        max_truths_per_match=_fan(pairs, 0),
        pairs=tuple(pairs),
    )


def score_intervals(
    matches: Sequence[Any],
    truths: Sequence[Any],
    *,
    tolerance_bytes: int = DEFAULT_TOLERANCE_BYTES,
) -> dict:
    """Score *matches* against *truths* under all three criteria.

    Args:
        matches: Detector firings — anything with ``offset``, ``length`` and
            (optionally) ``key_offset`` / ``key_length`` attributes; shaped like
            ``engine.yara_scan.RuleMatch``, which is intentionally not imported.
        truths: Known-true intervals — :class:`engine.truth_labels.TruthInterval`
            or anything with ``start``/``length``.
        tolerance_bytes: Slack for the ``key_offset`` criterion. Defaults to
            :data:`DEFAULT_TOLERANCE_BYTES` (16), matching the ``alignment=16``
            used by :func:`core.alignment_filter.alignment_filter`.

    Returns:
        ``{"containment": ..., "key_offset": ..., "exact": ...}``, each an
        :class:`IntervalDetectionMetrics`. All three are always present.
        ``exact`` is ``key_offset`` with ``tolerance_bytes=0``, so its relation
        is a subset of ``key_offset``'s.
    """
    match_list = list(matches)
    truth_list = list(truths)
    n_matches = len(match_list)
    n_truths = len(truth_list)

    containment = _metrics_from_pairs(
        CRITERION_CONTAINMENT, tolerance_bytes,
        _containment_pairs(match_list, truth_list), n_matches, n_truths,
    )

    fuzzy_pairs, scorable = _key_offset_pairs(
        match_list, truth_list, max(tolerance_bytes, 0))
    key_offset = _metrics_from_pairs(
        CRITERION_KEY_OFFSET, tolerance_bytes, fuzzy_pairs, scorable, n_truths,
    )

    exact_pairs, _ = _key_offset_pairs(match_list, truth_list, 0)
    exact = _metrics_from_pairs(
        CRITERION_EXACT, 0, exact_pairs, scorable, n_truths,
    )

    return {
        CRITERION_CONTAINMENT: containment,
        CRITERION_KEY_OFFSET: key_offset,
        CRITERION_EXACT: exact,
    }


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def _sum_metrics(
    criterion: str,
    tolerance_bytes: int,
    parts: Sequence[IntervalDetectionMetrics],
) -> IntervalDetectionMetrics:
    """Micro-average a criterion's metrics across independently scored rows.

    Counts are additive; ``precision``/``recall``/``f1`` are recomputed from the
    summed counts (a micro-average, so a row with many matches weighs more than
    a row with one). The fan-in/fan-out maxima are the max over rows. ``pairs``
    is emptied: its indices are only meaningful within the single row they were
    computed in, and concatenating them would invent cross-row pairings.
    """
    matches = sum(p.matches for p in parts)
    truths = sum(p.truths for p in parts)
    tp_matches = sum(p.tp_matches for p in parts)
    covered_truths = sum(p.covered_truths for p in parts)
    precision = _ratio(tp_matches, matches)
    recall = _ratio(covered_truths, truths)
    return IntervalDetectionMetrics(
        criterion=criterion,
        tolerance_bytes=tolerance_bytes,
        matches=matches,
        truths=truths,
        tp_matches=tp_matches,
        fp_matches=sum(p.fp_matches for p in parts),
        covered_truths=covered_truths,
        missed_truths=sum(p.missed_truths for p in parts),
        precision=precision,
        recall=recall,
        f1=_harmonic_mean(precision, recall),
        max_matches_per_truth=max((p.max_matches_per_truth for p in parts), default=0),
        max_truths_per_match=max((p.max_truths_per_match for p in parts), default=0),
        pairs=(),
    )


def _row_truth_sources(truths: Sequence[Any]) -> List[str]:
    return sorted({str(getattr(t, "source", "") or "") for t in truths} - {""})


def _score_row(row: Mapping[str, Any], tolerance_bytes: int) -> dict:
    """Score one report row, returning its per-criterion metrics and provenance."""
    truths = list(row.get("truths") or ())
    metrics = score_intervals(
        list(row.get("matches") or ()), truths, tolerance_bytes=tolerance_bytes)
    sources = row.get("truth_sources")
    return {
        "detector": str(row.get("detector") or "unknown"),
        "dump": str(row.get("dump") or ""),
        "truth_sources": list(sources) if sources else _row_truth_sources(truths),
        "metrics": metrics,
    }


def aggregate_detector_report(
    rows: Sequence[Mapping[str, Any]],
    *,
    tolerance_bytes: int = DEFAULT_TOLERANCE_BYTES,
) -> dict:
    """Roll per-dump scoring rows up into one detector-quality report.

    Args:
        rows: One mapping per (detector, dump) pair:

            * ``"matches"`` — that detector's firings on that dump.
            * ``"truths"`` — the truth intervals for that dump.
            * ``"detector"`` — detector/rule name (default ``"unknown"``).
            * ``"dump"`` — optional label, carried through for provenance.
            * ``"truth_sources"`` — optional override; otherwise derived from
              the intervals' own ``source`` field, so a report scored against
              the sparse DuckDB ledger is never mistaken for one scored against
              the complete keylog truth (see :mod:`engine.truth_labels`).

    Returns:
        ``{"tolerance_bytes", "criteria", "rows", "detectors", "overall"}``,
        fully JSON-serialisable. ``detectors`` is sorted by name; each entry and
        ``overall`` carry one ``to_dict()`` payload per criterion.

    Each row is scored **independently** and only the counts are summed. Pooling
    the intervals first would let a match from one dump pair with a truth from
    another whose offsets happen to line up, inventing true positives.
    """
    scored = [_score_row(row, tolerance_bytes) for row in rows]

    by_detector: dict = {}
    for entry in scored:
        by_detector.setdefault(entry["detector"], []).append(entry)

    detectors = [
        _detector_summary(name, entries, tolerance_bytes)
        for name, entries in sorted(by_detector.items())
    ]
    return {
        "tolerance_bytes": tolerance_bytes,
        "criteria": list(CRITERIA),
        "rows": len(scored),
        "detectors": detectors,
        "overall": _group_summary(scored, tolerance_bytes),
    }


def _group_summary(entries: Sequence[Mapping[str, Any]], tolerance_bytes: int) -> dict:
    """Micro-averaged metrics + provenance for a group of scored rows."""
    sources = sorted({s for e in entries for s in e["truth_sources"]})
    tolerances = {CRITERION_EXACT: 0}
    return {
        "rows": len(entries),
        "truth_sources": sources,
        "metrics": {
            criterion: _sum_metrics(
                criterion,
                tolerances.get(criterion, tolerance_bytes),
                [e["metrics"][criterion] for e in entries],
            ).to_dict()
            for criterion in CRITERIA
        },
    }


def _detector_summary(
    name: str, entries: Sequence[Mapping[str, Any]], tolerance_bytes: int,
) -> dict:
    summary: dict = {"detector": name}
    summary.update(_group_summary(entries, tolerance_bytes))
    summary["dumps"] = [e["dump"] for e in entries if e["dump"]]
    return summary
