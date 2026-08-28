"""Composable search-space reduction: variance → alignment → entropy.

Drives the ``memdiver search-reduce`` CLI. Loads a finalized consensus
state, extracts high-variance byte offsets, filters them through an
alignment grid, then narrows surviving regions by sliding-window Shannon
entropy. At N<3 dumps, variance is meaningless (Welford's population
variance at n=1 is zero everywhere), so the pipeline falls back to
entropy-only candidate generation and logs a warning.

All stages operate on length-``total_size`` numpy bool masks so a 210 MB
dump costs ~210 MB of transient memory (one bool per byte), not the
6 GB a Python ``Set[int]`` would take.

Every surviving region is then SCORED (:class:`CandidateScore`) so an
analyst who does not know where the key is gets the plausible candidates
first instead of whatever happens to sit at the lowest offset. The score is
a weighted sum of four normalized sub-scores and every one of them travels
on the row, so a rank can always be taken apart rather than trusted.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from memdiver.core.entropy import compute_entropy_profile, shannon_entropy
from memdiver.core.variance import (
    ByteClass,
    VarianceThresholds,
    class_mask,
    classify_variance,
    find_contiguous_runs,
    normalize_byte_classes,
)
from memdiver.engine.progress import (
    ProgressEvent,
    ProgressFn,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.candidate_pipeline")

MIN_N_FOR_VARIANCE = 3

# The historical raw-variance floor, kept as the default ONLY for callers that
# name no ``classes``. Note the value: it is exactly ``core.variance.POINTER_MAX``,
# i.e. the KEY_CANDIDATE lower bound -- so this floor and a class query are two
# spellings of the same cut, and leaving both active makes the class query a
# no-op. ``reduce_search_space`` resolves that; see its docstring.
DEFAULT_MIN_VARIANCE = 3000.0

# Default scan step of the block-density gate (``_aligned_mask``): the stride
# at which candidate blocks are tested for density, NOT the candidate
# enumeration grid (that is ``--stride``, see engine/candidate_grid.py). A byte
# is never discarded merely for being unaligned to it. Exported so any surface
# that reports the reduce envelope names the same number reduce actually ran
# with, instead of guessing a coincidental default.
DEFAULT_ALIGNMENT = 8


#: The two orderings :func:`reduce_search_space` can return its region list in.
ORDER_OFFSET = "offset"
ORDER_RANK = "rank"
ORDERS = (ORDER_OFFSET, ORDER_RANK)

#: Key-likeness weight of each ByteClass, indexed by its integer code. Evenly
#: spaced over [0, 1] so a region's composition mean is a plain average: an
#: INVARIANT byte contributes nothing, a KEY_CANDIDATE byte contributes fully.
CLASS_WEIGHTS = (0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0)

#: Variance of a uniformly-distributed byte, (256**2 - 1) / 12 = 5461.25. Key
#: material is indistinguishable from uniform random, so this — not the
#: arithmetic maximum 255**2 / 4 a two-valued byte reaches — is where the
#: variance sub-score saturates. A byte that only ever flips between 0x00 and
#: 0xff has three times this variance and is LESS key-like, not more.
UNIFORM_BYTE_VARIANCE = (256.0 ** 2 - 1.0) / 12.0

#: Plateau of byte lengths that plausibly hold key material — AES-128 at the
#: bottom, a TLS 1.2 48-byte master secret in the middle, a 512-bit key at the
#: top. Inside it the length sub-score is 1.0; below it it falls off linearly,
#: above it logarithmically (never to zero: a long run may still hold a key).
KEY_LENGTH_MIN = 16
KEY_LENGTH_MAX = 64

#: Weight of each :class:`CandidateScore` sub-score in the total. They sum to
#: 1.0, so ``CandidateRegion.score`` is itself in [0, 1]. The order of
#: importance is the differential workflow's own: what the classifier said
#: about the bytes first, then how hard they varied across dumps, then how
#: random they look, then whether they are the size of a key.
SCORE_WEIGHTS = {
    "byte_class": 0.30,
    "variance": 0.25,
    "entropy": 0.25,
    "length": 0.20,
}


@dataclass
class CandidateScore:
    """The four normalized sub-scores behind :attr:`CandidateRegion.score`.

    Each is in [0, 1] and each answers one question about the region:

    * ``byte_class`` — what the variance classifier made of its bytes, blended
      across the region's whole composition (:func:`_class_subscore`).
    * ``variance`` — how close its mean cross-dump variance comes to that of a
      uniformly random byte (:data:`UNIFORM_BYTE_VARIANCE`).
    * ``entropy`` — its own byte entropy against the most a region of that
      length could reach.
    * ``length`` — how plausible its length is for key material.

    :attr:`total` is ``sum(SCORE_WEIGHTS[k] * component[k])`` and nothing else,
    so a reader holding the row plus :data:`SCORE_WEIGHTS` (reported alongside
    it in ``ReductionResult.thresholds['score_weights']``) can recompute any
    rank by hand rather than taking a bare float on trust.
    """

    byte_class: float = 0.0
    variance: float = 0.0
    entropy: float = 0.0
    length: float = 0.0

    @property
    def total(self) -> float:
        return float(sum(SCORE_WEIGHTS[name] * float(getattr(self, name))
                         for name in SCORE_WEIGHTS))

    def to_dict(self) -> dict:
        return {name: float(getattr(self, name)) for name in SCORE_WEIGHTS}


@dataclass
class CandidateRegion:
    offset: int
    length: int
    mean_entropy: float
    mean_variance: float
    # Shannon entropy of the region's OWN bytes, in bits/byte. Deliberately
    # distinct from ``mean_entropy``, which averages fixed-width sliding
    # windows whose tails reach past the region: a 48-byte key sitting in
    # otherwise-zeroed heap reads low there and near-maximal here. Kept as a
    # raw value beside the normalized ``score_components.entropy`` it feeds.
    region_entropy: float = 0.0
    # Per-ByteClass byte counts inside the region, keyed by lower-cased class
    # name. Empty in the entropy-only fallback, where the pipeline has already
    # declared the variance unusable and refuses to classify against it.
    class_counts: Dict[str, int] = field(default_factory=dict)
    score: float = 0.0
    score_components: CandidateScore = field(default_factory=CandidateScore)
    # 1-based position in the score ranking, ties broken by offset. Always
    # stamped, whichever ``order`` the region list itself came back in.
    rank: int = 0

    def to_dict(self) -> dict:
        return {
            "offset": int(self.offset),
            "length": int(self.length),
            "mean_entropy": float(self.mean_entropy),
            "mean_variance": float(self.mean_variance),
            "region_entropy": float(self.region_entropy),
            "class_counts": dict(self.class_counts),
            "rank": int(self.rank),
            "score": float(self.score),
            "score_components": self.score_components.to_dict(),
        }


@dataclass
class StageCounts:
    total_bytes: int = 0
    variance: int = 0
    # Survivors of the optional ByteClass filter. With no ``classes`` query
    # the stage is a pass-through and mirrors ``variance``, so the funnel
    # still reads top-to-bottom without a hole in it.
    byte_class: int = 0
    aligned: int = 0
    high_entropy: int = 0

    def to_dict(self) -> dict:
        return {
            "total_bytes": self.total_bytes,
            "variance": self.variance,
            "byte_class": self.byte_class,
            "aligned": self.aligned,
            "high_entropy": self.high_entropy,
        }


@dataclass
class ReductionResult:
    regions: List[CandidateRegion] = field(default_factory=list)
    stages: StageCounts = field(default_factory=StageCounts)
    thresholds: dict = field(default_factory=dict)
    num_dumps: int = 0

    @property
    def fallback_entropy_only(self) -> bool:
        return self.num_dumps < MIN_N_FOR_VARIANCE

    def to_dict(self) -> dict:
        return {
            "N": self.num_dumps,
            "stages": self.stages.to_dict(),
            "thresholds": dict(self.thresholds),
            "fallback_entropy_only": self.fallback_entropy_only,
            "regions": [r.to_dict() for r in self.regions],
        }


def _variance_mask(variance: np.ndarray, min_variance: float) -> np.ndarray:
    """Purely threshold-based candidate mask.

    The global KEY_CANDIDATE enum threshold (3000) is a reasonable
    default for synthetic data, but real crypto keys on real datasets
    have per-byte variance that swings widely across runs — sometimes
    dipping to ~2000 even for bytes that DO change every run. We let
    ``--min-variance`` be the single tunable cutoff so the caller can
    match observed variance distributions without recompiling the enum.
    """
    return variance >= min_variance


def _aligned_mask(
    candidate_mask: np.ndarray,
    block_size: int,
    alignment: int,
    density_threshold: float,
) -> np.ndarray:
    """Vectorized alignment filter over a bool mask.

    Byte ``i`` survives iff it's a candidate AND is inside at least one
    ``alignment``-aligned, ``block_size``-wide block whose candidate
    density ≥ ``density_threshold``.
    """
    total = len(candidate_mask)
    if total < block_size or not candidate_mask.any():
        return np.zeros(total, dtype=bool)
    cum = np.concatenate([[0], np.cumsum(candidate_mask.astype(np.int32))])
    starts = np.arange(0, total - block_size + 1, alignment, dtype=np.int64)
    counts = cum[starts + block_size] - cum[starts]
    min_count = int(block_size * density_threshold)
    kept_starts = starts[counts >= min_count]
    if kept_starts.size == 0:
        return np.zeros(total, dtype=bool)
    events = np.zeros(total + 1, dtype=np.int32)
    np.add.at(events, kept_starts, 1)
    np.add.at(events, np.minimum(kept_starts + block_size, total), -1)
    in_kept_block = np.cumsum(events)[:total] > 0
    return candidate_mask & in_kept_block


def _entropy_profile_array(
    reference_data: bytes,
    window: int,
    step: int,
) -> np.ndarray:
    """Sliding-window entropy sampled every ``step`` bytes as a float32 array.

    Element ``k`` is the entropy of the window starting at ``k*step``.
    """
    profile = compute_entropy_profile(reference_data, window=window, step=step)
    return np.fromiter((e for _, e in profile), dtype=np.float32, count=len(profile))


def _entropy_coverage_mask(
    profile_arr: np.ndarray,
    total_size: int,
    window: int,
    step: int,
    threshold: float,
) -> np.ndarray:
    """Bool mask marking every byte covered by a high-entropy window."""
    mask = np.zeros(total_size, dtype=bool)
    if profile_arr.size == 0:
        return mask
    high_windows = np.flatnonzero(profile_arr >= threshold)
    if high_windows.size == 0:
        return mask
    events = np.zeros(total_size + 1, dtype=np.int32)
    starts = high_windows.astype(np.int64) * step
    ends = np.minimum(starts + window, total_size)
    np.add.at(events, starts, 1)
    np.add.at(events, ends, -1)
    return np.cumsum(events)[:total_size] > 0


def _runs_from_mask(mask: np.ndarray) -> List[tuple[int, int]]:
    """Contiguous (start, end) runs of True values in a bool mask."""
    return find_contiguous_runs(mask.astype(np.uint8), 1)


def _region_mean_entropy(
    start: int,
    end: int,
    profile_arr: np.ndarray,
    step: int,
    window: int,
    reference_data: bytes,
) -> float:
    """Mean entropy over window samples whose start offset falls in [start, end)."""
    lo_k = (start + step - 1) // step
    hi_k = end // step
    lo_k = max(0, lo_k)
    hi_k = min(int(profile_arr.size), hi_k)
    if hi_k > lo_k:
        return float(profile_arr[lo_k:hi_k].mean())
    # Region shorter than one window sample — fall back to direct entropy.
    return float(shannon_entropy(reference_data[start:end]))


def _one_byte_class(value: object) -> ByteClass:
    """Coerce a single class token — name, integer code or enum — to ByteClass."""
    if isinstance(value, int):
        return ByteClass(int(value))
    name = str(value).strip().lower()
    try:
        return ByteClass[name.upper()]
    except KeyError:
        raise ValueError(
            f"unknown byte class {value!r}; expected one of "
            + ", ".join(c.name.lower() for c in ByteClass)
        ) from None


def resolve_byte_classes(spec: object) -> Tuple[ByteClass, ...]:
    """Coerce a surface-level class query into a ByteClass tuple.

    ``core.variance.normalize_byte_classes`` already accepts enums and integer
    codes; the surfaces speak NAMES ("key_candidate"), because that is what
    ``ReductionResult.thresholds['classes']`` reports back and therefore what
    round-trips through JSON, a CLI flag and an MCP argument. This is the one
    place that translation lives, so the CLI, the MCP tool and the library API
    reject the same typos with the same message.
    """
    if isinstance(spec, (str, int)):
        items: List[object] = [spec]
    else:
        items = list(spec)  # type: ignore[call-overload]
    if not items:
        raise ValueError("at least one ByteClass is required")
    return normalize_byte_classes([_one_byte_class(v) for v in items])


def _class_counts(
    variance_slice: np.ndarray,
    thresholds: Optional[VarianceThresholds],
) -> Dict[str, int]:
    """Per-ByteClass byte counts for one region, keyed by lower-cased name.

    Classified per region rather than once over the whole array: the surviving
    regions are a few kilobytes even on a multi-GB dump, whereas classifying
    the full variance vector would allocate several dump-sized temporaries for
    a number only the kept regions ever need.
    """
    codes = classify_variance(variance_slice, thresholds)
    counts = np.bincount(codes, minlength=len(ByteClass))
    return {c.name.lower(): int(counts[int(c)]) for c in ByteClass}


def _class_subscore(class_counts: Dict[str, int]) -> float:
    """Blend a region's MEAN class weight with its PEAK class weight.

    Real key material is class-MIXED: measured on the reference corpus, the
    48-byte TLS 1.2 master secret classifies as 22 KEY_CANDIDATE + 18 POINTER
    + 8 STRUCTURAL bytes. Scoring on the dominant class alone would bury it
    under any shorter uniformly-KEY_CANDIDATE run; scoring on the mean alone
    would punish it for the pointer-ish bytes that are part of what a live key
    in a heap actually looks like. Half of each keeps a mixed region
    competitive without letting a run that is merely STRUCTURAL throughout —
    peak and mean both low — climb past one that touches KEY_CANDIDATE.
    """
    total = sum(class_counts.values())
    if total <= 0:
        return 0.0
    weights = {c.name.lower(): CLASS_WEIGHTS[int(c)] for c in ByteClass}
    mean = sum(weights[name] * n for name, n in class_counts.items()) / total
    peak = max((weights[name] for name, n in class_counts.items() if n),
               default=0.0)
    return 0.5 * mean + 0.5 * peak


def _entropy_subscore(region_entropy: float, length: int) -> float:
    """Region entropy against the most a region of that length could reach.

    A 16-byte region can never exceed log2(16) = 4 bits/byte however random it
    is, so normalizing by a flat 8 would rank every short region below every
    long one — the opposite of what key material needs.
    """
    ceiling = math.log2(min(length, 256)) if length > 1 else 0.0
    if ceiling <= 0.0:
        return 0.0
    return min(1.0, max(0.0, region_entropy) / ceiling)


def _length_subscore(length: int) -> float:
    """Plausibility of ``length`` as a key length; see KEY_LENGTH_MIN/MAX.

    Explicitly NOT monotonic in length: a 4 KB run is far more likely to be a
    buffer than a key, and the 48-byte master secret this pipeline exists to
    find must not lose to it on size alone. The long tail decays with log2 and
    never reaches zero, so a long region is demoted, never excluded.
    """
    if length <= 0:
        return 0.0
    if length < KEY_LENGTH_MIN:
        return length / KEY_LENGTH_MIN
    if length <= KEY_LENGTH_MAX:
        return 1.0
    return 1.0 / (1.0 + math.log2(length / KEY_LENGTH_MAX))


def _score_region(
    length: int,
    mean_variance: float,
    region_entropy: float,
    class_counts: Dict[str, int],
) -> CandidateScore:
    """Build the four sub-scores of one region. See :class:`CandidateScore`."""
    return CandidateScore(
        byte_class=_class_subscore(class_counts),
        variance=min(1.0, max(0.0, mean_variance) / UNIFORM_BYTE_VARIANCE),
        entropy=_entropy_subscore(region_entropy, length),
        length=_length_subscore(length),
    )


def _rank_regions(
    regions: List[CandidateRegion], order: str
) -> List[CandidateRegion]:
    """Stamp a 1-based ``rank`` on every region and return the requested order.

    The sort key is ``(-score, offset)`` and offsets are unique within one
    reduction, so the ranking is TOTAL: two runs over the same input produce
    the same order whatever the sort internals do with equal scores.

    ``regions`` arrives in ascending-offset order straight from
    ``_runs_from_mask``, so ``order="offset"`` returns it untouched — the
    pre-ranking output, byte for byte.
    """
    ranked = sorted(regions, key=lambda r: (-r.score, r.offset))
    for position, region in enumerate(ranked, start=1):
        region.rank = position
    return ranked if order == ORDER_RANK else regions


def reduce_search_space(
    variance: np.ndarray,
    reference_data: bytes,
    num_dumps: int,
    *,
    alignment: int = DEFAULT_ALIGNMENT,
    block_size: int = 32,
    density_threshold: float = 0.5,
    min_variance: Optional[float] = None,
    classes: Optional[Sequence[ByteClass]] = None,
    class_thresholds: Optional[VarianceThresholds] = None,
    entropy_window: int = 32,
    entropy_threshold: float = 4.5,
    min_region: int = 16,
    max_region: int = 0,
    order: str = ORDER_OFFSET,
    entropy_cache: dict | None = None,
    progress_callback: ProgressFn = noop_progress,
) -> ReductionResult:
    """Run the consensus → alignment → entropy reduction chain.

    All stages use numpy bool masks so memory stays O(total_size) instead
    of O(total_size × int64) a set would require.

    ``entropy_cache`` is an OPT-IN, caller-owned scratch dict for the sliding-
    window entropy profile. The profile depends only on ``reference_data``,
    ``entropy_window`` and ``alignment`` — never on ``min_variance`` — so a
    caller that reduces the SAME buffer at two different floors (see
    ``auto_floor._maximal_candidates``, which must run both passes for
    density-gate parity) can hand the same dict to both calls and pay for the
    profile once. Measured at 700k candidates: ~80-120 ms of the ~350-500 ms
    enumeration budget, halved. Output is byte-identical either way; omitting
    the argument keeps the previous compute-every-time behaviour.

    The cache key includes ``id(reference_data)``, so it can only ever hit for
    the very buffer it was filled from — the caller holds that buffer alive
    across both calls, which makes an id reuse impossible.

    ``classes`` is an ADDITIONAL gate, never a replacement for ``min_variance``:
    a byte must clear the raw float floor AND fall in one of the requested
    ``ByteClass`` bands. The two answer different questions — ``min_variance``
    is the tunable observed-distribution cutoff described in ``_variance_mask``,
    ``classes`` is the band vocabulary the analyst filters by — so a caller can
    ask for "KEY_CANDIDATE bytes, but only above 5000".
    ``class_thresholds`` overrides the band boundaries the query is resolved
    against; ``None`` uses the module defaults.

    ``min_variance=None`` RESOLVES against ``classes``, and this is the one
    piece of cleverness in the signature, so here is why it earns its place.
    The historical default of 3000.0 is exactly ``POINTER_MAX`` — the
    KEY_CANDIDATE lower bound. Left standing while ``classes`` widened the
    query, it silently re-imposed the very floor the class filter was opening
    up: asking for ``[STRUCTURAL, POINTER, KEY_CANDIDATE]`` returned
    KEY_CANDIDATE bytes only, and the filter looked broken for a reason nothing
    reported. Measured on a real 8-dump corpus, that is the difference between
    surfacing a 48-byte TLS secret as one clean region and losing it entirely,
    because real key material is class-MIXED (22 KEY_CANDIDATE + 18 POINTER +
    8 STRUCTURAL) and its KEY_CANDIDATE run is only 3 bytes long.

    So: ``None`` means 3000.0 when no classes are named (every existing caller
    is byte-identical), and 0.0 when they are — the class mask is then the
    authoritative variance gate and a second, contradictory band would only
    fight it. An explicit float always wins, so "KEY_CANDIDATE above 5000"
    stays expressible. The resolved value is echoed in ``thresholds`` rather
    than the sentinel, so a reader of the JSON sees the floor actually applied.

    ``max_region`` drops regions LONGER than the bound (0 = unbounded), the
    mirror of ``min_region``. Regions are dropped, never truncated: a 4 KB run
    is not four 1 KB keys.

    ``order`` selects the ORDER of the returned list — ``"offset"`` (ascending
    offset) or ``"rank"`` (best score first). It defaults to ``"offset"``
    because ``candidates.json`` is an INPUT to ``brute_force``, which walks it
    in list order: reordering it for callers who never asked would reorder
    hits, ``top_k`` and every pinned artifact downstream. Ranking is never
    withheld to pay for that, though — ``rank``, ``score`` and
    ``score_components`` are stamped on every row in BOTH orders, so an
    offset-ordered consumer sorts client-side and loses nothing.
    """
    if order not in ORDERS:
        raise ValueError(
            f"order={order!r} is not one of {ORDERS}"
        )
    if entropy_threshold > math.log2(entropy_window):
        raise ValueError(
            f"entropy_threshold={entropy_threshold} exceeds log2(window)"
            f"={math.log2(entropy_window):.2f}; pick a smaller threshold "
            f"or a larger window"
        )

    variance = np.asarray(variance)
    total_size = int(variance.size) if variance.size > 0 else len(reference_data)
    if variance.size > 0 and len(reference_data) < total_size:
        raise ValueError(
            f"reference dump shorter than variance array "
            f"({len(reference_data)} < {total_size})"
        )

    stages = StageCounts(total_bytes=total_size)
    # See the docstring: the historical 3000.0 default IS the KEY_CANDIDATE
    # lower bound, so leaving it standing under an explicit class query would
    # silently undo that query. Resolve it here, once, and publish the resolved
    # value rather than the sentinel.
    if min_variance is None:
        min_variance = 0.0 if classes else DEFAULT_MIN_VARIANCE
    thresholds = {
        "alignment": alignment,
        "block_size": block_size,
        "density_threshold": density_threshold,
        "min_variance": min_variance,
        "entropy_window": entropy_window,
        "entropy_threshold": entropy_threshold,
        "min_region": min_region,
        "max_region": max_region,
        "order": order,
        # Reported so a consumer can recompute any ``score`` from the
        # ``score_components`` on the row without importing this module.
        "score_weights": dict(SCORE_WEIGHTS),
        "classes": (
            [ByteClass(int(c)).name.lower() for c in normalize_byte_classes(classes)]
            if classes else None
        ),
    }

    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:start",
            pct=0.0,
            msg=f"total={total_size}",
            extra={"total_bytes": total_size, "num_dumps": num_dumps},
        ),
    )

    fallback = num_dumps < MIN_N_FOR_VARIANCE
    if fallback:
        logger.warning(
            "N=%d < %d; variance is unreliable, falling back to entropy-only",
            num_dumps, MIN_N_FOR_VARIANCE,
        )
        variance_mask = np.ones(total_size, dtype=bool)
    else:
        variance_mask = _variance_mask(variance, min_variance)
    stages.variance = int(variance_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:variance",
            pct=0.25,
            msg=f"variance survivors={stages.variance}",
            extra={"survivor_bytes": stages.variance, "input_bytes": total_size},
        ),
    )

    # Class gate. Skipped in the fallback for the same reason the variance
    # gate is: at N < MIN_N_FOR_VARIANCE every byte classifies INVARIANT, so
    # any class query would empty the result rather than narrow it.
    if fallback or not classes:
        class_mask_survivors = variance_mask
    else:
        wanted = normalize_byte_classes(classes)
        class_mask_survivors = variance_mask & class_mask(
            classify_variance(variance, class_thresholds), wanted
        )
        safe_emit(
            progress_callback,
            ProgressEvent(
                stage="search_reduce:class",
                pct=0.35,
                msg=f"class survivors={int(class_mask_survivors.sum())}",
                extra={"survivor_bytes": int(class_mask_survivors.sum()),
                       "input_bytes": stages.variance},
            ),
        )
    stages.byte_class = int(class_mask_survivors.sum())

    if fallback:
        aligned_mask = class_mask_survivors
    else:
        aligned_mask = _aligned_mask(
            class_mask_survivors, block_size, alignment, density_threshold
        )
    stages.aligned = int(aligned_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:aligned",
            pct=0.5,
            msg=f"aligned survivors={stages.aligned}",
            extra={"survivor_bytes": stages.aligned,
                   "input_bytes": stages.byte_class},
        ),
    )

    entropy_step = alignment
    cache_key = (id(reference_data), total_size, entropy_window, entropy_step)
    if entropy_cache is not None and entropy_cache.get("key") == cache_key:
        profile_arr = entropy_cache["profile"]
    else:
        profile_arr = _entropy_profile_array(
            reference_data[:total_size], entropy_window, entropy_step
        )
        if entropy_cache is not None:
            entropy_cache["key"] = cache_key
            entropy_cache["profile"] = profile_arr
    entropy_mask = _entropy_coverage_mask(
        profile_arr, total_size, entropy_window, entropy_step, entropy_threshold
    )
    surviving_mask = aligned_mask & entropy_mask
    stages.high_entropy = int(surviving_mask.sum())
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:entropy",
            pct=0.75,
            msg=f"high-entropy survivors={stages.high_entropy}",
            extra={"survivor_bytes": stages.high_entropy, "input_bytes": stages.aligned},
        ),
    )

    regions: List[CandidateRegion] = []
    for start, end in _runs_from_mask(surviving_mask):
        if end - start < min_region:
            continue
        if max_region and end - start > max_region:
            continue
        mean_entropy = _region_mean_entropy(
            start, end, profile_arr, entropy_step, entropy_window, reference_data
        )
        has_variance = not fallback and variance.size >= end
        mean_variance = (
            float(variance[start:end].mean()) if variance.size >= end else 0.0
        )
        region_entropy = float(shannon_entropy(reference_data[start:end]))
        # No class counts in the fallback: the pipeline has already declared
        # the variance unusable at this N, so reporting "invariant everywhere"
        # would be a classification it does not stand behind.
        class_counts = (
            _class_counts(variance[start:end], class_thresholds)
            if has_variance else {}
        )
        components = _score_region(
            end - start, mean_variance, region_entropy, class_counts
        )
        regions.append(
            CandidateRegion(
                offset=int(start),
                length=int(end - start),
                mean_entropy=mean_entropy,
                mean_variance=mean_variance,
                region_entropy=region_entropy,
                class_counts=class_counts,
                score=components.total,
                score_components=components,
            )
        )
    regions = _rank_regions(regions, order)

    result = ReductionResult(
        regions=regions,
        stages=stages,
        thresholds=thresholds,
        num_dumps=num_dumps,
    )
    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="search_reduce:regions",
            pct=1.0,
            msg=f"{len(regions)} regions",
            extra={"num_regions": len(regions)},
        ),
    )
    return result
