"""Response pieces of the entropy producer (``tools_inspect.entropy_result``).

Kept out of ``tools_inspect`` so the producer stays a thin orchestration:
threshold resolution (window-aware default, reachability warning), the
region-width rule, the two profiling paths (sampled / full resolution) and
their JSON shapes. Every field added here is ADDITIVE to the historical
response (``overall_entropy``, ``high_entropy_regions``, ``profile_sample``,
``stats``, ``step``, ``window``, ``view``), whose meaning is unchanged.
"""

from typing import Callable, Dict, List, Literal, Optional, Sequence, Tuple

import numpy as np

from memdiver.core.entropy import (
    STREAM_SLAB_BYTES,
    default_entropy_threshold,
    find_high_entropy_regions,
    max_window_entropy,
    threshold_is_reachable,
)
from memdiver.core.entropy_overview import (
    EntropyEnvelope,
    EntropyOverview,
    clamp_buckets,
    envelope_from_profile,
    merge_close_runs,
    stream_entropy_overview,
)
from memdiver.core.entropy_profile import EntropyProfile

Resolution = Literal["auto", "sampled", "full"]
RESOLUTIONS = ("auto", "sampled", "full")

#: ``resolution="auto"`` profiles inputs up to this size at full resolution
#: (step 1) in the first response (~0.3-0.6 s); larger ones get the sampled
#: profile and ``full_resolution_available`` so a client can follow up.
FULL_RESOLUTION_AUTO_BYTES = STREAM_SLAB_BYTES

#: A region must cover at least this many bytes (one AES-256 key). Every
#: window that reaches the threshold already covers ``window`` bytes, so at
#: the default 32-byte window a single qualifying window is a region.
MIN_REGION_BYTES = 32

#: At most this many regions are listed (``region_count`` has the total).
MAX_ENTROPY_REGIONS = 2000

#: Point samples in ``profile_sample`` (the historical response size).
MAX_ENTROPY_SAMPLES = 200

ReadFn = Callable[[int, int], bytes]


def resolve_threshold(window: int, threshold: Optional[float]) -> Dict[str, object]:
    """The threshold to use plus the fields that explain it.

    ``None`` -> :func:`default_entropy_threshold` (window-aware). An explicit
    value is used AS GIVEN, even when no window can reach it; the response
    then says so (``threshold_reachable: false`` + a ``threshold_unreachable``
    warning code) instead of silently reporting no regions.
    """
    source = "default" if threshold is None else "explicit"
    value = default_entropy_threshold(window) if threshold is None else float(threshold)
    reachable = threshold_is_reachable(value, window)
    return {
        "threshold": value,
        "threshold_source": source,
        "max_entropy": max_window_entropy(window),
        "threshold_reachable": reachable,
        "warnings": [] if reachable else ["threshold_unreachable"],
    }


def region_min_span(window: int, step: int) -> int:
    """``find_high_entropy_regions`` ``min_width`` (window-start span) for
    regions covering at least :data:`MIN_REGION_BYTES` bytes.

    A run of ``r`` points ``step`` apart spans ``r * step`` starts and covers
    ``(r - 1) * step + window`` bytes, so ``covered >= M`` iff
    ``span >= M - window + step``.
    """
    return max(0, MIN_REGION_BYTES - window + step)


def region_join_gap(window: int, step: int) -> int:
    """Runs closer than this (in window starts) are one region: their windows'
    covered bytes overlap (see :func:`merge_close_runs`)."""
    return window - step


def profile_regions(profile: EntropyProfile, threshold: float, window: int,
                    step: int) -> List[Tuple[int, int, float]]:
    """Regions of a step-*step* profile under the same rules as the full path:
    runs of windows >= threshold, byte-overlapping runs joined, >= 32 bytes."""
    runs = find_high_entropy_regions(profile, threshold=threshold, min_width=0)
    if not runs:
        return []
    starts, stops, means = (np.array(column) for column in zip(*runs))
    counts = ((stops - starts) // max(step, 1)).astype(np.float64)
    return merge_close_runs(starts, stops, means * counts, counts,
                            region_join_gap(window, step), region_min_span(window, step))


def sample_indices(count: int, samples: int = MAX_ENTROPY_SAMPLES) -> np.ndarray:
    """Evenly spread indices into ``range(count)``, first and last included."""
    if count <= samples:
        return np.arange(count, dtype=np.int64)
    return (np.arange(samples, dtype=np.int64) * (count - 1)) // (samples - 1)


def envelope_payload(envelope: EntropyEnvelope) -> Dict[str, List]:
    """Column-oriented JSON of an envelope (compact for ~2000 buckets)."""
    return {
        "starts": envelope.starts.tolist(),
        "stops": envelope.stops.tolist(),
        "min": np.round(envelope.minimum, 4).tolist(),
        "max": np.round(envelope.maximum, 4).tolist(),
        "mean": np.round(envelope.mean, 4).tolist(),
    }


def _regions_payload(regions: Sequence[Tuple[int, int, float]], window: int,
                     step: int) -> Dict:
    listed = regions[:MAX_ENTROPY_REGIONS]
    return {
        "high_entropy_regions": [
            # `end` keeps its historical meaning (exclusive, in window-start
            # space: last start + step); `byte_end` is the exclusive end of the
            # bytes the region's windows cover (last start + window).
            {"start": s, "end": e, "mean_entropy": round(m, 4),
             "byte_end": e - step + window}
            for s, e, m in listed
        ],
        "region_count": len(regions),
        "regions_truncated": len(regions) > len(listed),
        "min_region_bytes": MIN_REGION_BYTES,
    }


def _stats(minimum: float, maximum: float, mean: float) -> Dict[str, float]:
    return {"min": round(minimum, 4), "max": round(maximum, 4), "mean": round(mean, 4)}


def sampled_payload(overall: float, profile: EntropyProfile, data_len: int,
                    window: int, step: int, threshold: float,
                    buckets: Optional[int]) -> Dict:
    """Response of the sampled (``step >= 1``) profile -- the historical path."""
    regions = profile_regions(profile, threshold, window, step)
    offsets, values = profile.as_arrays()
    picks = sample_indices(offsets.shape[0])
    entropies = values.tolist() if offsets.shape[0] else [0.0]
    payload = {
        "overall_entropy": round(overall, 4),
        **_regions_payload(regions, window, step),
        "profile_sample": [{"offset": o, "entropy": round(e, 4)}
                           for o, e in zip(offsets[picks].tolist(), values[picks].tolist())],
        "stats": _stats(min(entropies), max(entropies), sum(entropies) / len(entropies)),
        "envelope": envelope_payload(envelope_from_profile(
            profile, max(0, data_len - window + 1), clamp_buckets(buckets))),
        "resolution": "sampled",
    }
    return payload


def full_payload(overview: EntropyOverview) -> Dict:
    """Response of the full-resolution (step-1) overview."""
    return {
        "overall_entropy": round(overview.overall_entropy, 4),
        **_regions_payload(overview.regions, overview.window, 1),
        "profile_sample": [
            {"offset": o, "entropy": round(e, 4)}
            for o, e in zip(overview.sample_offsets.tolist(), overview.sample_values.tolist())
        ],
        "stats": _stats(overview.minimum, overview.maximum, overview.mean)
        if overview.positions else _stats(0.0, 0.0, 0.0),
        "envelope": envelope_payload(overview.envelope),
        "resolution": "full",
        "step": 1,
    }


def compute_full_payload(read: ReadFn, data_len: int, window: int, threshold: float,
                         buckets: Optional[int]) -> Dict:
    """Stream the whole range once at step 1 (see ``core.entropy_overview``)."""
    positions = max(0, data_len - window + 1)
    overview = stream_entropy_overview(
        read, data_len, window, threshold,
        min_width=region_min_span(window, 1), buckets=clamp_buckets(buckets),
        sample_positions=sample_indices(positions), join_gap=region_join_gap(window, 1))
    return full_payload(overview)


def wants_full_resolution(resolution: str, data_len: int) -> bool:
    """Whether to run the step-1 pass for this request."""
    if resolution == "full":
        return True
    return resolution == "auto" and data_len <= FULL_RESOLUTION_AUTO_BYTES
