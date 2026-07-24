"""Online floor-policy helpers shared across the reduce / auto-floor surfaces.

Low-level and dependency-light on purpose: top-level imports are ``numpy`` plus
the N<3 variance-reliability constant only. The data-driven floor math
(:func:`compute_phi0`) is imported *lazily* inside :func:`recommended_floor` to
break the ``auto_floor`` <-> ``floor_policy`` module-load cycle (the same idiom
used at ``auto_floor.py`` / ``candidate_stats.py``): ``auto_floor`` imports this
module at load time for :func:`window_variance` / :func:`enumerate_maximal`, so
this module must not import ``auto_floor`` at load time in return.

The variance floor only *orders* oracle tests, so every recommendation degrades
to latency, never a miss -- hence the never-miss ``0.0`` return on low-N or a
no-signal (no crypto component) sample.

``kneedle_descending`` / ``floor_ladder`` in :mod:`engine.candidate_stats`
remain the OFFLINE validators (ground-truth experiments) and are intentionally
NOT used here.
"""
from __future__ import annotations

from typing import List, Sequence, Tuple

import numpy as np

from memdiver.core.variance import STRUCTURAL_MAX
from memdiver.engine.candidate_grid import iter_region_grid
from memdiver.engine.candidate_pipeline import MIN_N_FOR_VARIANCE, reduce_search_space

# Below this max per-byte variance there is no high-entropy / crypto component
# to separate, so a floor would be meaningless -> recommend the never-miss 0.0.
# STRUCTURAL_MAX is the classifier's canonical structural ceiling (single source
# of truth in core.variance), so this gate can never drift from it.
_NO_SIGNAL_MAX_VARIANCE = STRUCTURAL_MAX


def window_variance(
    variance: np.ndarray,
    offsets: np.ndarray,
    sizes: np.ndarray,
) -> np.ndarray:
    """Mean per-byte variance over each ``[offset, offset + size)`` window.

    Lifted verbatim from the inline cumsum block that used to live in
    ``auto_floor._maximal_candidates``; used only to RANK candidates.
    """
    var = np.asarray(variance, dtype=np.float64)
    offsets = np.asarray(offsets, dtype=np.int64)
    sizes = np.asarray(sizes, dtype=np.int64)
    if offsets.size == 0:
        return np.empty(0, dtype=np.float64)
    cumvar = np.concatenate([[0.0], np.cumsum(var)])
    return (cumvar[offsets + sizes] - cumvar[offsets]) / sizes


def recommended_floor(wvar_or_variance: np.ndarray, num_dumps: int) -> float:
    """Advisory variance floor (``compute_phi0``-based) for reduce-only surfaces.

    Returns the never-miss ``0.0`` when the floor cannot be trusted:

    * ``num_dumps < MIN_N_FOR_VARIANCE`` (variance meaningless at N<3), or
    * no detectable crypto component (max positive variance below the
      structural ceiling -- nothing high-entropy to separate).

    Otherwise returns ``compute_phi0(...).phi0`` (already clamped to
    ``[0, DEFAULT_FLOOR]`` and CV-deflated by finite N). Accepts either the raw
    per-byte ``variance`` array or a precomputed ``wvar`` sample.
    """
    # Scalar low-N guard first: never touch (or copy) the array on this path.
    if num_dumps is None or num_dumps < MIN_N_FOR_VARIANCE:
        return 0.0
    sample = np.asarray(wvar_or_variance, dtype=np.float64)
    nz = sample[sample > 0.0]
    if nz.size == 0 or float(nz.max()) < _NO_SIGNAL_MAX_VARIANCE:
        return 0.0
    # Lazy import breaks the auto_floor <-> floor_policy module-load cycle.
    # compute_phi0 already clamps to [0, DEFAULT_FLOOR] and CV-deflates by N.
    from memdiver.engine.auto_floor import compute_phi0

    return float(compute_phi0(nz, num_dumps=num_dumps).phi0)


def enumerate_candidates(
    regions,
    dump_len: int,
    key_sizes: Sequence[int],
    stride: int,
) -> List[Tuple[int, int]]:
    """(offset, size) grid a search-reduce region set would feed the oracle.

    Shares the stride-snap grid math with engine.brute_force.iter_candidate_slices
    via engine.candidate_grid.iter_region_grid: snap the first offset up to a
    multiple of ``stride`` >= the region start, then step by ``stride``.
    """
    out: List[Tuple[int, int]] = []
    for r in regions:
        out.extend(iter_region_grid(r.offset, r.offset + r.length, key_sizes, stride, dump_len))
    return out


def enumerate_maximal(
    variance: np.ndarray,
    reference_data: bytes,
    num_dumps: int,
    reduce_kwargs: dict,
    key_sizes: Sequence[int],
    stride: int,
    *,
    min_variance: float = 0.0,
    compute_wvar: bool = True,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return ``(offsets, sizes, wvar)`` for the reduce-at-``min_variance`` grid.

    The single shared core that the auto-floor maximal-set enumerator, the
    pipeline escalation, and the reduce experiments all delegate to.
    ``min_variance=0.0`` yields the maximal (entropy+alignment-only) set. Pass
    ``compute_wvar=False`` when only the (offset,size) pairs are needed (e.g.
    the default-floor set used purely for membership): the returned ``wvar`` is
    then an empty array, skipping a full-length cumsum over the variance array.
    """
    rk = {**reduce_kwargs, "min_variance": min_variance}
    red = reduce_search_space(variance, reference_data, num_dumps, **rk)
    pairs = enumerate_candidates(red.regions, len(reference_data), key_sizes, stride)
    if not pairs:
        return (np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64),
                np.empty(0, dtype=np.float64))
    offsets = np.asarray([o for o, _ in pairs], dtype=np.int64)
    sizes = np.asarray([s for _, s in pairs], dtype=np.int64)
    wvar = window_variance(variance, offsets, sizes) if compute_wvar else np.empty(0, dtype=np.float64)
    return offsets, sizes, wvar
