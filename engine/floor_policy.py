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

import itertools
from typing import Iterator, List, Sequence, Tuple

import numpy as np

from memdiver.core.variance import STRUCTURAL_MAX
from memdiver.engine.candidate_grid import count_region_grid, iter_region_grid
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


def iter_candidates(
    regions,
    dump_len: int,
    key_sizes: Sequence[int],
    stride: int,
) -> Iterator[Tuple[int, int]]:
    """Streaming sibling of :func:`enumerate_candidates` -- same pairs, no list.

    At stride=1 a realistic slab reaches ~700k candidates, and materialising
    them as a ``List[Tuple[int, int]]`` costs ~230 MB of RSS and a few hundred
    ms (measured: ``tools/bench_auto_floor_memory.py``). Consumers that only
    need to *fill an array* iterate this instead and pre-size with
    :func:`count_candidates`, the same pre-count trick
    ``engine.brute_force.count_candidate_slices`` uses.

    :func:`enumerate_candidates` is KEPT as the eager list form (it is the
    documented helper re-exported as ``auto_floor._enumerate_candidates``) and
    now delegates here, so the two can never drift.
    """
    for r in regions:
        yield from iter_region_grid(
            r.offset, r.offset + r.length, key_sizes, stride, dump_len)


def count_candidates(
    regions,
    dump_len: int,
    key_sizes: Sequence[int],
    stride: int,
) -> int:
    """Closed-form count of what :func:`iter_candidates` will yield.

    O(len(regions) * len(key_sizes)) via
    :func:`engine.candidate_grid.count_region_grid`, whose equivalence to
    ``iter_region_grid`` is pinned by a test -- so this can pre-size an array
    without walking a 700k-element grid first.
    """
    return sum(
        count_region_grid(r.offset, r.offset + r.length, key_sizes, stride, dump_len)
        for r in regions
    )


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
    return list(iter_candidates(regions, dump_len, key_sizes, stride))


class PairMembership:
    """Memory-lean ``(offset, size) in ...`` test over a candidate grid.

    Drop-in for the ``set`` of ``(offset, size)`` tuples ``auto_floor`` used to
    build for the default-floor candidate set: same ``in`` / ``len()`` /
    iteration semantics, ~16x less memory (measured at 700k pairs: ~90 MB of
    Python tuples/ints vs one sorted 5.6 MB int64 array).

    Pairs are encoded losslessly as ``offset * (max_size + 1) + size``, which is
    injective for ``0 <= size <= max_size`` -- so membership answers are
    BIT-IDENTICAL to the set's, not approximate. Nothing is hashed and nothing
    is bounded: a false negative here would silently downgrade a RECOVERED
    verdict to FLOOR_WAS_TOO_HIGH.
    """

    __slots__ = ("_keys", "_scale")

    def __init__(self, offsets: np.ndarray, sizes: np.ndarray) -> None:
        offsets = np.asarray(offsets, dtype=np.int64)
        sizes = np.asarray(sizes, dtype=np.int64)
        self._scale = int(sizes.max()) + 1 if sizes.size else 1
        self._keys = np.sort(offsets * self._scale + sizes)

    def __contains__(self, pair) -> bool:
        # Anything that is not a pair of integers is simply absent -- the same
        # answer a ``set`` of (offset, size) tuples would give.
        try:
            offset, size = pair
            offset, size = int(offset), int(size)
        except (TypeError, ValueError):
            return False
        if self._keys.size == 0 or not (0 <= size < self._scale):
            return False
        key = offset * self._scale + size
        idx = int(np.searchsorted(self._keys, key))
        return idx < self._keys.size and int(self._keys[idx]) == key

    def __len__(self) -> int:
        return int(self._keys.size)

    def __iter__(self) -> Iterator[Tuple[int, int]]:
        for key in self._keys.tolist():
            yield key // self._scale, key % self._scale


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
    dump_len = len(reference_data)
    # STREAMED, not materialised: pre-count with the closed form, then fill one
    # flat int64 buffer straight from the generator. The eager
    # ``enumerate_candidates`` + two list comprehensions this replaces built
    # ~700k Python tuples (~230 MB, measured) purely to throw them away one
    # line later; ``np.fromiter(count=...)`` preallocates exactly once.
    n = count_candidates(red.regions, dump_len, key_sizes, stride)
    if n == 0:
        return (np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64),
                np.empty(0, dtype=np.float64))
    flat = np.fromiter(
        itertools.chain.from_iterable(
            iter_candidates(red.regions, dump_len, key_sizes, stride)),
        dtype=np.int64, count=2 * n,
    )
    # ascontiguousarray copies the strided even/odd views into their own
    # buffers so ``flat`` (2x their combined size) can be released right away.
    offsets = np.ascontiguousarray(flat[0::2])
    sizes = np.ascontiguousarray(flat[1::2])
    del flat
    wvar = window_variance(variance, offsets, sizes) if compute_wvar else np.empty(0, dtype=np.float64)
    return offsets, sizes, wvar
