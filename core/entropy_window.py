"""Fast sliding-window entropy primitives for the step-1 ``entropy_scan``.

Two complementary pieces, both W-wide instead of 256-bin-wide:

* :func:`sliding_entropy_estimate` -- every window's entropy to within
  :data:`ESTIMATE_TOLERANCE` in O(1) amortised work per window. The sum
  ``sum_v c_v * log2(c_v)`` is kept in *fixed-point integers*, so sliding the
  window by one byte (two bins change) is an exact integer delta and a plain
  ``cumsum`` never drifts. The two counts each delta needs (the outgoing
  byte's count in the old window, the incoming byte's count in the new one)
  come from ONE stable radix argsort by byte value per call.
* :func:`entropy_from_window_rows` -- the exact float of
  :func:`memdiver.core.entropy.entropy_from_freq_batch` for given windows.
  That function sums ``lut[count]`` left to right over bins 0..255; zero bins
  add an exact ``+0.0`` (every partial sum is ``+0.0`` or negative, never
  ``-0.0``), so the result equals the sequential sum of the NONZERO terms in
  ascending byte order -- exactly what sorting each row and summing one term
  per run of equal bytes produces, over W columns instead of 256.

Callers use the estimate to decide everything that is not close (threshold,
cluster maximum) and the exact function only for the few windows within the
tolerance; see :mod:`memdiver.algorithms.unknown_key.entropy_scan`.
"""

import math
from typing import Optional

import numpy as np

from memdiver.core.entropy import entropy_term_lut

#: Guaranteed bound on ``|estimate - entropy_from_freq_batch|`` (bits/byte).
#: The actual error is below ~1e-12 (fixed-point rounding <= 2**-41 plus a few
#: hundred float ulps of the reference); the margin is ~1000x.
ESTIMATE_TOLERANCE = 1e-9

#: Fractional bits of the fixed-point ``c * log2(c)`` table.
_MAX_FRACTION_BITS = 44
#: Fewer fractional bits than this would endanger :data:`ESTIMATE_TOLERANCE`.
_MIN_FRACTION_BITS = 40
#: Headroom below 2**63 for the running fixed-point sums.
_INT64_BITS = 62

# Slot columns per byte position in the combined radix sort (see below).
_QUERY_BEFORE_WINDOW_END = 0
_QUERY_BEFORE_WINDOW_START = 1
_ELEMENT = 2
_SLOTS = 3


def fixed_point_bits(window: int) -> Optional[int]:
    """Fractional bits for *window*, or ``None`` if int64 cannot hold them."""
    if window <= 0:
        return None
    magnitude = window * math.log2(window) + 1.0
    bits = min(_MAX_FRACTION_BITS, _INT64_BITS - math.ceil(math.log2(magnitude)))
    return bits if bits >= _MIN_FRACTION_BITS else None


def supports_estimate(window: int) -> bool:
    """Whether :func:`sliding_entropy_estimate` meets its tolerance for *window*."""
    return fixed_point_bits(window) is not None


def _fixed_point_table(window: int, bits: int) -> np.ndarray:
    """``round(c * log2(c) * 2**bits)`` for ``c`` in ``0..window`` (int64)."""
    scale = float(1 << bits)
    return np.array([0] + [round(c * math.log2(c) * scale) for c in range(1, window + 1)],
                    dtype=np.int64)


def sliding_entropy_estimate(values: np.ndarray, window: int) -> np.ndarray:
    """Entropy estimate of every *window*-byte window of the uint8 *values*.

    Returns ``len(values) - window + 1`` floats (empty when too short), each
    within :data:`ESTIMATE_TOLERANCE` of ``entropy_from_freq_batch`` on that
    window's histogram. Raises ``ValueError`` when :func:`supports_estimate`
    is false. Peak scratch is ~100 bytes per input byte.
    """
    values = np.ascontiguousarray(values, dtype=np.uint8)
    bits = fixed_point_bits(window)
    if bits is None:
        raise ValueError(f"window {window} too large for the fixed-point estimate")
    num_windows = values.shape[0] - window + 1
    if num_windows <= 0:
        return np.empty(0, dtype=np.float64)
    table = _fixed_point_table(window, bits)
    sums = np.empty(num_windows, dtype=np.int64)
    sums[0] = table[np.bincount(values[:window], minlength=256)].sum()
    if num_windows > 1:
        outgoing, incoming = _sliding_counts(values, window, num_windows - 1)
        increments = np.diff(table)  # increments[k - 1] = table[k] - table[k - 1]
        deltas = increments[incoming - 1]
        deltas -= increments[outgoing - 1]
        np.cumsum(deltas, out=deltas)
        np.add(deltas, sums[0], out=sums[1:])
    return math.log2(window) - sums * (1.0 / (window * float(1 << bits)))


def _sliding_counts(values: np.ndarray, window: int, steps: int):
    """Per slide ``i`` in ``[0, steps)``: the two counts its delta needs.

    ``outgoing[i]`` = occurrences of ``values[i]`` in ``[i, i + window)``;
    ``incoming[i]`` = occurrences of ``values[j]`` in ``(j - window, j]`` for
    ``j = i + window``. Both are "elements of my byte value before position
    y" differences: every position contributes an element slot and two query
    slots (``before i + window`` carrying ``values[i]``, ``before
    j - window + 1`` carrying ``values[j]``), query slots ordered before the
    element slot of the same position. After a stable radix argsort by byte
    value, the elements preceding a slot are a prefix count; the difference
    of two such counts within one value group is the wanted occurrence count.
    """
    length = values.shape[0]
    slots = np.zeros((length, _SLOTS), dtype=np.uint8)
    slots[:, _ELEMENT] = values
    # query "before position y" for window start i = y - window
    slots[window:window + steps, _QUERY_BEFORE_WINDOW_END] = values[:steps]
    # query "before position y" for window end j = y + window - 1
    slots[1:1 + steps, _QUERY_BEFORE_WINDOW_START] = values[window:window + steps]
    order = np.argsort(slots.ravel(), kind="stable")
    element_flags = np.zeros(order.shape[0], dtype=np.int64)
    element_flags[_ELEMENT::_SLOTS] = 1
    # Elements up to and including each sorted slot: for a query slot that
    # is "elements before it"; for an element slot, one more (itself).
    through = element_flags[order]
    np.cumsum(through, out=through)
    counts = np.empty(order.shape[0], dtype=np.int64)
    counts[order] = through
    counts = counts.reshape(length, _SLOTS)
    outgoing = (counts[window:window + steps, _QUERY_BEFORE_WINDOW_END] + 1
                - counts[:steps, _ELEMENT])
    incoming = (counts[window:window + steps, _ELEMENT]
                - counts[1:1 + steps, _QUERY_BEFORE_WINDOW_START])
    return outgoing, incoming


def entropy_from_window_rows(rows: np.ndarray, total: int) -> np.ndarray:
    """Exact ``entropy_from_freq_batch`` of each uint8 row's histogram.

    ``rows`` is ``(m, total)``. Each row is sorted; at the last byte of every
    run of equal values the term ``lut[run length]`` is placed (``+0.0``
    elsewhere), and the columns are accumulated sequentially -- the same
    nonzero terms in the same ascending byte order as the 256-bin reference,
    hence the same float, bit for bit.
    """
    rows = np.asarray(rows, dtype=np.uint8)
    count = rows.shape[0]
    if total == 0 or count == 0:
        return np.zeros(count, dtype=np.float64)
    ordered = np.sort(rows, axis=1)
    run_start = np.ones(ordered.shape, dtype=bool)
    run_start[:, 1:] = ordered[:, 1:] != ordered[:, :-1]
    run_end = np.ones(ordered.shape, dtype=bool)
    run_end[:, :-1] = run_start[:, 1:]
    column = np.arange(total, dtype=np.int64)
    start_column = np.maximum.accumulate(np.where(run_start, column, 0), axis=1)
    terms = np.where(run_end, entropy_term_lut(total)[column - start_column + 1], 0.0)
    columns = np.ascontiguousarray(terms.T)
    sums = columns[0].copy()
    for term in columns[1:]:  # sequential, like the reference's cumsum
        sums += term
    return -sums + 0.0
