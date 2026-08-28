"""Per-byte variance computation and classification.

Shared by ConsensusVector (engine) and DifferentialAlgorithm (algorithms).
Uses numpy for vectorized computation (10-30x faster than pure Python loops).
"""

import array
from enum import IntEnum
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple, Union

import logging

import numpy as np

logger = logging.getLogger("memdiver.core.variance")


class ByteClass(IntEnum):
    """Byte-position classification based on cross-run variance."""
    INVARIANT = 0
    STRUCTURAL = 1
    POINTER = 2
    KEY_CANDIDATE = 3


# Single source of truth for variance thresholds
INVARIANT_MAX = 0.0
STRUCTURAL_MAX = 200.0
POINTER_MAX = 3000.0


class VarianceThresholds(NamedTuple):
    """The three boundaries separating the four :class:`ByteClass` bands.

    A byte is INVARIANT at ``variance <= invariant_max``, STRUCTURAL up to
    ``structural_max``, POINTER up to ``pointer_max`` and KEY_CANDIDATE above
    it. The defaults are the module constants, so an omitted / ``None``
    threshold set reproduces the historical hard-coded boundaries exactly.

    There is no config-file path into this layer today (``core.config_schema``
    only covers dataset/logging/analysis/ui and is read solely by ``ui.state``),
    so overrides travel as an explicit argument from the caller.
    """

    invariant_max: float = INVARIANT_MAX
    structural_max: float = STRUCTURAL_MAX
    pointer_max: float = POINTER_MAX

    def validate(self) -> "VarianceThresholds":
        """Return self after checking the bands are non-negative and ordered."""
        if self.invariant_max < 0.0:
            raise ValueError(f"invariant_max must be >= 0, got {self.invariant_max}")
        if not (self.invariant_max <= self.structural_max <= self.pointer_max):
            raise ValueError(
                "variance thresholds must be non-decreasing, got "
                f"invariant_max={self.invariant_max}, "
                f"structural_max={self.structural_max}, "
                f"pointer_max={self.pointer_max}"
            )
        return self


DEFAULT_THRESHOLDS = VarianceThresholds()

# A single ByteClass, its raw integer code, or any iterable of either.
ByteClassSpec = Union[ByteClass, int, Iterable[Union[ByteClass, int]]]

# Chunk size for the byte-offset loop inside compute_variance. 16 MiB keeps
# peak working set bounded at ~4 * N * CHUNK_BYTES + 4 * min_size, well inside
# laptop RAM even for N=50, d=4 GiB.
CHUNK_BYTES = 16 * 1024 * 1024


def compute_variance(byte_buffers: List[bytes], min_size: int,
                     chunk_bytes: int = CHUNK_BYTES) -> np.ndarray:
    """Compute per-byte-position variance across multiple byte buffers.

    Uses a chunked two-pass estimator: the byte range [0, min_size) is
    divided into slabs of *chunk_bytes* bytes; each slab is stacked into an
    (N, chunk_len) float32 matrix and reduced via ``np.var(axis=0)``. Output
    is bit-identical to a single-call ``np.var`` over a fully-stacked matrix
    because the per-column reduction is column-local.

    Args:
        byte_buffers: List of raw byte sequences (each at least min_size long).
        min_size: Number of byte positions to analyze.
        chunk_bytes: Width of the per-slab reduction. Tests may override.

    Returns:
        numpy.ndarray (float32) of length min_size with per-byte variance.
    """
    if min_size == 0 or not byte_buffers:
        return np.array([], dtype=np.float32)
    views = [np.frombuffer(buf, dtype=np.uint8, count=min_size)
             for buf in byte_buffers]
    result = np.empty(min_size, dtype=np.float32)
    for start in range(0, min_size, chunk_bytes):
        end = min(start + chunk_bytes, min_size)
        mat = np.stack([v[start:end] for v in views]).astype(np.float32)
        result[start:end] = np.var(mat, axis=0)
    return result


class WelfordVariance:
    """Online (Welford's recurrence) per-byte variance accumulator.

    Maintains running mean and sum-of-squared-deviations vectors of length
    *size* that are updated one dump at a time. Intended for incremental /
    live-capture workflows where dumps arrive sequentially and the full set
    cannot be held in memory at once.

    Numerically equivalent to ``np.var(..., axis=0, ddof=0)`` applied to the
    batch of all added dumps.
    """

    def __init__(self, size: int) -> None:
        self._size = size
        self._mean = np.zeros(size, dtype=np.float32)
        self._m2 = np.zeros(size, dtype=np.float32)
        self._n = 0

    @property
    def num_dumps(self) -> int:
        return self._n

    @property
    def size(self) -> int:
        return self._size

    def add_dump(self, buf: bytes) -> None:
        """Fold one dump into the running accumulators.

        Processed in position slabs so the transient float32 working set stays
        O(chunk) rather than O(size). The naive whole-array update allocates ~5
        full-width temporaries (``x``, ``delta``, ``delta/n``, ``x-mean`` and the
        product); on a multi-GiB dump that peaks at tens of GiB. Welford's
        recurrence is per-position independent, so slabbing by byte offset is
        bit-identical to the whole-array update.
        """
        if len(buf) < self._size:
            raise ValueError(
                f"dump shorter than accumulator size ({len(buf)} < {self._size})"
            )
        raw = np.frombuffer(buf, dtype=np.uint8, count=self._size)
        self._n += 1
        n = self._n
        for start in range(0, self._size, CHUNK_BYTES):
            end = min(start + CHUNK_BYTES, self._size)
            x = raw[start:end].astype(np.float32)
            mean = self._mean[start:end]  # view — ``+=`` updates in place
            m2 = self._m2[start:end]
            delta = x - mean
            mean += delta / n
            m2 += delta * (x - mean)

    def variance(self) -> np.ndarray:
        """Return current population variance (ddof=0). Zeros if n == 0."""
        if self._n == 0:
            return np.zeros(self._size, dtype=np.float32)
        return (self._m2 / self._n).astype(np.float32)

    def reset(self) -> None:
        self._mean.fill(0.0)
        self._m2.fill(0.0)
        self._n = 0

    def state_arrays(self) -> "tuple[np.ndarray, np.ndarray, int]":
        """Return (mean, m2, n) — used by the CLI to persist state to disk."""
        return self._mean, self._m2, self._n

    @classmethod
    def from_state(cls, mean: np.ndarray, m2: np.ndarray, n: int) -> "WelfordVariance":
        """Rebuild from persisted arrays (CLI round-trip)."""
        if mean.shape != m2.shape or mean.ndim != 1:
            raise ValueError("mean and m2 must be 1-D arrays of the same shape")
        obj = cls(mean.shape[0])
        obj._mean = mean.astype(np.float32, copy=True)
        obj._m2 = m2.astype(np.float32, copy=True)
        obj._n = int(n)
        return obj


def classify_variance(
    variance: Union[np.ndarray, "array.array"],
    thresholds: Optional[VarianceThresholds] = None,
) -> np.ndarray:
    """Classify every byte position by its variance value.

    Args:
        variance: Per-byte variance values (numpy array or stdlib array).
        thresholds: Optional band boundaries. ``None`` uses
            ``DEFAULT_THRESHOLDS`` (0.0 / 200.0 / 3000.0), which is what every
            caller got before the boundaries became overridable.

    Returns:
        numpy.ndarray (uint8) of ByteClass integer codes.
    """
    bands = (thresholds or DEFAULT_THRESHOLDS).validate()
    if not isinstance(variance, np.ndarray):
        variance = np.array(variance, dtype=np.float32)
    result = np.full(len(variance), ByteClass.KEY_CANDIDATE, dtype=np.uint8)
    # Variance is non-negative, so ``<= 0.0`` is exactly the historical
    # ``== 0.0`` test at the default invariant_max.
    result[variance <= bands.invariant_max] = ByteClass.INVARIANT
    mask_structural = (
        (variance > bands.invariant_max) & (variance <= bands.structural_max)
    )
    result[mask_structural] = ByteClass.STRUCTURAL
    mask_pointer = (
        (variance > bands.structural_max) & (variance <= bands.pointer_max)
    )
    result[mask_pointer] = ByteClass.POINTER
    return result


def normalize_byte_classes(byte_class: ByteClassSpec) -> Tuple[ByteClass, ...]:
    """Coerce a class query into a de-duplicated, ordered ByteClass tuple.

    Accepts a single ``ByteClass`` (or its integer code) as well as any
    iterable of them, so a caller can ask for one class or several without
    switching call shape.
    """
    if isinstance(byte_class, (ByteClass, int)):
        return (ByteClass(int(byte_class)),)
    classes = tuple(sorted({ByteClass(int(c)) for c in byte_class}))
    if not classes:
        raise ValueError("at least one ByteClass is required")
    return classes


def class_mask(
    classifications: Union[np.ndarray, "array.array"],
    classes: Sequence[ByteClass],
) -> np.ndarray:
    """Bool mask marking every byte belonging to any of *classes*."""
    if isinstance(classifications, np.ndarray):
        codes = classifications
    else:
        codes = np.array(classifications, dtype=np.uint8)
    wanted = np.array([int(c) for c in classes], dtype=np.uint8)
    return np.isin(codes, wanted)


def find_contiguous_runs(
    classifications: Union[np.ndarray, "array.array"], target: int,
) -> List[Tuple[int, int]]:
    """Return (start, end) pairs for contiguous runs of *target* ByteClass."""
    if isinstance(classifications, np.ndarray) and len(classifications) > 0:
        mask = classifications == target
        if not np.any(mask):
            return []
        diff = np.diff(mask.astype(np.int8))
        starts = np.where(diff == 1)[0] + 1
        ends = np.where(diff == -1)[0] + 1
        if mask[0]:
            starts = np.concatenate(([0], starts))
        if mask[-1]:
            ends = np.concatenate((ends, [len(classifications)]))
        return list(zip(starts.tolist(), ends.tolist()))
    # Fallback for stdlib array
    runs: List[Tuple[int, int]] = []
    run_start = None
    for i in range(len(classifications)):
        if classifications[i] == target:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                runs.append((run_start, i))
                run_start = None
    if run_start is not None:
        runs.append((run_start, len(classifications)))
    return runs


def count_classifications(classifications) -> Dict[str, int]:
    """Count occurrences of each classification label.

    Returns dict with human-readable string keys for backward compatibility.
    """
    if isinstance(classifications, np.ndarray):
        codes, cnts = np.unique(classifications, return_counts=True)
        return {ByteClass(int(c)).name.lower(): int(n) for c, n in zip(codes, cnts)}
    counts: Dict[str, int] = {}
    for code in classifications:
        label = ByteClass(int(code)).name.lower()
        counts[label] = counts.get(label, 0) + 1
    return counts
