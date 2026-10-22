"""Streaming slab-wise two-pass variance across N byte sources.

The one-shot consensus builders used to load every dump whole, then hand the
N buffers to :func:`core.variance.compute_variance`. Peak memory was therefore
``N x dump size`` before a single variance value existed.

:func:`stream_variance` keeps the exact same estimator (``np.var(axis=0)``,
two-pass, ddof=0, float32, over a freshly stacked contiguous ``(N, w)`` slab)
but changes how the bytes are *reached*: it walks position slabs and reads
each slab range from each source on demand. Variance is column-local, so the
result does not depend on the slab width -- with one numpy caveat handled by
:func:`plan_slabs`: a ``(N, 1)`` slab is reduced along a contiguous axis
(pairwise summation) and can differ in the last bit from the same column
inside a wider slab. Slab plans therefore never emit a width-1 slab, except
exactly where the historical 16 MiB grid of ``compute_variance`` did.

Working set per slab: ``N x w x BYTES_PER_POSITION_PER_SOURCE``.
"""

from __future__ import annotations

import logging
import os
import tempfile
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple, Union

import numpy as np

from .memory_budget import (
    MIB,
    MemoryBudget,
    MemoryEstimate,
    adaptive_chunk_positions,
    resolve_memory_budget,
)
from .variance import CHUNK_BYTES

logger = logging.getLogger("memdiver.core.slab_variance")

#: Per position per source: 1 B uint8 read + 4 B float32 stack + 4 B float32
#: ``arr - mean`` deviation temporary inside ``np.var``.
BYTES_PER_POSITION_PER_SOURCE = 9
#: Per position of the slab: variance result + mean temporaries (float32).
SLAB_OVERHEAD_PER_POSITION = 8
#: Bytes per position of a float32 variance vector.
VARIANCE_BYTES_PER_POSITION = 4
#: Bytes per position of the uint8 classification vector.
CLASSIFICATION_BYTES_PER_POSITION = 1

BudgetLike = Union[MemoryBudget, int, None]


# ---------------------------------------------------------------------------
# Slab readers
# ---------------------------------------------------------------------------


class SlabReader(Protocol):
    """Anything that can serve ``[start, end)`` of a flat byte stream."""

    size: int

    def read_slab(self, start: int, end: int) -> np.ndarray:
        """Return exactly ``end - start`` bytes as a 1-D uint8 array."""

    def read_prefix(self, length: int) -> bytes:
        """Return the first *length* bytes as one ``bytes`` object."""


def _require_length(data: Any, expected: int, what: str) -> None:
    if len(data) != expected:
        raise ValueError(
            f"{what}: short read ({len(data)} of {expected} bytes)")


class BufferSlabReader:
    """Serve slabs as zero-copy views of an in-memory buffer."""

    def __init__(self, buffer: Any) -> None:
        self._buffer = buffer
        self._view = np.frombuffer(buffer, dtype=np.uint8)
        self.size = int(self._view.shape[0])

    def read_slab(self, start: int, end: int) -> np.ndarray:
        return self._view[start:end]

    def read_prefix(self, length: int) -> bytes:
        if isinstance(self._buffer, bytes) and len(self._buffer) == length:
            return self._buffer
        return self._view[:length].tobytes()


class FileSlabReader:
    """Serve slabs of a plain file with ``readinto`` (no whole-file read)."""

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.size = self.path.stat().st_size
        self._fh = None

    def _handle(self):
        if self._fh is None:
            self._fh = open(self.path, "rb")
        return self._fh

    def read_slab(self, start: int, end: int) -> np.ndarray:
        out = np.empty(end - start, dtype=np.uint8)
        fh = self._handle()
        fh.seek(start)
        got = fh.readinto(memoryview(out))
        _require_length(out[:got], end - start, str(self.path))
        return out

    def read_prefix(self, length: int) -> bytes:
        fh = self._handle()
        fh.seek(0)
        data = fh.read(length)
        _require_length(data, length, str(self.path))
        return data

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class SourceSlabReader:
    """Serve slabs of a DumpSource's default flat view via ``read_range``.

    Only used where ``read_range(o, n)`` is known to equal
    ``read_all()[o:o + n]`` (see :func:`as_slab_reader`).
    """

    def __init__(self, source: Any, size: int) -> None:
        self._source = source
        self.size = int(size)

    def read_slab(self, start: int, end: int) -> np.ndarray:
        data = self._source.read_range(start, end - start)
        _require_length(data, end - start, str(getattr(self._source, "path", "")))
        return np.frombuffer(data, dtype=np.uint8)

    def read_prefix(self, length: int) -> bytes:
        data = self._source.read_range(0, length)
        _require_length(data, length, str(getattr(self._source, "path", "")))
        return bytes(data)


class CallableSlabReader:
    """Adapt ``read_fn(start, end) -> bytes-like`` of a *size*-byte stream.

    For streams that exist only as a function -- e.g. an aligned slab
    assembled from page references -- so :func:`stream_variance` can walk
    them like any other source.
    """

    def __init__(self, read_fn: Callable[[int, int], Any], size: int) -> None:
        self._read_fn = read_fn
        self.size = int(size)

    def read_slab(self, start: int, end: int) -> np.ndarray:
        data = self._read_fn(start, end)
        _require_length(data, end - start, "slab reader")
        if isinstance(data, np.ndarray):
            return data
        return np.frombuffer(data, dtype=np.uint8)

    def read_prefix(self, length: int) -> bytes:
        return bytes(self._read_fn(0, length))


def _msl_flat_view_is_dense(source: Any) -> bool:
    """True when an MSL source's ``read_range`` "vas" stream equals ``read_all``.

    ``read_all`` concatenates each captured run's AVAILABLE bytes while
    ``read_range`` addresses runs by their nominal ``length``; the two agree
    exactly when no run is truncated (``avail == length``). The region view
    filter is honoured by both, because both go through the filtered index.
    """
    run_index = getattr(source, "_run_index", None)
    if not callable(run_index):
        return False
    index = run_index()
    if index is None:
        return False
    return all(run.avail == run.length for run in index.runs)


def _is_raw_source(source: Any) -> bool:
    from .dump_source import RawDumpSource
    return isinstance(source, RawDumpSource)


def _raw_size(source: Any) -> int:
    """A RawDumpSource's length; it reports 0 until mapped, so map it first
    (``read_all`` / ``read_range`` would do the same)."""
    ensure_open = getattr(source, "_ensure_open", None)
    if callable(ensure_open):
        ensure_open()
    return int(source.size)


def _is_msl_source(source: Any) -> bool:
    from .dump_source import MslDumpSource
    return isinstance(source, MslDumpSource)


def as_slab_reader(source: Any) -> SlabReader:
    """Wrap a buffer, a file path, a DumpSource or a SlabReader.

    DumpSources whose flat view cannot be proven slice-equivalent to
    ``read_all()`` fall back to one ``read_all()`` -- the historical
    behaviour, and counted by :func:`whole_read_bytes`.
    """
    if hasattr(source, "read_slab") and hasattr(source, "size"):
        return source
    if isinstance(source, (bytes, bytearray, memoryview, np.ndarray)):
        return BufferSlabReader(source)
    if isinstance(source, (str, os.PathLike)):
        return FileSlabReader(source)
    if _is_raw_source(source):
        return SourceSlabReader(source, _raw_size(source))
    if _is_msl_source(source) and _msl_flat_view_is_dense(source):
        return SourceSlabReader(source, source.size)
    return BufferSlabReader(source.read_all())


def sliceable_flat_size(source: Any) -> Optional[int]:
    """``len(source.read_all())`` without reading, or ``None`` if unprovable.

    Known for raw dumps and for ``.msl`` sources whose captured runs are all
    complete (honouring any region view filter).
    """
    if _is_raw_source(source):
        return _raw_size(source)
    if _is_msl_source(source) and _msl_flat_view_is_dense(source):
        return int(source.size)
    return None


def whole_read_bytes(source: Any) -> int:
    """Bytes :func:`as_slab_reader` will hold resident for *source* (estimate)."""
    if isinstance(source, (bytes, bytearray, memoryview, np.ndarray, str, os.PathLike)):
        return 0
    if hasattr(source, "read_slab") or _is_raw_source(source):
        return 0
    if _is_msl_source(source) and _msl_flat_view_is_dense(source):
        return 0
    return int(getattr(source, "size", 0) or 0)


# ---------------------------------------------------------------------------
# Slab planning
# ---------------------------------------------------------------------------


def _grid(begin: int, end: int, chunk: int) -> List[Tuple[int, int]]:
    """``[begin, end)`` cut every *chunk*; a width-1 tail joins its neighbour."""
    slabs = [(s, min(s + chunk, end)) for s in range(begin, end, chunk)]
    if len(slabs) > 1 and slabs[-1][1] - slabs[-1][0] == 1:
        last = slabs.pop()
        slabs[-1] = (slabs[-1][0], last[1])
    return slabs


def plan_slabs(size: int, chunk: int,
               legacy_chunk: Optional[int] = CHUNK_BYTES) -> List[Tuple[int, int]]:
    """Slab boundaries whose ``np.var`` results equal ``compute_variance``.

    Every slab is at least two positions wide, except when the legacy
    ``legacy_chunk`` grid itself ended in a single position (``size %
    legacy_chunk == 1``): that position is then reduced alone, as before.
    ``legacy_chunk=None`` means the reference never reduced a lone position
    (e.g. the per-page aligned MSL build), so no width-1 slab is emitted.
    """
    if size <= 0:
        return []
    if chunk < 1:
        raise ValueError(f"chunk must be positive, got {chunk}")
    if legacy_chunk and size > 1 and size % legacy_chunk == 1:
        return _grid(0, size - 1, chunk) + [(size - 1, size)]
    return _grid(0, size, chunk)


#: Widest slab ever used. Wider slabs buy nothing (1 MiB is as fast as
#: 16 MiB, measured: 4 x 32 MiB in 0.17 s vs 0.25 s -- cache-friendlier)
#: but multiply the working set, so the budget only ever narrows it.
MAX_SLAB_POSITIONS = 1 * MIB


def resolve_chunk_positions(n_sources: int, budget: BudgetLike = None) -> int:
    """Slab width for *n_sources* under *budget* (``MAX_SLAB_POSITIONS`` at most)."""
    if budget is None:
        budget = resolve_memory_budget()
    limit = budget.bytes if isinstance(budget, MemoryBudget) else int(budget)
    if limit <= 0:
        return MAX_SLAB_POSITIONS
    return adaptive_chunk_positions(
        max(1, n_sources), BYTES_PER_POSITION_PER_SOURCE, budget,
        max_chunk=MAX_SLAB_POSITIONS,
    )


# ---------------------------------------------------------------------------
# Estimate / output allocation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SlabVariancePlan:
    """Chunk width, variance placement and the predicted peak of one build."""

    chunk_positions: int
    variance_in_ram: bool
    estimate: MemoryEstimate


def _budget_limit(budget: BudgetLike) -> int:
    if isinstance(budget, MemoryBudget):
        return budget.bytes
    return int(budget or 0)


def _estimate(n_sources: int, size: int, chunk: int, *, variance_in_ram: bool,
              with_reference: bool, classify: bool, resident_sources: int,
              operation: str, extra: Optional[Dict[str, int]] = None) -> MemoryEstimate:
    width = min(chunk, size) if size else 0
    breakdown = {
        "slab_working_set": n_sources * width * BYTES_PER_POSITION_PER_SOURCE
        + width * SLAB_OVERHEAD_PER_POSITION,
        "variance": size * VARIANCE_BYTES_PER_POSITION if variance_in_ram else 0,
    }
    if with_reference:
        breakdown["reference_bytes"] = size
    if classify:
        breakdown["classifications"] = size * CLASSIFICATION_BYTES_PER_POSITION
    if resident_sources:
        breakdown["whole_source_reads"] = resident_sources
    for name, nbytes in (extra or {}).items():
        if nbytes:
            breakdown[name] = int(nbytes)
    return MemoryEstimate(sum(breakdown.values()), operation, breakdown)


def plan_slab_variance(
    n_sources: int,
    size: int,
    *,
    budget: BudgetLike,
    with_reference: bool = True,
    classify: bool = True,
    resident_sources: int = 0,
    chunk_positions: Optional[int] = None,
    operation: str = "consensus build",
    extra: Optional[Dict[str, int]] = None,
) -> SlabVariancePlan:
    """Pick a slab width and keep the variance in RAM only when it fits.

    ``resident_sources`` is the byte total of sources that must be read whole
    (see :func:`whole_read_bytes`). ``extra`` adds named components to the
    estimate (e.g. an alignment index or a decompressed-region cache).
    """
    chunk = chunk_positions or resolve_chunk_positions(n_sources, budget)
    kwargs = dict(with_reference=with_reference, classify=classify,
                  resident_sources=resident_sources, operation=operation,
                  extra=extra)
    in_ram = _estimate(n_sources, size, chunk, variance_in_ram=True, **kwargs)
    limit = _budget_limit(budget)
    if limit <= 0 or in_ram.peak_bytes <= limit:
        return SlabVariancePlan(chunk, True, in_ram)
    on_disk = _estimate(n_sources, size, chunk, variance_in_ram=False, **kwargs)
    return SlabVariancePlan(chunk, False, on_disk)


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def allocate_variance_output(size: int, *, in_ram: bool = True,
                             directory: Optional[Union[str, Path]] = None) -> np.ndarray:
    """A float32 vector of *size*: in RAM, or a disk-backed ``.npy`` memmap.

    The memmap's file is unlinked right away where the OS allows it (POSIX
    keeps the mapping alive); otherwise it is removed once the array is
    garbage collected.
    """
    if in_ram or size == 0:
        return np.empty(size, dtype=np.float32)
    fd, path = tempfile.mkstemp(prefix="memdiver-variance-", suffix=".npy",
                                dir=str(directory) if directory else None)
    os.close(fd)
    out = np.lib.format.open_memmap(path, mode="w+", dtype=np.float32, shape=(size,))
    try:
        os.unlink(path)
    except OSError:
        weakref.finalize(out, _remove_quietly, path)
    logger.info("variance (%d MiB) placed in a disk-backed memmap", size * 4 // MIB)
    return out


# ---------------------------------------------------------------------------
# The estimator
# ---------------------------------------------------------------------------


def _close_owned(readers: Sequence[Any], sources: Sequence[Any]) -> None:
    """Close the file handles this module opened (never a caller's reader)."""
    for reader, source in zip(readers, sources):
        if reader is not source and isinstance(reader, FileSlabReader):
            reader.close()


def _reduce_slab(readers: Sequence[SlabReader], start: int, end: int) -> np.ndarray:
    mat = np.empty((len(readers), end - start), dtype=np.float32)
    for row, reader in enumerate(readers):
        mat[row] = reader.read_slab(start, end)
    return np.var(mat, axis=0)


def stream_variance(
    sources: Sequence[Any],
    size: int,
    *,
    budget: BudgetLike = None,
    out: Optional[np.ndarray] = None,
    chunk_positions: Optional[int] = None,
    with_reference: bool = True,
    legacy_chunk: Optional[int] = CHUNK_BYTES,
) -> Tuple[np.ndarray, Optional[bytes]]:
    """Per-position variance of ``sources[*][0:size]``, one slab at a time.

    Bit-identical to ``compute_variance([s[:size] for s in buffers], size)``.

    :param sources: buffers, file paths, DumpSources or :class:`SlabReader` s,
        each at least *size* bytes long.
    :param budget: memory budget used to size slabs when ``chunk_positions``
        is not given (``None`` resolves the host budget).
    :param out: optional float32 destination of length *size* (e.g. a memmap).
    :param with_reference: also return ``sources[0][:size]`` as ``bytes``.
    :param legacy_chunk: reduction grid of the reference result being matched
        (see :func:`plan_slabs`); ``None`` when it never reduced a lone column.
    :returns: ``(variance, reference_or_None)``.
    """
    if out is None:
        out = np.empty(size, dtype=np.float32)
    if out.shape != (size,) or out.dtype != np.float32:
        raise ValueError("out must be a float32 vector of length size")
    if size == 0 or not sources:
        return out, (b"" if with_reference else None)
    opened = [as_slab_reader(s) for s in sources]
    readers = list(opened)
    try:
        for i, reader in enumerate(readers):
            if reader.size < size:
                raise ValueError(f"source {i} shorter than size ({reader.size} < {size})")
        reference = None
        if with_reference:
            reference = readers[0].read_prefix(size)
            readers[0] = BufferSlabReader(reference)
        chunk = chunk_positions or resolve_chunk_positions(len(readers), budget)
        for start, end in plan_slabs(size, chunk, legacy_chunk):
            out[start:end] = _reduce_slab(readers, start, end)
        return out, reference
    finally:
        _close_owned(opened, sources)
