"""Bounded-RAM byte buffer for single-dump analysis (``run_file``).

Single-dump algorithms take one flat ``dump_data`` buffer. Historically the
runner always called ``source.read_all()``, i.e. one full heap copy of the dump
(two, transiently, for ``.msl`` whose ``read_all`` joins its captured runs).
:func:`open_analysis_buffer` keeps that path when it fits the memory budget
and otherwise hands the algorithms a read-only :class:`mmap.mmap` instead:

* ``"bytes"`` — ``source.read_all()``; used whenever the estimate fits the
  budget (no behaviour change), and as the forced fallback.
* ``"mmap"``  — a :class:`~memdiver.core.dump_source.RawDumpSource` is a flat
  file whose default view IS the file bytes, so the file itself is mapped
  (zero copy). A gdb_raw / lldb_raw ``.bin`` (``vas_is_file_prefix``) is
  mapped the same way, up to its ``vas`` size (trailing padding excluded).
* ``"spill"`` — any other source with a ``read_all`` (a plaintext ``.msl`` or a
  gcore ELF core, whose ``vas`` view is the concatenation of captured runs /
  PT_LOAD bodies and is not contiguous on disk) is streamed in bounded chunks
  via ``read_range`` into a temporary file, which is mapped and deleted on exit.

The flat view is the one ``read_all()`` returns by default (:func:`flat_view`:
``raw`` for a raw dump, ``vas`` for ``.msl``, gcore and gdb_raw / lldb_raw),
so hit offsets are in the same space as before for every format. Every read
here names that view explicitly: gcore and the regioned sources default
``read_range`` to ``"raw"`` and ``size`` to the raw file size, which is NOT
their ``read_all`` view.

An ENCRYPTED ``.msl`` is never spilled: that would write decrypted memory to
disk. It keeps the ``read_all`` path, guarded by
:func:`~memdiver.core.memory_budget.check_budget`, which raises the structured
``memory_budget_exceeded`` error unless ``force`` is set. The same guard
applies when the spill directory lacks free space.

The gate also counts the algorithms' own working sets
(:meth:`~memdiver.algorithms.base.BaseAlgorithm.estimate_working_set`, passed
in as ``working_sets``): peak = dump copy (``read_all`` path only) + the
largest working set, since ``run_file`` runs algorithms one after another.
``read_all`` is kept only while both fit; otherwise mmap/spill is chosen and
the algorithms alone are gated. See ``docs/design/large_dumps_and_memory.md``.

An mmap is a drop-in for ``bytes`` in the algorithms (``find``, ``re``,
``np.frombuffer``, slicing to ``bytes``) EXCEPT for substring ``in``, which
silently returns False; analysis code uses
:func:`memdiver.core.buffer_ops.contains_bytes` instead.
"""

from __future__ import annotations

import contextlib
import gc
import inspect
import logging
import mmap
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, List, Mapping, Optional, Union

from memdiver.core.service_errors import CapabilityError
from memdiver.core.memory_budget import (
    MemoryBudget,
    MemoryEstimate,
    check_budget,
    format_bytes,
    resolve_memory_budget,
)

logger = logging.getLogger("memdiver.app.pipeline.analysis_buffer")

STRATEGY_BYTES = "bytes"
STRATEGY_MMAP = "mmap"
STRATEGY_SPILL = "spill"

#: Bytes copied per ``read_range`` call while spilling (bounds the heap).
SPILL_CHUNK_BYTES = 8 * 1024 * 1024

#: Content sample for data-dependent working-set estimates: this many blocks
#: of this size, evenly spread over the flat view (2 MiB read in total).
SAMPLE_BLOCKS = 32
SAMPLE_BLOCK_BYTES = 64 * 1024

BufferLike = Union[bytes, mmap.mmap]


@dataclass(frozen=True)
class BufferPlan:
    """Which strategy :func:`open_analysis_buffer` takes, and why."""

    strategy: str
    estimate: MemoryEstimate
    reason: str


# ---------------------------------------------------------------------------
# The flat view (what ``read_all()`` returns)
# ---------------------------------------------------------------------------

#: ``format_name`` of sources whose ``read_all`` holds ONE copy of the view at
#: peak (one mmap slice, or a join of zero-copy memoryview slices). Measured
#: with tracemalloc in ``tests/test_analysis_buffer.py``.
_SINGLE_COPY_READ_ALL_FORMATS = ("gcore", "gdb_raw", "lldb_raw")


def flat_view(source: Any) -> Optional[str]:
    """The view ``source.read_all()`` materialises (its ``view`` default).

    ``None`` when the source has no ``read_all`` or it takes no ``view``
    (duck-typed sources); callers then use ``size`` / ``read_range`` as is.
    """
    read_all = getattr(source, "read_all", None)
    if read_all is None:
        return None
    try:
        default = inspect.signature(read_all).parameters["view"].default
    except (TypeError, ValueError, KeyError):
        return None
    return default if isinstance(default, str) else None


def flat_view_size(source: Any) -> int:
    """``len(source.read_all())`` without reading it."""
    view = flat_view(source)
    return int(source.size if view is None else source.size_for(view))


def read_flat_range(source: Any, offset: int, length: int) -> bytes:
    """``source.read_all()[offset:offset + length]`` via ``read_range``."""
    view = flat_view(source)
    if view is None:
        return source.read_range(offset, length)
    return source.read_range(offset, length, view=view)


# ---------------------------------------------------------------------------
# Content sample (for BaseAlgorithm.estimate_working_set)
# ---------------------------------------------------------------------------


def read_estimate_sample(source: Any, blocks: int = SAMPLE_BLOCKS,
                         block_bytes: int = SAMPLE_BLOCK_BYTES,
                         ) -> Optional[List[bytes]]:
    """Evenly spread blocks of *source*'s flat view, or ``None``.

    The whole view when it is no larger than ``blocks * block_bytes``.
    ``None`` when the source cannot ``read_range`` (estimates then assume the
    worst case).
    """
    if not hasattr(source, "read_range"):
        return None
    try:
        size = flat_view_size(source)
        if size <= 0:
            return None
        if size <= blocks * block_bytes:
            return [read_flat_range(source, 0, size)]
        stride = (size - block_bytes) // (blocks - 1) if blocks > 1 else 0
        return [read_flat_range(source, i * stride, block_bytes)
                for i in range(blocks)]
    except Exception:  # noqa: BLE001 - a sample is an optimisation only
        logger.debug("could not sample %s for estimates", source.name, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Planning (pure apart from reading source attributes / disk free space)
# ---------------------------------------------------------------------------


def _is_raw_file_source(source: Any) -> bool:
    from memdiver.core.dump_source import RawDumpSource
    return type(source) is RawDumpSource


def _flat_view_is_file_prefix(source: Any) -> bool:
    """True when the flat view is the first ``flat_view_size`` file bytes.

    A raw dump (the whole file), or a regioned source declaring
    ``vas_is_file_prefix`` whose flat view is that ``vas`` view.
    """
    if _is_raw_file_source(source):
        return True
    return (bool(getattr(source, "vas_is_file_prefix", False))
            and flat_view(source) == "vas")


def _is_encrypted(source: Any) -> bool:
    """True when *source* decrypts its content (an encrypted ``.msl``)."""
    status = getattr(source, "tag_status", None)
    if status is None:
        return False
    from memdiver.msl.enums import TagStatus
    return status != TagStatus.NOT_ENCRYPTED


def estimate_read_all(source: Any) -> MemoryEstimate:
    """Peak heap of ``source.read_all()``.

    ``RawDumpSource.read_all`` is one ``mmap.read()`` (1x); gcore and
    gdb_raw / lldb_raw are one copy too (see
    ``_SINGLE_COPY_READ_ALL_FORMATS``). Every other source (``.msl``) joins
    chunks, so the chunk list and the joined result coexist (2x).
    """
    size = flat_view_size(source)
    single_copy = (_is_raw_file_source(source)
                   or getattr(source, "format_name", None)
                   in _SINGLE_COPY_READ_ALL_FORMATS)
    factor = 1 if single_copy else 2
    return MemoryEstimate(
        peak_bytes=size * factor,
        operation=f"single-dump analysis read of {source.name}",
        breakdown={"dump_copy": size * factor},
    )


def _limit(budget: Union[MemoryBudget, int]) -> int:
    return budget.bytes if isinstance(budget, MemoryBudget) else int(budget)


def _spill_space_ok(size: int, spill_dir: Optional[Path]) -> bool:
    target = spill_dir if spill_dir is not None else Path(tempfile.gettempdir())
    while not target.exists() and target.parent != target:
        target = target.parent  # spill_dir is created lazily by the spill
    try:
        return shutil.disk_usage(target).free > size
    except OSError:
        return False


def plan_analysis_buffer(
    source: Any,
    *,
    budget: Union[MemoryBudget, int],
    spill_dir: Optional[Path] = None,
    working_sets: Optional[Mapping[str, int]] = None,
) -> BufferPlan:
    """Choose a strategy for *source* (opened) under *budget*; never raises.

    ``read_all`` bytes are kept only when the copy PLUS the largest algorithm
    working set (*working_sets*, algorithm name -> bytes; the algorithms run
    one after another) fits; otherwise the zero-heap mmap/spill paths are
    preferred so the budget is left to the algorithms.
    """
    estimate = estimate_read_all(source)
    limit = _limit(budget)
    heaviest = max(working_sets.values(), default=0) if working_sets else 0
    if limit <= 0 or estimate.peak_bytes + heaviest <= limit:
        return BufferPlan(STRATEGY_BYTES, estimate, "fits the memory budget")
    if _flat_view_is_file_prefix(source):
        return BufferPlan(STRATEGY_MMAP, estimate, "raw file mapped read-only")
    if not hasattr(source, "read_all"):
        # No flat view to spill; keep today's call (and its error).
        return BufferPlan(STRATEGY_BYTES, estimate, "source has no flat view")
    if _is_encrypted(source):
        return BufferPlan(STRATEGY_BYTES, estimate,
                          "encrypted .msl is never spilled as plaintext")
    if not _spill_space_ok(flat_view_size(source), spill_dir):
        return BufferPlan(STRATEGY_BYTES, estimate, "not enough disk to spill")
    return BufferPlan(STRATEGY_SPILL, estimate, "flat view spilled to a temp file")


# ---------------------------------------------------------------------------
# Gate: dump buffer + algorithm working sets
# ---------------------------------------------------------------------------


def analysis_estimate(plan: BufferPlan, source_name: str,
                      working_sets: Optional[Mapping[str, int]] = None,
                      ) -> MemoryEstimate:
    """Peak heap of the whole analysis under *plan*.

    = the dump copy (``read_all`` strategy only; mmap/spill pages are
    file-backed and reclaimable, so they cost no heap) + the LARGEST
    algorithm working set (``run_file`` runs algorithms sequentially).
    The breakdown lists every algorithm's own estimate.
    """
    buffer_bytes = (plan.estimate.peak_bytes
                    if plan.strategy == STRATEGY_BYTES else 0)
    working_sets = dict(working_sets or {})
    breakdown = {f"dump_copy ({plan.strategy})": buffer_bytes}
    breakdown.update(working_sets)
    return MemoryEstimate(
        peak_bytes=buffer_bytes + max(working_sets.values(), default=0),
        operation=(f"single-dump analysis of {source_name} "
                   "(dump copy + largest algorithm working set)"),
        breakdown=breakdown,
    )


def _heaviest(working_sets: Optional[Mapping[str, int]]) -> Optional[str]:
    if not working_sets:
        return None
    name, size = max(working_sets.items(), key=lambda item: item[1])
    return name if size > 0 else None


def check_analysis_budget(
    estimate: MemoryEstimate,
    working_sets: Optional[Mapping[str, int]],
    *,
    force: bool,
    budget: Union[MemoryBudget, int],
) -> Optional[str]:
    """:func:`check_budget`, with the refusal naming the heaviest algorithm.

    The re-raised error keeps ``code`` / ``category`` / ``details`` and adds
    ``details["heaviest_algorithm"]`` and ``details["algorithm_working_sets"]``.
    """
    try:
        return check_budget(estimate, force=force, budget=budget)
    except CapabilityError as exc:
        heaviest = _heaviest(working_sets)
        if exc.code != "memory_budget_exceeded" or heaviest is None:
            raise
        hint = (f" Heaviest algorithm: {heaviest} (~"
                f"{format_bytes(working_sets[heaviest])} working set); deselect "
                "it or apply a region filter to shrink the dump.")
        details = dict(exc.details or {})
        details["heaviest_algorithm"] = heaviest
        details["algorithm_working_sets"] = dict(working_sets)
        raise CapabilityError(exc.message + hint, category=exc.category,
                              status=exc.status, code=exc.code,
                              details=details) from None


# ---------------------------------------------------------------------------
# Materialisation
# ---------------------------------------------------------------------------


def _close_mapping(mapping: mmap.mmap) -> None:
    """Close *mapping*; a still-exported buffer (numpy view) is left to GC."""
    try:
        mapping.close()
    except BufferError:
        gc.collect()
        try:
            mapping.close()
        except BufferError:
            logger.debug("mmap still exported at exit; closing on GC")


@contextlib.contextmanager
def _mapped_file(path: Path, length: Optional[int] = None) -> Iterator[BufferLike]:
    """Map *path* read-only: the whole file, or only its first *length* bytes."""
    with open(path, "rb") as fh:
        file_size = os.fstat(fh.fileno()).st_size
        length = file_size if length is None else min(length, file_size)
        if length <= 0:
            yield b""
            return
        mapping = mmap.mmap(fh.fileno(), length, access=mmap.ACCESS_READ)
        try:
            yield mapping
        finally:
            _close_mapping(mapping)


def spill_flat_view(source: Any, spill_dir: Optional[Path] = None,
                    chunk_bytes: int = SPILL_CHUNK_BYTES) -> Path:
    """Stream ``source``'s flat view to a new temp file; return its path.

    Equal to ``source.read_all()`` byte for byte (``read_range`` over
    :func:`flat_view`, e.g. the ``vas`` concatenation for ``.msl`` / gcore).
    The caller owns (and must delete) the file.
    """
    if spill_dir is not None:
        spill_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="memdiver-spill-", suffix=".bin",
                                dir=None if spill_dir is None else str(spill_dir))
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            total = flat_view_size(source)
            for offset in range(0, total, chunk_bytes):
                out.write(read_flat_range(source, offset,
                                          min(chunk_bytes, total - offset)))
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


@contextlib.contextmanager
def _spilled(source: Any, spill_dir: Optional[Path]) -> Iterator[BufferLike]:
    path = spill_flat_view(source, spill_dir)
    try:
        with _mapped_file(path) as mapping:
            yield mapping
    finally:
        path.unlink(missing_ok=True)
        if spill_dir is not None:
            with contextlib.suppress(OSError):
                spill_dir.rmdir()  # only succeeds when empty


@contextlib.contextmanager
def open_analysis_buffer(
    source: Any,
    *,
    budget: Union[MemoryBudget, int, None] = None,
    force: bool = False,
    spill_dir: Optional[Path] = None,
    working_sets: Optional[Mapping[str, int]] = None,
) -> Iterator[BufferLike]:
    """Yield the dump's flat view as ``bytes`` or a read-only ``mmap``.

    *source* must be open while entering; the yielded mmap does not depend on
    it afterwards, so the caller may close the source and keep using the
    buffer until this context exits. *working_sets* (algorithm name -> the
    bytes :meth:`BaseAlgorithm.estimate_working_set` predicts) is budgeted on
    top of the buffer, see :func:`analysis_estimate`. Raises the structured
    ``memory_budget_exceeded`` :class:`CapabilityError` when that total
    exceeds the budget and ``force`` is not set -- for the mmap/spill paths
    only the algorithms can exceed it.
    """
    if budget is None:
        budget = resolve_memory_budget()
    plan = plan_analysis_buffer(source, budget=budget, spill_dir=spill_dir,
                                working_sets=working_sets)
    logger.info("analysis buffer for %s (%s): %s — %s", source.name,
                format_bytes(flat_view_size(source)), plan.strategy, plan.reason)
    check_analysis_budget(analysis_estimate(plan, source.name, working_sets),
                          working_sets, force=force, budget=budget)
    if plan.strategy == STRATEGY_MMAP:
        with _mapped_file(Path(source.path), flat_view_size(source)) as mapping:
            yield mapping
    elif plan.strategy == STRATEGY_SPILL:
        with _spilled(source, spill_dir) as mapping:
            yield mapping
    else:
        yield source.read_all()
