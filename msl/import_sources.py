"""Bounded-RAM byte sources for streaming importers.

An importer describes each MSL memory region's captured-byte stream as a
short list of *runs* (file ranges, zero fill, or small literal buffers)
over a read-only mmap of the source dump. :class:`RunSource` turns that
list into the ``read_chunk(offset, length)`` callable that
:meth:`MslWriter.add_memory_region_source` pulls from during ``write()``,
so no region is ever materialised in full.

Resident set: reading through the mmap faults the source file's pages into
the process, so without help a 4 GiB import ends at ~4 GiB RSS. The source
mapping is read-only and file-backed, so its pages can be dropped at any
time and transparently re-read from the file: :meth:`MappedFile.release`
advises ``MADV_DONTNEED`` for ranges the writer has consumed (the previous
streamed chunk, a copied span, a finished ``find`` scan). Platforms without
``mmap.madvise`` / ``MADV_DONTNEED`` simply skip the advice.

Only Linux actually unmaps file-backed pages on ``MADV_DONTNEED``; macOS
accepts the call but keeps the pages resident (measured: 1 GiB stays
1 GiB RSS). Where the advice is not known to work, the streaming path
(:meth:`MappedFile.stream_view`) and :meth:`MappedFile.find` map each
chunk / scan window as its own short-lived mmap instead: still zero-copy,
and the pages leave the RSS when the window is unmapped (as soon as the
writer drops the chunk). The whole-file mapping is then only touched by
small metadata reads.
"""

from __future__ import annotations

import bisect
import gc
import mmap
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Union

Chunk = Union[bytes, bytearray, memoryview]

#: ``MADV_DONTNEED`` when this platform's ``mmap`` exposes it, else ``None``.
_MADV_DONTNEED: Optional[int] = getattr(mmap, "MADV_DONTNEED", None)

#: True where ``MADV_DONTNEED`` drops resident file-backed pages (Linux).
_DONTNEED_DROPS_PAGES: bool = sys.platform.startswith("linux")

#: Window of the :meth:`MappedFile.find` scan (released / mapped per window).
_FIND_WINDOW = 16 << 20


class MappedFile:
    """Read-only mmap of a source file plus one shared memoryview.

    Must stay open until ``MslWriter.write()`` returns (read_chunk slices
    the view lazily). Use as a context manager; an empty file maps to an
    empty view (``mmap`` rejects zero-length maps).
    """

    def __init__(self, path: Path):
        self._file = open(path, "rb")
        self._mmap: Optional[mmap.mmap] = None
        try:
            if self._file.seek(0, 2) > 0:
                self._mmap = mmap.mmap(self._file.fileno(), 0,
                                       access=mmap.ACCESS_READ)
        except Exception:
            self._file.close()
            raise
        self._view = memoryview(self._mmap) if self._mmap is not None \
            else memoryview(b"")
        # File range of the last zero-copy streamed chunk, released on the
        # next stream_view() call (the writer has consumed it by then).
        self._pending_release: Optional[Tuple[int, int]] = None

    @property
    def size(self) -> int:
        return self._view.nbytes

    def view(self, offset: int, length: int) -> memoryview:
        """Zero-copy slice ``[offset, offset+length)`` (clamped to the file)."""
        return self._view[offset:offset + length]

    def stream_view(self, offset: int, length: int) -> memoryview:
        """:meth:`view` for sequential streaming, without growing the RSS.

        Where ``MADV_DONTNEED`` works, returns a slice of the whole-file
        view and releases the previous chunk's pages (the writer's
        ``read_chunk`` loop has consumed it by the time it asks for the
        next one). Elsewhere, returns a view of a fresh window mapping
        (:meth:`_window_view`). Clamped to the file like :meth:`view`.
        """
        if self._use_windows():
            return self._window_view(offset, length)
        self._release_pending()
        self._pending_release = (offset, length)
        return self.view(offset, length)

    def _use_windows(self) -> bool:
        return self._mmap is not None and not _DONTNEED_DROPS_PAGES

    def _window_view(self, offset: int, length: int) -> memoryview:
        """Zero-copy view of ``[offset, +length)`` via its own mmap.

        The mapping is unmapped (and its pages leave the RSS) once the last
        reference to the returned view is dropped.
        """
        length = max(0, min(length, self.size - offset))
        if length == 0:
            return memoryview(b"")
        window, start = self._map_window(offset, offset + length)
        return memoryview(window)[offset - start:]

    def _map_window(self, lo: int, hi: int) -> Tuple[mmap.mmap, int]:
        """Read-only mmap covering ``[lo, hi)`` and its (aligned) file start."""
        start = lo - lo % mmap.ALLOCATIONGRANULARITY
        window = mmap.mmap(self._file.fileno(), hi - start,
                           access=mmap.ACCESS_READ, offset=start)
        return window, start

    def release(self, offset: int, length: int) -> None:
        """Advise the kernel to drop resident pages of ``[offset, +length)``.

        Safe at any time: the mapping is read-only and file-backed, so a
        later access (even through a still-live view) re-reads the file.
        No-op on platforms without ``madvise`` / ``MADV_DONTNEED``.
        """
        if (self._mmap is None or _MADV_DONTNEED is None
                or not hasattr(self._mmap, "madvise")):
            return
        start = offset - offset % mmap.PAGESIZE  # madvise needs page alignment
        end = min(offset + length, self.size)
        if end <= start:
            return
        try:
            self._mmap.madvise(_MADV_DONTNEED, start, end - start)
        except (OSError, ValueError):
            pass  # advisory only

    def _release_pending(self) -> None:
        if self._pending_release is not None:
            self.release(*self._pending_release)
            self._pending_release = None

    def find(self, needle: bytes, start: int, end: int) -> int:
        """``mmap.find`` over ``[start, end)``; -1 when absent or file empty.

        Scans in :data:`_FIND_WINDOW` windows (overlapping by
        ``len(needle) - 1`` so a match straddling two windows is seen),
        releasing each scanned window (or mapping it on its own), so a
        key-hint scan of a huge region does not grow the RSS.
        """
        if self._mmap is None:
            return b"".find(needle, start, end)
        start, end = max(0, start), min(end, self.size)
        if not needle:
            return start if start <= end else -1
        step = max(_FIND_WINDOW, len(needle))
        pos = start
        while pos + len(needle) <= end:
            hit = self._find_window(needle, pos,
                                    min(pos + step + len(needle) - 1, end))
            if hit >= 0:
                return hit
            pos += step
        return -1

    def _find_window(self, needle: bytes, lo: int, hi: int) -> int:
        """Absolute offset of *needle* in ``[lo, hi)`` (or -1)."""
        if self._use_windows():
            window, start = self._map_window(lo, hi)
            with window:
                hit = window.find(needle, lo - start)
            return start + hit if hit >= 0 else -1
        try:
            return self._mmap.find(needle, lo, hi)
        finally:
            self.release(lo, hi - lo)

    def close(self) -> None:
        self._view.release()
        if self._mmap is not None:
            try:
                self._mmap.close()
            except BufferError:
                # A transient sub-view (e.g. a writer piece) is still alive;
                # collect it and retry once.
                gc.collect()
                self._mmap.close()
            self._mmap = None
        self._file.close()

    def __enter__(self) -> "MappedFile":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclass(frozen=True)
class Run:
    """One contiguous piece of a region's captured-byte stream.

    Exactly one source applies: ``file_offset`` (bytes from the mapped
    file), ``literal`` (a small in-memory buffer), or neither (zero fill).
    """

    stream_offset: int
    length: int
    file_offset: Optional[int] = None
    literal: Optional[bytes] = None


class RunBuilder:
    """Accumulate runs in stream order, coalescing adjacent like runs."""

    def __init__(self) -> None:
        self.runs: List[Run] = []
        self.length = 0

    def add_file(self, file_offset: int, length: int) -> None:
        last = self.runs[-1] if self.runs else None
        if (last is not None and last.file_offset is not None
                and last.file_offset + last.length == file_offset):
            self._extend_last(length)
        else:
            self._append(Run(self.length, length, file_offset=file_offset))

    def add_zeros(self, length: int) -> None:
        last = self.runs[-1] if self.runs else None
        if last is not None and last.file_offset is None and last.literal is None:
            self._extend_last(length)
        else:
            self._append(Run(self.length, length))

    def add_literal(self, data: bytes) -> None:
        self._append(Run(self.length, len(data), literal=bytes(data)))

    def _append(self, run: Run) -> None:
        if run.length > 0:
            self.runs.append(run)
            self.length += run.length

    def _extend_last(self, length: int) -> None:
        last = self.runs[-1]
        self.runs[-1] = Run(last.stream_offset, last.length + length,
                            file_offset=last.file_offset)
        self.length += length


class RunSource:
    """``read_chunk(offset, length)`` over a run list and a mapped file.

    A request inside a single file run returns a zero-copy memoryview;
    requests spanning runs (or touching zero/literal runs) are assembled
    into one buffer of exactly *length* bytes.
    """

    def __init__(self, mapped: MappedFile, runs: List[Run]):
        self._mapped = mapped
        self._runs = runs
        self._starts = [r.stream_offset for r in runs]

    def __call__(self, offset: int, length: int) -> Chunk:
        idx = bisect.bisect_right(self._starts, offset) - 1
        run = self._runs[idx]
        rel = offset - run.stream_offset
        if run.file_offset is not None and rel + length <= run.length:
            return self._mapped.stream_view(run.file_offset + rel, length)
        return self._assemble(idx, offset, length)

    def _assemble(self, idx: int, offset: int, length: int) -> bytearray:
        out = bytearray(length)
        done = 0
        while done < length:
            run = self._runs[idx]
            rel = offset + done - run.stream_offset
            take = min(run.length - rel, length - done)
            if run.file_offset is not None:
                src = run.file_offset + rel
                out[done:done + take] = self._mapped.stream_view(src, take)
                self._mapped.release(src, take)  # copied: pages not needed
            elif run.literal is not None:
                out[done:done + take] = run.literal[rel:rel + take]
            done += take
            idx += 1
        return out

    @property
    def length(self) -> int:
        return self._runs[-1].stream_offset + self._runs[-1].length if self._runs else 0

    def __len__(self) -> int:
        return self.length

    def find(self, needle: bytes) -> int:
        """First offset of *needle* in the stream (``bytes.find`` semantics).

        Searches file runs in place via ``mmap.find`` and checks each run
        boundary with a small (< 2*len(needle)) window, so the region is
        never materialised.
        """
        if not needle:
            return 0
        for idx, run in enumerate(self._runs):
            if idx > 0:
                hit = self._find_across_boundary(needle, run.stream_offset)
                if hit >= 0:
                    return hit
            hit = self._find_in_run(needle, run)
            if hit >= 0:
                return hit
        return -1

    def _find_in_run(self, needle: bytes, run: Run) -> int:
        if run.file_offset is not None:
            hit = self._mapped.find(needle, run.file_offset,
                                    run.file_offset + run.length)
            return hit - run.file_offset + run.stream_offset if hit >= 0 else -1
        if run.literal is not None:
            hit = run.literal.find(needle)
        else:
            hit = 0 if run.length >= len(needle) and not any(needle) else -1
        return hit + run.stream_offset if hit >= 0 else -1

    def _find_across_boundary(self, needle: bytes, boundary: int) -> int:
        lo = max(0, boundary - (len(needle) - 1))
        hi = min(self.length, boundary + len(needle) - 1)
        if hi - lo < len(needle):
            return -1
        hit = bytes(self(lo, hi - lo)).find(needle)
        return lo + hit if hit >= 0 else -1
