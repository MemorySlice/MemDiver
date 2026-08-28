"""DumpSource for Linux ``gcore.core`` (ELF64 ``ET_CORE``) dumps.

Wraps :class:`core.binary_formats.elf_core_reader.ElfCoreReader` in the
same public surface as :class:`core.dump_source.RawDumpSource` /
:class:`core.dump_source.MslDumpSource` so scanners, UI endpoints, and
analysis pipelines can treat every dump flavour uniformly.

Design notes:
- mmap-only. No :meth:`pathlib.Path.read_bytes`.
- ``view="raw"``: byte-for-byte view of the ELF core file.
- ``view="vas"``: flattened concatenation of every ``PT_LOAD`` segment
  with ``filesz > 0``. Because PT_LOAD segments in an ELF core dump map
  1:1 to captured memory regions, this mirrors the semantics used by
  ``MslDumpSource.view="vas"`` and ``_RegionedRawSource.view="vas"``.
- VAS offsets -> file offsets walk the PT_LOAD table. A gap in the
  virtual-address space simply produces a short read.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from memdiver.core.binary_formats.elf_core_reader import ElfCoreReader, PtLoadSegment

logger = logging.getLogger("memdiver.core.dump_sources.gcore")


class GCoreDumpSource:
    """Freestanding DumpSource for ``gcore.core`` files (ELF64 ET_CORE)."""

    format_name = "gcore"

    #: The PT_LOAD table is a real virtual-address map, so cross-dump
    #: consensus can align these captures by VA
    #: (:mod:`memdiver.engine.consensus_va`) instead of falling back to flat
    #: file offsets. Declared rather than sniffed — see
    #: ``consensus_va.supports_va_alignment``.
    supports_va_alignment = True

    def __init__(self, path: Path):
        self._path = Path(path)
        self._reader = ElfCoreReader(self._path)
        # Cached cumulative VAS offsets for the filesz>0 PT_LOAD prefix.
        # _vas_cum[i] is the flat VAS offset where segment i starts (in the
        # filtered list); _vas_cum[-1] is the total VAS size.
        self._vas_segments: List[PtLoadSegment] = []
        self._vas_cum: List[int] = []

    # -- Path / metadata properties ----------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def size(self) -> int:
        """Raw size for back-compat with scanners that assume ``.size``."""
        return self.size_for("raw")

    # -- Lifecycle ----------------------------------------------------------

    def open(self) -> None:
        self._reader.open()
        self._rebuild_vas_index()

    def close(self) -> None:
        self._reader.close()
        self._vas_segments = []
        self._vas_cum = []

    def __enter__(self) -> "GCoreDumpSource":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._reader._mmap is None:  # noqa: SLF001 — controlled access
            self.open()

    # -- Index --------------------------------------------------------------

    def _rebuild_vas_index(self) -> None:
        """Filter to PT_LOAD segments with content and build the VAS table."""
        self._vas_segments = [
            seg for seg in self._reader.info.segments if seg.filesz > 0
        ]
        cum: List[int] = [0]
        running = 0
        for seg in self._vas_segments:
            running += seg.filesz
            cum.append(running)
        self._vas_cum = cum

    # -- Size queries -------------------------------------------------------

    def size_for(self, view: str = "vas") -> int:
        if view == "raw":
            return self._reader.size if self._reader._mmap is not None else self._stat_size()  # noqa: SLF001
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._vas_cum[-1] if self._vas_cum else 0

    def _stat_size(self) -> int:
        try:
            return self._path.stat().st_size
        except OSError:
            return 0

    # -- Iteration ----------------------------------------------------------

    def iter_ranges(self, view: str = "vas") -> Iterator[Tuple[int, int, int]]:
        """Yield ``(start_va, end_va, file_offset)`` per PT_LOAD with content."""
        if view not in ("vas", "raw"):
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        for seg in self._vas_segments:
            yield (seg.vaddr, seg.vaddr + seg.filesz, seg.file_offset)

    # -- Reading ------------------------------------------------------------

    def read_range(self, offset: int, length: int, view: str = "raw") -> bytes:
        self._ensure_open()
        if view == "raw":
            return self._reader.read_at(offset, length)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._read_vas_range(offset, length)

    def _read_vas_range(self, vas_offset: int, length: int) -> bytes:
        """Serve a flat VAS slice from the PT_LOAD table."""
        if length <= 0 or not self._vas_segments:
            return b""
        result = bytearray()
        remaining = length
        pos = vas_offset
        for idx, seg in enumerate(self._vas_segments):
            seg_start = self._vas_cum[idx]
            seg_end = self._vas_cum[idx + 1]
            seg_size = seg_end - seg_start
            if pos >= seg_size:
                pos -= seg_size
                continue
            take = min(seg_size - pos, remaining)
            file_off = seg.file_offset + pos
            result.extend(self._reader.read_at(file_off, take))
            remaining -= take
            pos = 0
            if remaining <= 0:
                break
        return bytes(result)

    def find_all(self, needle: bytes, view: str = "raw") -> List[int]:
        """Locate every occurrence of ``needle`` in the chosen view."""
        self._ensure_open()
        if view == "raw":
            return _find_all_in_bytes(self._reader_raw_bytes(), needle)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._find_all_vas(needle)

    def _reader_raw_bytes(self):
        """Return the live ``mmap`` object for the whole core file.

        The ``mmap`` object is returned directly (not sliced/copied): it
        supports ``len()`` and ``.find()`` exactly like ``bytes``, which is
        all :func:`_find_all_in_bytes` needs. Copying the entire core into a
        ``bytes`` object would defeat the mmap-only design and risk OOM on
        multi-GB cores. The caller treats the result as read-only bytes.
        """
        mm = self._reader._mmap  # noqa: SLF001
        if mm is None:
            return b""
        return mm

    def _find_all_vas(self, needle: bytes) -> List[int]:
        """Locate ``needle`` in the flattened VAS stream (overlap-tolerant).

        PT_LOAD segments are concatenated contiguously in the ``view="vas"``
        stream (see :meth:`_read_vas_range`), so a needle may straddle the
        boundary between two adjacent segments. To catch such hits without
        materialising the whole VAS stream, each segment is scanned together
        with a short overlap window stitched from the bytes that follow it in
        the VAS stream (``len(needle) - 1`` bytes is the maximum a straddling
        match can reach into the next segment). Only matches that *begin*
        inside the current segment are recorded, which keeps results unique
        and ordered.
        """
        hits: List[int] = []
        if not needle or not self._vas_segments:
            return hits
        mm = self._reader._mmap  # noqa: SLF001
        if mm is None:
            return hits
        overlap = len(needle) - 1
        for idx, seg in enumerate(self._vas_segments):
            seg_bytes = mm[seg.file_offset:seg.file_offset + seg.filesz]
            vas_base = self._vas_cum[idx]
            window = seg_bytes
            if overlap > 0:
                # Stitch up to ``overlap`` bytes from the following segment(s)
                # so a needle crossing the boundary is detected here.
                tail = self._read_vas_range(vas_base + seg.filesz, overlap)
                if tail:
                    # seg_bytes is already a fresh bytes from the mmap slice;
                    # concatenation copies it, so bytes(seg_bytes) is redundant.
                    window = seg_bytes + tail
            seg_len = seg.filesz
            start = 0
            while True:
                at = window.find(needle, start)
                if at == -1 or at >= seg_len:
                    # ``at >= seg_len`` means the match starts in the overlap
                    # tail; it will be recorded by the segment that owns it.
                    break
                hits.append(vas_base + at)
                start = at + 1
        return hits

    def find_first(self, needle: bytes, view: str = "raw") -> Optional[int]:
        """First offset of ``needle`` in the chosen view, or ``None``.

        The presence-only companion to :meth:`find_all`: it agrees with
        ``find_all(needle, view)[0]`` but early-exits on the first hit instead
        of scanning the whole core, which is what a corpus-scale
        "is this secret present?" sweep needs.
        """
        self._ensure_open()
        if view == "raw":
            return _find_first_in_bytes(self._reader_raw_bytes(), needle)
        if view != "vas":
            raise ValueError(f"Unknown view: {view!r} (expected 'raw' or 'vas')")
        return self._find_first_vas(needle)

    def _find_first_vas(self, needle: bytes) -> Optional[int]:
        """First occurrence in the flattened VAS stream (overlap-tolerant).

        Same segment walk and same boundary-stitching window as
        :meth:`_find_all_vas` - each PT_LOAD is searched together with up to
        ``len(needle) - 1`` following VAS bytes so a straddling needle is
        found - but it returns as soon as a match *begins* inside a segment.
        A first window match that starts in the stitched tail is skipped here
        exactly as :meth:`_find_all_vas` skips it: the segment that owns those
        bytes reports it on the next iteration.
        """
        if not needle or not self._vas_segments:
            return None
        mm = self._reader._mmap  # noqa: SLF001
        if mm is None:
            return None
        overlap = len(needle) - 1
        for idx, seg in enumerate(self._vas_segments):
            seg_bytes = mm[seg.file_offset:seg.file_offset + seg.filesz]
            vas_base = self._vas_cum[idx]
            window = seg_bytes
            if overlap > 0:
                tail = self._read_vas_range(vas_base + seg.filesz, overlap)
                if tail:
                    window = seg_bytes + tail
            # ``window`` is a bytes slice (or a concatenation), so it carries
            # no position -- but the start is passed explicitly anyway so every
            # ``find`` in this file reads the same way and none can regress into
            # the mmap-position trap documented in ``_find_first_in_bytes``.
            at = window.find(needle, 0)
            if at != -1 and at < seg.filesz:
                return vas_base + at
        return None

    # -- VA translation -----------------------------------------------------

    def va_to_file_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a core-file offset."""
        for seg in self._vas_segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.file_offset + (va - seg.vaddr)
        return None

    def va_to_vas_offset(self, va: int) -> "int | None":
        """Translate a virtual address to a flat VAS offset."""
        for idx, seg in enumerate(self._vas_segments):
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                return self._vas_cum[idx] + (va - seg.vaddr)
        return None

    # -- Metadata -----------------------------------------------------------

    def metadata(self) -> Dict[str, Any]:
        info = self._reader.info if self._reader._mmap is not None else None  # noqa: SLF001
        segments = info.segments if info else []
        file_mappings = info.file_mappings if info else []
        modules = [
            {"start": m.start, "end": m.end, "path": m.path}
            for m in file_mappings
        ]
        return {
            "format": self.format_name,
            "path": str(self._path),
            "pid": info.pid if info else None,
            "region_count": len(segments),
            "vas_size": sum(s.memsz for s in segments),
            "raw_size": self._stat_size(),
            "modules": modules,
        }


# -- module-local helpers ----------------------------------------------------


def _find_all_in_bytes(data: bytes, needle: bytes) -> List[int]:
    if not needle:
        return []
    offsets: List[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def _find_first_in_bytes(data: bytes, needle: bytes) -> Optional[int]:
    """Presence-only search; ``None`` when absent.

    Empty-needle handling matches :func:`_find_all_in_bytes` above (which
    returns no hits rather than one per byte), so ``find_first`` stays in
    agreement with ``find_all[0]`` for every needle.
    """
    if not needle:
        return None
    # Explicit start required: despite the ``_in_bytes`` name, the raw-view
    # caller passes the LIVE mmap from ``_reader_raw_bytes()`` (documented there
    # as deliberate, to avoid copying a multi-GB core). ``mmap.find(sub)``
    # defaults to the mapping's current position, so without the 0 this returns
    # "absent" for a present needle after any read that moved it. See
    # ``core.dump_io.find_first_offset`` for the full reasoning.
    idx = data.find(needle, 0)
    return None if idx == -1 else idx
