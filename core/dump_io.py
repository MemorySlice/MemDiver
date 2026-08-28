"""DumpReader with mmap for memory-mapped dump file access."""

import logging
import mmap
import re
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("memdiver.dump_io")


def find_all_offsets(buf, needle: bytes) -> List[int]:
    """Return every offset of *needle* in *buf*, including overlapping matches.

    Works over anything supporting ``.find(needle, start)`` (``bytes`` or an
    ``mmap`` object). Overlapping matches are preserved by advancing the
    search cursor by one byte past each hit (``start = idx + 1``).

    An EMPTY needle returns ``[]``. This guard is load-bearing, not defensive
    tidiness: ``mmap.find(b"", start)`` CLAMPS an out-of-range ``start`` to the
    buffer length instead of returning ``-1`` (verified: on a 300-byte mapping
    ``mm.find(b"", 999)`` is ``300``), so the ``start = idx + 1`` cursor can
    never escape and the loop appends the same offset forever -- an unbounded
    hang plus unbounded memory growth. ``bytes`` happens to terminate on the
    same input, so the failure only reproduces on the mmap-backed sources
    (:class:`DumpReader`, and via it ``RawDumpSource``/``MslDumpSource``), which
    are exactly the ones a corpus sweep uses. Searching for nothing is a caller
    error rather than a meaningful query, so both this and
    :func:`find_first_offset` report "no match" instead of the degenerate
    every-offset answer -- and they agree, so the two can be swapped freely.
    """
    if not needle:
        return []
    offsets: List[int] = []
    start = 0
    while True:
        idx = buf.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def find_first_offset(buf, needle: bytes) -> Optional[int]:
    """Return the FIRST offset of *needle* in *buf*, or ``None`` when absent.

    Works over anything supporting ``.find(needle)`` (``bytes`` or an ``mmap``
    object). The presence-only counterpart of :func:`find_all_offsets`: a single
    ``.find()`` that stops at the first hit instead of scanning to EOF, which is
    what a "does this secret appear in this dump at all?" query over a
    corpus-scale (multi-hundred-GB) sweep needs.

    An EMPTY needle returns ``None``, agreeing with :func:`find_all_offsets`'s
    ``[]`` so the two can be swapped freely (a caller cannot get "present" from
    one and "absent" from the other for the same input). Searching for nothing
    is a caller error, not a query with a degenerate answer: reporting offset
    ``0`` would let an empty secret masquerade as a hit at the start of every
    dump in a corpus sweep, which is a false positive in the one place that is
    most expensive to notice. See :func:`find_all_offsets` for why the
    every-offset reading is also unsafe on an ``mmap``.
    """
    if not needle:
        return None
    # The explicit start is REQUIRED, not stylistic. ``mmap.find(sub)`` defaults
    # its start to the mmap's CURRENT FILE POSITION, not 0 -- unlike
    # ``bytes.find``, which has no position. So after anything that advances the
    # mapping (``read_all()`` is the common one) a bare ``buf.find(needle)``
    # searches only the tail and returns -1 for a needle that IS present, which
    # this function then reports as "absent". Verified on a real corpus dump: a
    # secret at offset 585148 was found by ``find_all`` and reported missing by
    # ``find_first`` once ``read_all()`` had run. ``find_all_offsets`` was never
    # exposed to it because it always passes ``start``.
    idx = buf.find(needle, 0)
    return None if idx == -1 else idx


class DumpReader:
    """Memory-mapped dump file reader for efficient scanning.

    Uses mmap to map dump files into virtual memory without loading
    the entire file. The re module operates directly on mmap objects
    for pattern scanning at C-speed.
    """

    def __init__(self, path: Path):
        self.path = path
        self._mmap: Optional[mmap.mmap] = None
        self._file = None

    def open(self) -> None:
        """Memory-map the dump file for reading."""
        self._file = open(self.path, "rb")
        size = self.path.stat().st_size
        if size == 0:
            logger.warning("Empty dump file: %s", self.path)
            self._mmap = None
            return
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        logger.debug("Mapped %d bytes from %s", size, self.path.name)

    def close(self) -> None:
        """Release the memory mapping."""
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def data(self) -> Optional[mmap.mmap]:
        """The underlying mmap object (or None if empty/closed)."""
        return self._mmap

    @property
    def size(self) -> int:
        """Size of the mapped file in bytes."""
        return len(self._mmap) if self._mmap else 0

    def read_all(self) -> bytes:
        """Read the entire file into memory as bytes."""
        if self._mmap is None:
            return b""
        self._mmap.seek(0)
        return self._mmap.read()

    def read_range(self, offset: int, length: int) -> bytes:
        """Read a specific byte range from the mapped file."""
        if self._mmap is None:
            return b""
        # Reject negative offset/length: a negative offset would otherwise
        # index from the file tail (Python negative slicing) and return
        # wrong-region bytes for adversarial inputs. Mirrors the guard in
        # ElfCoreReader.read_at / GCoreDumpSource.read_at.
        if offset < 0 or length <= 0:
            return b""
        end = min(offset + length, len(self._mmap))
        return self._mmap[offset:end]

    def find_all(self, needle: bytes) -> List[int]:
        """Find all occurrences of needle in the mapped file."""
        if self._mmap is None:
            return []
        return find_all_offsets(self._mmap, needle)

    def find_first(self, needle: bytes) -> Optional[int]:
        """Find the first occurrence of needle in the mapped file.

        Returns ``None`` when the needle is absent (or the file is empty /
        unmapped). Early-exits on the first hit - see
        :func:`find_first_offset`, including its empty-needle note.
        """
        if self._mmap is None:
            return None
        return find_first_offset(self._mmap, needle)

    def regex_scan(self, pattern: bytes, max_matches: int = 0) -> List[Tuple[int, int, bytes]]:
        """Scan the mapped file with a regex pattern.

        Args:
            pattern: Compiled or raw regex pattern (bytes).
            max_matches: Maximum matches to return (0 = unlimited).

        Returns:
            List of (offset, length, matched_bytes) tuples.
        """
        if self._mmap is None:
            return []
        compiled = re.compile(pattern) if isinstance(pattern, bytes) else pattern
        results = []
        for m in compiled.finditer(self._mmap):
            results.append((m.start(), m.end() - m.start(), m.group()))
            if max_matches and len(results) >= max_matches:
                break
        return results
