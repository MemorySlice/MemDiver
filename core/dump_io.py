"""DumpReader with mmap for memory-mapped dump file access."""

import logging
import mmap
import re
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("memdiver.dump_io")


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
        end = min(offset + length, len(self._mmap))
        return self._mmap[offset:end]

    def find_all(self, needle: bytes) -> List[int]:
        """Find all occurrences of needle in the mapped file."""
        if self._mmap is None:
            return []
        offsets = []
        start = 0
        while True:
            idx = self._mmap.find(needle, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

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
