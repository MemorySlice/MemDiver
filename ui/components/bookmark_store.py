"""Bookmark storage for the hex viewer."""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("memdiver.ui.components.bookmark_store")


@dataclass
class Bookmark:
    """A single bookmark marking a region in a memory dump."""

    offset: int
    length: int = 1
    label: str = ""
    color: str = ""


class BookmarkStore:
    """Plain Python state container for hex viewer bookmarks."""

    def __init__(self) -> None:
        self.bookmarks: List[Bookmark] = []

    def add(self, offset: int, length: int = 1, label: str = "") -> Bookmark:
        """Add a bookmark, replacing any existing one at the same offset."""
        self.remove(offset)
        bm = Bookmark(offset=offset, length=length, label=label)
        self.bookmarks.append(bm)
        logger.debug("added bookmark at offset %d (length=%d)", offset, length)
        return bm

    def remove(self, offset: int) -> bool:
        """Remove bookmark at offset. Returns True if found."""
        before = len(self.bookmarks)
        self.bookmarks = [b for b in self.bookmarks if b.offset != offset]
        removed = len(self.bookmarks) < before
        if removed:
            logger.debug("removed bookmark at offset %d", offset)
        return removed

    def get_at(self, offset: int) -> Optional[Bookmark]:
        """Get bookmark at exact offset."""
        for bm in self.bookmarks:
            if bm.offset == offset:
                return bm
        return None

    def get_in_range(self, start: int, end: int) -> List[Bookmark]:
        """Get all bookmarks with offset in [start, end)."""
        return [b for b in self.bookmarks if start <= b.offset < end]

    def clear(self) -> None:
        """Remove all bookmarks."""
        count = len(self.bookmarks)
        self.bookmarks.clear()
        logger.debug("cleared %d bookmarks", count)

    def to_highlight_offsets(self) -> set:
        """Return set of all bookmarked offsets for hex_renderer compatibility.

        Each bookmark expands to cover ``offset`` through
        ``offset + length - 1``.
        """
        offsets: set = set()
        for bm in self.bookmarks:
            for i in range(bm.length):
                offsets.add(bm.offset + i)
        return offsets
