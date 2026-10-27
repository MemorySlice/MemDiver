"""DumpSearcher - search binary dump files for key bytes."""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .models import TLSSecret, KeyOccurrence

logger = logging.getLogger("memdiver.dump_search")


class DumpSearcher:
    """Search binary dump files for key bytes."""

    def __init__(self, dump_path: Path):
        self.path = dump_path
        self.data: Optional[bytes] = None

    def load(self) -> None:
        with open(self.path, "rb") as f:
            self.data = f.read()

    def find_all(self, needle: bytes) -> List[int]:
        if self.data is None:
            self.load()
        assert self.data is not None  # nosec B101 — load() sets self.data (bytes) or raises; narrows Optional for mypy
        offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    def extract_context(self, offset: int, key_len: int, ctx: int = 0x100) -> Tuple[bytes, bytes, bytes]:
        if self.data is None:
            self.load()
        assert self.data is not None  # nosec B101 — load() sets self.data (bytes) or raises; narrows Optional for mypy
        file_len = len(self.data)

        before_start = max(0, offset - ctx)
        before = self.data[before_start:offset]
        if len(before) < ctx:
            before = b'\x00' * (ctx - len(before)) + before

        key_bytes = self.data[offset:offset + key_len]

        after_end = min(file_len, offset + key_len + ctx)
        after = self.data[offset + key_len:after_end]
        if len(after) < ctx:
            after = after + b'\x00' * (ctx - len(after))

        return before, key_bytes, after

    def search_secrets(self, secrets: List[TLSSecret], ctx: int = 0x100) -> List[KeyOccurrence]:
        if self.data is None:
            self.load()
        occurrences = []
        for secret in secrets:
            offsets = self.find_all(secret.secret_value)
            for offset in offsets:
                before, key_bytes, after = self.extract_context(offset, len(secret.secret_value), ctx)
                occurrences.append(KeyOccurrence(
                    offset=offset,
                    secret=secret,
                    context_before=before,
                    key_bytes=key_bytes,
                    context_after=after,
                ))
        return occurrences


# -- Multi-needle presence (one pass per dump, not one per needle) ------------

#: Window size for the contiguous (``"raw"``) strategy. Matches the VA search
#: window, so both strategies walk a dump in the same-sized steps.
_PRESENCE_WINDOW = 8 * 1024 * 1024


def present_needles(source: Any, needles: Iterable[bytes], view: str,
                    find_first: Callable[[bytes], bool]) -> Set[bytes]:
    """The subset of *needles* that occur at least once in *source*'s *view*.

    Answers the SAME question as asking ``find_first(needle)`` for every
    needle, but reads the dump once instead of once per needle: each window is
    fetched (decoded, for ``.msl``) a single time and every still-unfound
    needle is checked against it while it is hot. A needle is dropped from the
    working set at its first hit, because presence is all that is asked.

    Exactness is by construction, not by approximation: each strategy below
    walks EXACTLY the byte ranges the source's own ``find_all`` searches for
    that view, so the answer cannot differ from the per-needle one.

    * ``"raw"`` on a mmap-backed source (raw, gdb/lldb raw, gcore, the ``.msl``
      container): one contiguous buffer. Window ``k`` asks ``buf.find(needle,
      start, start + W + len(needle) - 1)``, so a match straddling a window
      boundary is found in the window it STARTS in, and in no other.
    * ``"va"`` on an ``.msl`` source: the source's own captured-window walk,
      run once per distinct needle LENGTH (its windows and its short-run skip
      depend on the length), so every needle sees the windows it always saw.
    * anything else (unknown source or view): *find_first* per needle -- the
      caller's original per-needle path, unchanged.

    :param find_first: the caller's per-needle presence query, used verbatim
        as the fallback so unknown sources keep their exact old behaviour.
    """
    pending = _dedupe(needles)
    if not pending:
        return set()
    windows = _window_strategy(source, view)
    if windows is None:
        return {n for n in pending if find_first(n)}
    return windows(pending)


def _dedupe(needles: Iterable[bytes]) -> List[bytes]:
    return [n for n in dict.fromkeys(needles) if n]


def _window_strategy(source: Any, view: str
                     ) -> Optional[Callable[[List[bytes]], Set[bytes]]]:
    from .dump_source import MslDumpSource

    if view == "va" and isinstance(source, MslDumpSource):
        return lambda pending: _present_in_va_windows(source, pending)
    if view in ("va", "vas") and _is_image_view(source):
        return lambda pending: _present_in_captured_runs(source, pending)
    if view == "raw":
        buf = _raw_view_buffer(source)
        if buf is not _NO_BUFFER:
            return lambda pending: _present_in_buffer(buf, pending)
    return None


#: Sentinel: the source's raw view is not a known contiguous mmap.
_NO_BUFFER: Any = object()


def _raw_view_buffer(source: Any) -> Any:
    """The exact buffer ``source.find_all(..., view="raw")`` searches, opened.

    ``None``/``b""`` (an empty or unmapped file) is a real, empty buffer;
    :data:`_NO_BUFFER` means "unknown source -- use the fallback".
    """
    from .dump_source import MslDumpSource, RawDumpSource
    from .dump_sources._regioned_base import _RegionedRawSource
    from .dump_sources.gcore import GCoreDumpSource

    if isinstance(source, MslDumpSource):
        return source._ensure_raw_reader()._mmap  # noqa: SLF001
    if isinstance(source, (RawDumpSource, _RegionedRawSource, GCoreDumpSource)):
        source._ensure_open()  # noqa: SLF001
        return source._reader._mmap  # noqa: SLF001
    return _NO_BUFFER


def _present_in_buffer(buf: Any, pending: List[bytes]) -> Set[bytes]:
    found: Set[bytes] = set()
    if not buf:
        return found
    size = len(buf)
    for start in range(0, size, _PRESENCE_WINDOW):
        for needle in pending:
            if needle not in found and buf.find(
                    needle, start, start + _PRESENCE_WINDOW + len(needle) - 1) != -1:
                found.add(needle)
        if len(found) == len(pending):
            break
    return found


def _is_image_view(source: Any) -> bool:
    from .image.sources import Vol3LayerSource

    return isinstance(source, Vol3LayerSource)


def _present_in_captured_runs(source: Any, pending: List[bytes]) -> Set[bytes]:
    """Image views: ``Vol3LayerSource.find_all`` matches inside ONE captured run
    (never across a gap), in ``"va"`` and ``"vas"`` alike, so walk each run once
    through the packed ``"vas"`` stream, windows overlapping by the longest
    needle, never reading past the run's end."""
    found: Set[bytes] = set()
    overlap = max(len(n) for n in pending) - 1
    for _va, length, vas_offset in source.captured_runs():
        for start in range(0, length, _PRESENCE_WINDOW):
            size = min(_PRESENCE_WINDOW + overlap, length - start)
            data = source.read_range(vas_offset + start, size, view="vas")
            found.update(n for n in pending if n not in found and n in data)
            if len(found) == len(pending):
                return found
    return found


def _present_in_va_windows(source: Any, pending: List[bytes]) -> Set[bytes]:
    found: Set[bytes] = set()
    by_length: Dict[int, List[bytes]] = {}
    for needle in pending:
        by_length.setdefault(len(needle), []).append(needle)
    for length, group in by_length.items():
        left = list(group)
        for _offset, data in source._iter_va_captured_windows(length):  # noqa: SLF001
            left = [n for n in left if data.find(n) == -1]
            if not left:
                break
        found.update(n for n in group if n not in left)
    return found
