"""Module-level cache for opened MslReader instances.

Motivation
----------
Every MCP tool call and every `/api/inspect` HTTP call that reads an MSL
file used to create a fresh `MslReader` — which does a fresh mmap of the
file, parses the 64-byte file header, and primes its 8 per-block-type
caches lazily on first access. For an AI-driven investigation session
that issues 20 tool calls against the same dump, that is 20 redundant
mmaps, 20 re-reads of the file header, and 20 rebuilds of the block
cache. All of them throwaway — the reader was `close()`d at the end of
the `with` block and every subsequent call started over.

This module keeps the opened readers alive across calls so that the
second call against the same path reuses the hot page cache, the hot
block scan, and the live mmap.

Design (see `.claude-work/plans/curried-jumping-lantern.md` → PR 3):

- **Path-keyed, module-level, shared by MCP and HTTP.** Not on
  `ToolSession` — session is a connection-lifetime object, but dump
  lifetime is longer. A single process-wide cache lets MCP and HTTP
  callers warm each other up.
- **In-process only, never crosses a process boundary.** A cached
  `MslReader` holds a live mmap fd, which cannot be pickled for
  ProcessPool serialization. This is fine: PR 2 settled that the only
  ProcessPool consumer (`BatchRunner`) does not share readers with the
  main process — it reopens in the worker. So the "readers live in the
  main process, algorithms cross the boundary with data not handles"
  model (from the architectural agent in the plan) is intact.
- **Bounded LRU with deferred close.** Cache has a `max_size` (default
  32). Eviction respects refcounts: an evicted entry whose `refcount > 0`
  is removed from the LRU map but deferred-closed on the caller's
  release. This closes the `close()-while-reading` race without needing
  a full reference-counting GC.
- **Immutability assumption.** We assume an MSL file is not mutated on
  disk after capture. This is the normal MSL lifecycle documented in
  `CLAUDE.md`. If a file is replaced, the cached reader will continue to
  serve the old content until eviction. Callers that care must call
  `invalidate(path)` explicitly.

Thread safety
-------------
`MslReader` reads are thread-safe: mmap is read-only, there is no
cursor state on the instance, `read_bytes` / `read_block_payload` /
`_parse_block_header` are all stateless. The one soft race is
`_collect()` lazy population — two threads racing on first access will
both walk the block stream and both assign the same cache slot; the
results are byte-identical so the only cost is duplicated work on first
call. No corruption.

The cache itself is guarded by a single `threading.Lock`. Acquire and
release are O(1). No lock is held during actual reader use.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from msl.reader import MslReader

logger = logging.getLogger("memdiver.api.services.reader_cache")

DEFAULT_MAX_SIZE = 32


class _CacheEntry:
    """Single cache entry wrapping a live MslReader and its refcount."""

    __slots__ = ("reader", "refcount", "evicted")

    def __init__(self, reader: "MslReader") -> None:
        self.reader = reader
        self.refcount = 0
        self.evicted = False


class MslReaderCache:
    """Thread-safe, path-keyed LRU cache of opened MslReader instances."""

    def __init__(self, max_size: int = DEFAULT_MAX_SIZE) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self._max_size = max_size
        self._entries: "OrderedDict[str, _CacheEntry]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(path: Path) -> str:
        """Canonical cache key. Resolves symlinks so two paths pointing to
        the same file share a cache entry.
        """
        return str(Path(path).resolve())

    def _acquire(self, path: Path) -> tuple[str, _CacheEntry]:
        """Return the cache entry for `path`, creating it if absent.

        Increments the entry's refcount. Must be matched by `_release`.
        Called under self._lock.
        """
        from msl.reader import MslReader

        key = self._key(path)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                reader = MslReader(Path(path))
                reader.open()
                entry = _CacheEntry(reader)
                self._entries[key] = entry
                logger.debug("reader_cache: opened %s", key)
            else:
                self._entries.move_to_end(key)
                logger.debug("reader_cache: hit %s (refcount %d)", key, entry.refcount)
            entry.refcount += 1
            self._evict_over_capacity_locked()
            return key, entry

    def _release(self, key: str, entry: _CacheEntry) -> None:
        """Decrement an entry's refcount; close the reader if it was
        previously evicted and this is the last reference."""
        with self._lock:
            entry.refcount -= 1
            if entry.refcount <= 0 and entry.evicted:
                try:
                    entry.reader.close()
                    logger.debug(
                        "reader_cache: closed deferred-evicted entry for %s", key,
                    )
                except Exception as exc:  # pragma: no cover — belt-and-suspenders
                    logger.warning(
                        "reader_cache: close failed for %s: %s", key, exc,
                    )

    def _evict_over_capacity_locked(self) -> None:
        """Evict the oldest entries until len(self._entries) <= max_size.

        Entries in active use (refcount > 0) are removed from the LRU map
        but their readers are left open until the holder releases. This
        avoids a TOCTOU race where a reader is closed out from under a
        concurrent `read_*` call. Newly acquired entries (which are at the
        end of the OrderedDict) are never the eviction victim.
        """
        while len(self._entries) > self._max_size:
            key, entry = next(iter(self._entries.items()))
            del self._entries[key]
            if entry.refcount > 0:
                entry.evicted = True
                logger.debug(
                    "reader_cache: evicted %s (deferred close, refcount %d)",
                    key, entry.refcount,
                )
            else:
                try:
                    entry.reader.close()
                    logger.debug("reader_cache: evicted and closed %s", key)
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        "reader_cache: close failed during eviction for %s: %s",
                        key, exc,
                    )

    def invalidate(self, path: Path) -> bool:
        """Drop the cache entry for `path`, closing it if idle.

        Returns True if an entry existed, False otherwise. Use this when
        you know the underlying file has been replaced on disk.
        """
        key = self._key(path)
        with self._lock:
            entry = self._entries.pop(key, None)
            if entry is None:
                return False
            if entry.refcount > 0:
                entry.evicted = True
                logger.debug(
                    "reader_cache: invalidated %s (deferred close)", key,
                )
            else:
                try:
                    entry.reader.close()
                    logger.debug("reader_cache: invalidated and closed %s", key)
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        "reader_cache: close failed during invalidate for %s: %s",
                        key, exc,
                    )
            return True

    def shutdown(self) -> None:
        """Close all cached readers and clear the cache.

        Called from the FastAPI lifespan shutdown branch. Any entry with
        `refcount > 0` is flagged as evicted and its reader is left for
        the last holder to close on release — the same deferred-close
        contract used by normal eviction.
        """
        with self._lock:
            leaked = 0
            for key, entry in list(self._entries.items()):
                if entry.refcount > 0:
                    entry.evicted = True
                    leaked += 1
                    logger.warning(
                        "reader_cache: shutdown while in use — deferred close for "
                        "%s (refcount %d)",
                        key, entry.refcount,
                    )
                else:
                    try:
                        entry.reader.close()
                    except Exception as exc:  # pragma: no cover
                        logger.warning(
                            "reader_cache: close failed during shutdown for %s: %s",
                            key, exc,
                        )
            self._entries.clear()
            if leaked:
                logger.info(
                    "reader_cache: shutdown complete with %d deferred closes", leaked,
                )
            else:
                logger.debug("reader_cache: shutdown complete, all readers closed")

    def stats(self) -> Dict[str, object]:
        """Snapshot of current cache contents, for tests and diagnostics."""
        with self._lock:
            return {
                "size": len(self._entries),
                "max_size": self._max_size,
                "keys": list(self._entries.keys()),
                "refcounts": {k: e.refcount for k, e in self._entries.items()},
            }


# --- module-level singleton accessor -----------------------------------

_default_cache: Optional[MslReaderCache] = None
_default_cache_lock = threading.Lock()


def get_default_cache() -> MslReaderCache:
    """Return the process-wide MslReaderCache, creating it on first access."""
    global _default_cache
    with _default_cache_lock:
        if _default_cache is None:
            _default_cache = MslReaderCache()
        return _default_cache


def set_default_cache(cache: Optional[MslReaderCache]) -> None:
    """Replace the process-wide cache. Used by tests for isolation."""
    global _default_cache
    with _default_cache_lock:
        _default_cache = cache


def shutdown_default_cache() -> None:
    """Shut down and release the process-wide cache singleton."""
    global _default_cache
    with _default_cache_lock:
        if _default_cache is not None:
            _default_cache.shutdown()
            _default_cache = None


# --- public context managers -------------------------------------------


@contextmanager
def cached_msl_reader(path: Path) -> "Iterator[MslReader]":
    """Yield a cached MslReader for `path`. Auto-releases on context exit.

    Usage::

        with cached_msl_reader(path) as reader:
            hints = reader.collect_key_hints()

    The reader stays open in the cache after the `with` block exits, so
    subsequent calls against the same path skip the mmap + header parse.
    """
    cache = get_default_cache()
    key, entry = cache._acquire(path)
    try:
        yield entry.reader
    finally:
        cache._release(key, entry)


@contextmanager
def cached_dump_source(path: Path) -> Iterator[object]:
    """Yield a DumpSource for any dump path, caching MSL readers.

    For `.msl` inputs: yields a lightweight `MslDumpSource` whose
    underlying reader is borrowed from the module cache. The proxy's
    close is a no-op — the cache owns the reader lifecycle.

    For raw dumps: yields a normal `open_dump()` result, which wraps a
    `RawDumpSource` with its own lazy-open mechanism (no caching needed
    since raw opens are already cheap).
    """
    from core.dump_source import MslDumpSource, open_dump
    from msl.enums import FILE_MAGIC

    p = Path(path)
    is_msl = False
    try:
        with open(p, "rb") as f:
            is_msl = (f.read(8) == FILE_MAGIC)
    except OSError:
        # Let the downstream call surface a precise error.
        pass

    if not is_msl:
        source = open_dump(p)
        try:
            source.open()
            yield source
        finally:
            source.close()
        return

    with cached_msl_reader(p) as reader:
        # Borrow the cached reader via the explicit factory so close() is
        # a no-op on the proxy. The cache retains ownership; this source
        # is a view. See MslDumpSource.borrow_reader in core/dump_source.py.
        source = MslDumpSource.borrow_reader(p, reader)
        try:
            yield source
        finally:
            source.close()  # no-op (borrowed) — detaches the view
