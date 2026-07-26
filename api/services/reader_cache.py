"""Backward-compatible shim for the relocated MslReader cache.

The process-wide MslReader LRU cache moved DOWN into the ``app`` layer —
:mod:`memdiver.app.reader_cache` — so the ``app`` producers (xref /
key-material) no longer import UP into ``api/services`` to reach it. That
inverted dependency is what this relocation removes.

This module is retained as a re-export shim so any external importer of
``memdiver.api.services.reader_cache`` keeps working unchanged. Every name
below is the SAME object defined in :mod:`memdiver.app.reader_cache` — in
particular the singleton accessors operate on the ONE process-wide cache that
lives in that module, so callers reaching the cache through this shim and
callers reaching it directly share a single instance.
"""

from __future__ import annotations

from memdiver.app.reader_cache import (
    DEFAULT_MAX_SIZE,
    MslReaderCache,
    cached_dump_source,
    cached_msl_reader,
    get_default_cache,
    key_material_scope,
    set_default_cache,
    shutdown_default_cache,
)

__all__ = [
    "DEFAULT_MAX_SIZE",
    "MslReaderCache",
    "cached_dump_source",
    "cached_msl_reader",
    "get_default_cache",
    "key_material_scope",
    "set_default_cache",
    "shutdown_default_cache",
]
