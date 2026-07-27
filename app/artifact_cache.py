"""Run-scoped reference-bytes cache + read-only variance mmap (P1.5).

The web pipeline runs consensus -> search_reduce -> brute_force -> (escalate) ->
emit_plugin *sequentially in one process*. Three stages re-opened and re-read the
same multi-hundred-MB ``reference.bin``, and the variance stages fully
materialized ``variance.npy``. This module removes both redundancies:

* :func:`mmapped_variance` maps ``variance.npy`` read-only so a consumer that only
  masks / slices / copies it never allocates a full float32 buffer. The mmap fd is
  closed on context exit -- **no array view may escape the block** (reading a
  memmap after its fd closes segfaults the interpreter, it does not raise).

* :func:`reference_cache_scope` + :func:`cache_reference_bytes` cache plaintext
  reference bytes for the duration of ONE run, keyed by ``(path, mtime_ns, size)``
  so the reading stages share a single read. The scope resets on exit, so a reused
  ProcessPool worker never retains the previous run's blob. With no active scope
  the cache is a pure no-op -- the CLI (process per stage) and MCP (stage per
  call) stay byte-identical.

Secrets never enter the cache: the sole caller
(``tools_pipeline._read_reference_bytes``) routes only a PLAINTEXT, non-observed
read here (key material or an ``on_source`` hook both bypass to a direct load).
"""

from __future__ import annotations

import contextlib
import contextvars
import os
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional, Tuple

import numpy as np

# Active per-run cache, or None when no scope is open. Keyed by
# (resolved_path, st_mtime_ns, st_size) so a rewrite within a live scope is
# never served stale.
_REFERENCE_CACHE_VAR: "contextvars.ContextVar[Optional[Dict[Tuple[str, int, int], bytes]]]" = (
    contextvars.ContextVar("memdiver_reference_cache", default=None)
)


@contextlib.contextmanager
def mmapped_variance(path: str) -> Iterator[np.ndarray]:
    """Yield ``variance.npy`` as a read-only memmap; close the fd on exit.

    The yielded array is a ``numpy.memmap`` (float32 for consensus output).
    Consumers must only READ or COPY it inside the block: ``reduce_search_space``
    produces fresh mask arrays and Python-float scalars, and ``recommended_floor``
    / ``run_auto_floor`` ``asarray(dtype=float64)``-copy it -- none retain a view.
    Reading the array after this context exits segfaults the interpreter, so all
    variance-touching compute must complete inside the block.
    """
    arr = np.load(path, mmap_mode="r")
    try:
        yield arr
    finally:
        mm = getattr(arr, "_mmap", None)
        if mm is not None:
            mm.close()


@contextlib.contextmanager
def reference_cache_scope() -> Iterator[None]:
    """Open a run-scoped reference-bytes cache; reset (drop) it on exit.

    Nesting reuses the outer scope (an inner ``with`` neither shadows nor clears
    it and does not reset it on exit), so wrapping ``run_pipeline`` is idempotent.
    On exit the ContextVar is reset to its prior value, dereferencing the cached
    blob so a reused worker never retains a previous run's bytes.
    """
    if _REFERENCE_CACHE_VAR.get() is not None:
        yield
        return
    token = _REFERENCE_CACHE_VAR.set({})
    try:
        yield
    finally:
        _REFERENCE_CACHE_VAR.reset(token)


def cache_reference_bytes(path: str, loader: Callable[[], bytes]) -> bytes:
    """Return reference bytes, served from the active run scope when possible.

    With no scope active this is exactly ``loader()`` -- no caching, no stat call.
    With a scope active the bytes are keyed by ``(resolved_path, mtime_ns, size)``:
    a hit returns the shared blob; a miss calls ``loader()`` and stores it. The
    stat key means a rewritten reference (different mtime/size) is reloaded, never
    served stale.
    """
    cache = _REFERENCE_CACHE_VAR.get()
    if cache is None:
        return loader()
    resolved = str(Path(path).resolve())
    try:
        st = os.stat(resolved)
    except OSError:
        # Missing/racing file -- let the loader surface the real error.
        return loader()
    key = (resolved, st.st_mtime_ns, st.st_size)
    hit = cache.get(key)
    if hit is not None:
        return hit
    data = loader()
    cache[key] = data
    return data
