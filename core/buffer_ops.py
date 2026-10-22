"""Buffer-agnostic byte operations for analysis code.

Single-dump algorithms receive ``dump_data`` that is usually ``bytes`` but may
be a read-only :class:`mmap.mmap` when the dump is too large to copy onto the
heap (see :mod:`memdiver.app.pipeline.analysis_buffer`). The two types share
``find``, ``re`` support, ``np.frombuffer``, ``len``, int indexing and slicing
(slices return ``bytes``), but NOT substring membership: ``needle in mm`` on an
mmap (or memoryview) silently iterates ints and returns ``False`` instead of
raising, so a key that IS present would be reported missing.

Use :func:`contains_bytes` instead of ``needle in buf`` wherever ``buf`` may be
a dump buffer.
"""

from __future__ import annotations

from typing import Any


def contains_bytes(buffer: Any, needle: bytes) -> bool:
    """Return True iff *needle* occurs in *buffer* (``bytes`` or ``mmap``).

    Same semantics as ``needle in buffer`` for ``bytes`` (an empty needle is
    always contained), and correct for ``mmap``/``bytearray``. A buffer type
    without ``find`` (e.g. ``memoryview``) is converted to ``bytes`` first.
    """
    finder = getattr(buffer, "find", None)
    if finder is None:
        return bytes(buffer).find(needle) != -1
    return finder(needle) != -1
