"""Hashing utilities for MSL integrity, cross-references, and block chains.

Provides a single home for the blake3-preferred / sha256-fallback dance so
writer, xref_resolver, and integrity modules don't each ship their own copy.
"""

from typing import Iterable

try:
    import blake3 as _blake3

    def _new_hasher():
        return _blake3.blake3()

    def hash_bytes(data: bytes) -> bytes:
        return _blake3.blake3(data).digest()
except ImportError:
    import hashlib

    def _new_hasher():
        return hashlib.sha256()

    def hash_bytes(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


def hash_stream(chunks: Iterable[bytes]) -> bytes:
    """Hash a stream of byte chunks without materializing the full input."""
    hasher = _new_hasher()
    for chunk in chunks:
        if chunk:
            hasher.update(chunk)
    return hasher.digest()


def hash_file(path, chunk_size: int = 1 << 20) -> bytes:
    """Hash a file via chunked reads. Default chunk size is 1 MiB."""
    hasher = _new_hasher()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.digest()
