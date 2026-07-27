"""Decryption key-material helpers for MCP dump-opening tools.

Mirrors ``cli._key_material_from_args`` so the MCP surface can read
encrypted ``.msl`` containers (spec §10). The unkeyed fast path keeps
using the shared reader cache (``memdiver.app.reader_cache``); the keyed
path bypasses the cache — which cannot carry key material — and opens the
container directly with the supplied key/passphrase/KEM private key.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional


def key_material_kwargs(
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> dict:
    """Turn MCP decryption params into ``open_dump(**kw)`` kwargs.

    Thin surface adapter over :func:`core.key_material.from_files`; keeps the
    app/MCP public name and always returns ``{"key", "passphrase",
    "kem_private_key"}`` with every value ``None`` when no param was supplied.
    """
    from memdiver.core.key_material import from_files
    return from_files(key_file, passphrase, kem_key_file)


def has_key_material(km: dict) -> bool:
    """True if any decryption material is present in a kwargs dict."""
    return any(v is not None for v in km.values())


@contextmanager
def open_dump_source(path: str, km: dict) -> Iterator[object]:
    """Yield an opened DumpSource, honouring decryption key material.

    With key material we open the container directly (the reader cache
    cannot carry keys); without it we keep the cached fast path used by
    the unkeyed inspect tools. Both branches yield an already-opened
    source and close it on exit.
    """
    from memdiver.app.reader_cache import cached_dump_source
    from memdiver.core.dump_source import open_dump

    if has_key_material(km):
        source = open_dump(Path(path), **km)
        source.open()
        try:
            yield source
        finally:
            source.close()
    else:
        with cached_dump_source(Path(path)) as source:
            yield source


@contextmanager
def open_msl_reader(path: str, km: dict) -> Iterator[object]:
    """Yield an opened MslReader, honouring decryption key material.

    Keyed opens construct a fresh ``MslReader`` with the key material;
    unkeyed opens reuse the shared cache.
    """
    from memdiver.app.reader_cache import cached_msl_reader

    if has_key_material(km):
        from memdiver.msl.reader import MslReader

        with MslReader(Path(path), **km) as reader:
            yield reader
    else:
        with cached_msl_reader(Path(path)) as reader:
            yield reader
