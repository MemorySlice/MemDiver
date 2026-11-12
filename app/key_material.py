"""Decryption key-material helpers for MCP dump-opening tools.

Mirrors ``cli._key_material_from_args`` so the MCP surface can read
encrypted ``.msl`` containers (spec §10). The unkeyed fast path keeps
using the shared reader cache (``memdiver.app.reader_cache``); the keyed
path bypasses the cache — which cannot carry key material — and opens the
container directly with the supplied key/passphrase/KEM private key.

:class:`KeyedSources` pools those keyed opens for ONE run (one synthesis
reads the same dumps several times) and :func:`probe_dump_key` checks a key
without opening the dump at all (the preflight of a background job).
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NamedTuple, Optional


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
def open_dump_source(path: str, km: dict,
                     region_filter: object = None) -> Iterator[object]:
    """Yield an opened DumpSource, honouring decryption key material.

    With key material we open the container directly (the reader cache
    cannot carry keys); without it we keep the cached fast path used by
    the unkeyed inspect tools. Both branches yield an already-opened
    source and close it on exit.

    ``region_filter`` (``RegionSelection`` / spec / ``to_note()`` string)
    applies the analysis-time region view filter to sources that support
    one (``.msl``); ``None`` leaves the source unfiltered, exactly as before.
    The cached branch yields a fresh per-call proxy around the pooled
    reader, so filtering it never leaks into another caller's view.
    """
    from memdiver.app.reader_cache import cached_dump_source

    if has_key_material(km):
        source = _open_keyed(path, km, region_filter)
        try:
            yield source
        finally:
            source.close()
    else:
        with cached_dump_source(Path(path)) as source:
            _apply_view_filter(source, region_filter)
            yield source


def _open_keyed(path: object, km: dict, region_filter: object = None) -> object:
    """A fresh, uncached, OPENED source built with key material; the caller closes it."""
    from memdiver.core.dump_source import open_dump

    source = open_dump(Path(path), region_filter=region_filter, **km)
    try:
        source.open()
    except BaseException:
        source.close()  # a half-open reader (file/mmap mapped, header refused)
        raise
    return source


def _apply_view_filter(source: object, region_filter: object) -> None:
    """Set *region_filter* on *source* when given and supported."""
    if region_filter is None:
        return
    setter = getattr(source, "set_region_filter", None)
    if callable(setter):
        setter(region_filter)


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


class KeyedSources:
    """Run-scoped pool: each KEYED dump is opened (and decrypted) once.

    A keyed ``.msl`` open is a full pass over the ciphertext (one AEAD tag at
    the end of the file), so one synthesis that checks, locates and reads
    windows from the same N dumps must not decrypt each of them 4 or 5 times.
    With key material, :meth:`source` and :meth:`opener` open a path on first
    use (exactly as :func:`open_dump_source`'s keyed branch does) and hand out
    that SAME open source afterwards; :meth:`close` (or leaving the ``with``
    block, also on an exception) closes them all. Without key material
    nothing is pooled: :meth:`source` is :func:`open_dump_source` (the shared
    LRU cache) and :meth:`opener` is plain ``open_dump``, as before.

    Never let a pool outlive one request / job: keyed opens stay uncached
    ACROSS requests (``app.composition``'s keyed -> uncached invariant). A
    pooled source is shared, so a consumer must not change its state (no
    ``set_region_filter``); :meth:`opener` gives a call that asks for other
    key material or a region filter a fresh ``open_dump`` instead.
    """

    def __init__(self, km: dict) -> None:
        self._km = dict(km)
        self._keyed = has_key_material(self._km)
        self._open: dict = {}

    def __enter__(self) -> "KeyedSources":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close every pooled source (each one, even when an earlier close raises)."""
        from contextlib import ExitStack

        opened, self._open = list(self._open.values()), {}
        with ExitStack() as closing:
            for source in opened:
                closing.callback(source.close)

    @contextmanager
    def source(self, path: object) -> Iterator[object]:
        """Yield the opened source of *path*: pooled when keyed, else the cached path."""
        if not self._keyed:
            with open_dump_source(str(path), self._km) as source:
                yield source
            return
        yield self._pooled(path)

    def opener(self, path: object, **open_kwargs: object) -> object:
        """``core.dump_source.open_dump``'s call shape, for an ``opener=`` parameter.

        ``with pool.opener(path, **km) as source:`` yields the pooled source
        and leaves it open. Unkeyed, or called with other kwargs than the
        pool's key material, it IS ``open_dump(path, **open_kwargs)``.
        """
        from contextlib import nullcontext

        from memdiver.core.dump_source import open_dump

        if not self._keyed or open_kwargs != self._km:
            return open_dump(Path(path), **open_kwargs)
        return nullcontext(self._pooled(path))

    def _pooled(self, path: object) -> object:
        slot = Path(str(path)).expanduser().resolve()
        source = self._open.get(slot)
        if source is None:
            source = self._open[slot] = _open_keyed(path, self._km)
        return source


class ProbedKey(NamedTuple):
    """A dump's key state learnt WITHOUT opening it (:func:`probe_dump_key`).

    Carries ``tag_status`` like an opened source, so the one lock guard
    (``app.composition.raise_if_locked``) reads it and refuses with the very
    same error and hint.
    """

    tag_status: object


def probe_dump_key(path: object, km: dict) -> ProbedKey:
    """The key state of the dump at *path*, without opening (or decrypting) it.

    The format is told by ``open_dump``'s own detection (its detector registry;
    the source it returns is never opened). Only an ``.msl`` container is
    probed, by ``msl.reader.probe_key``: one key derivation and the first
    cipher block, no full AEAD pass -- so a ciphertext tampered beyond block 0
    still probes VALID. Every other format is NOT_ENCRYPTED.
    """
    from memdiver.core.dump_source import MslDumpSource, open_dump
    from memdiver.msl.enums import TagStatus
    from memdiver.msl.reader import probe_key

    if not isinstance(open_dump(Path(str(path)), **km), MslDumpSource):
        return ProbedKey(TagStatus.NOT_ENCRYPTED)
    return ProbedKey(probe_key(Path(str(path)), **km))
