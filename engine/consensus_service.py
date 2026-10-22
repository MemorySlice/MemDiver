"""Shared open-and-build core for consensus construction.

The CLI, the HTTP API, and the MCP server all need the same three-step
skeleton to compute a per-byte consensus variance vector: open every dump
as a context-managed :class:`~memdiver.core.dump_source.DumpSource`, build a
:class:`~memdiver.engine.consensus.ConsensusVector` from those opened sources,
then close the sources once the vector has captured its own copies of the
variance and reference bytes. This module owns that skeleton so the three
call sites cannot drift apart again.

Deliberately *not* included here: the per-caller pre-checks (``< 2`` dumps,
empty-vector detection), key-material decoding, and the region/artifact/session
shaping of the result. Each caller keeps those so its observable output — error
messages, HTTP bodies, written artifacts, stderr warnings — stays
byte-identical. This module is purely open + (optional per-source hook) + build.

The one exception is the *type* of a missing-file failure. Opening is what
raises it, so translating it is this module's job, not each caller's: a bare
``FileNotFoundError`` out of ``core.dump_io`` is not a ``CapabilityError``, so
it bypassed the API's global error funnel entirely and surfaced as a 500 with a
full traceback instead of a 404. See :func:`open_consensus_sources`.

Base-dependency only: importing this module pulls in neither FastAPI, the MCP
server, nor any UI framework.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, List, Mapping, Optional, Sequence, Union

from memdiver.core.dump_source import DumpSource, open_dump
from memdiver.core.service_errors import FileNotFoundServiceError
from memdiver.engine.consensus import ConsensusVector

__all__ = ["open_consensus_sources", "build_consensus"]

PathLike = Union[str, Path]


@contextmanager
def open_consensus_sources(
    paths: Sequence[PathLike],
    key_material: Optional[Mapping[str, Any]] = None,
    region_filter: Any = None,
) -> Iterator[List[DumpSource]]:
    """Open every dump path as a context-managed source and yield the list.

    Each path is opened via :func:`~memdiver.core.dump_source.open_dump`,
    forwarding ``**(key_material or {})`` so encrypted ``.msl`` containers are
    decrypted when key material is supplied. Entering the source (via the
    :class:`~contextlib.ExitStack`) is what actually opens it — an unopened
    ``MslDumpSource`` raises when read — and the stack guarantees every source
    is closed on exit, including on error.

    :param paths: Dump file paths to open, in order.
    :param key_material: Optional ``open_dump`` keyword arguments (e.g.
        ``key`` / ``passphrase`` / ``kem_private_key``); ``None`` opens
        unencrypted.
    :param region_filter: Optional analysis-time region view filter
        (``RegionSelection`` / ``"heap,stack"`` / ``to_note()`` string),
        forwarded to ``open_dump``. Honoured by ``.msl`` sources only; other
        formats ignore it (see :func:`memdiver.core.dump_source.open_dump`).
    :yields: The opened sources, one per input path, in the same order.
    """
    km = key_material or {}
    with ExitStack() as stack:
        try:
            sources: List[DumpSource] = [
                stack.enter_context(
                    open_dump(Path(p), region_filter=region_filter, **km))
                for p in paths
            ]
        except FileNotFoundError as exc:
            # ``core.dump_io.DumpReader.open`` raises the bare builtin, which is
            # not a CapabilityError and so never reaches the API's global
            # handler. Translate it here — the canonical idiom, matching
            # ``app.tools_pipeline`` — so every surface reports a missing dump
            # as NOT_FOUND (404 / a clean CLI message) naming the path.
            raise FileNotFoundServiceError(
                f"File not found: {exc.filename or exc}"
            ) from exc
        yield sources


def build_consensus(
    dump_paths: Sequence[PathLike],
    *,
    normalize: bool = False,
    key_material: Optional[Mapping[str, Any]] = None,
    on_source: Optional[Callable[[DumpSource], None]] = None,
    region_filter: Any = None,
    force: bool = False,
    budget: Any = None,
) -> ConsensusVector:
    """Open the dumps, optionally inspect each, and build a consensus vector.

    This is the shared open + build core. Sources are opened together (so
    :meth:`ConsensusVector.build_from_sources` reads them while they are all
    live) and closed once the vector has been built — by then the vector holds
    its own copies of ``variance`` and ``reference_bytes``.

    :param dump_paths: Dump file paths to combine, in order.
    :param normalize: Forwarded to
        :meth:`~memdiver.engine.consensus.ConsensusVector.build_from_sources`;
        enables ASLR-aware region alignment for native ``.msl`` sources.
    :param key_material: Optional ``open_dump`` keyword arguments; see
        :func:`open_consensus_sources`.
    :param on_source: Optional hook invoked once per opened source, in order,
        *before* the vector is built (e.g. the CLI's tag-status warning). It
        runs while every source is still open.
    :param region_filter: Optional region view filter; see
        :func:`open_consensus_sources`. The aligned ``.msl`` path and the
        flat fallback both read through the filtered sources.
    :param force: Proceed even when the flat build's estimated peak memory
        exceeds the budget (otherwise ``CapabilityError`` code
        ``memory_budget_exceeded``).
    :param budget: Optional ``MemoryBudget`` / byte count; ``None`` resolves
        the host budget.
    :returns: The built :class:`~memdiver.engine.consensus.ConsensusVector`.
    """
    with open_consensus_sources(
        dump_paths, key_material=key_material, region_filter=region_filter,
    ) as sources:
        if on_source is not None:
            for src in sources:
                on_source(src)
        cm = ConsensusVector()
        cm.build_from_sources(sources, normalize=normalize,
                              force=force, budget=budget)
    return cm
