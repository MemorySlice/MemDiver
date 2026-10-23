"""Heap router — allocator detection, chunk layout and free lists.

The web face of the ``heap.*`` capabilities. Every route is a thin adapter over
its shared producer in :mod:`memdiver.app.tools_heap` (single source of truth
with the library, the CLI and the MCP tools):

* ``GET /api/heap/detect``     — ranked allocator candidates with evidence.
* ``GET /api/heap/summary``    — whole-heap overview (state counts, histogram).
* ``GET /api/heap/chunks``     — one filtered page of the chunk table.
* ``GET /api/heap/chunk-at``   — the chunk containing a VA / view offset.
* ``GET /api/heap/free-lists`` — every walked free list with corruption flags.
* ``GET /api/heap/roles``      — byte-role runs of a view window (hex overlay).

Key material (``passphrase`` / ``key_hex`` / ``kem_key_hex``) is bound for the
call with ``key_material_scope`` exactly as on the inspect router. Virtual
addresses are plain integers, as everywhere else on the API.

Error contract: this router is new, so it uses the MODERN contract (as
``api/routers/scan.py`` does) rather than the inspect router's legacy
200-with-error-dict: there is no ``try``/``except`` below, so a producer's
``CapabilityError`` reaches the global handler in ``api/main.py`` and is
rendered as ``{error, code, category}`` with the category's own status
(bad allocator/view/state/window → 400, missing dump → 404, …).
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

from fastapi import APIRouter, Depends, Query

from memdiver.api.dependencies import get_tool_session
from memdiver.api.services.key_material import decode_key_material
from memdiver.app import tools_heap
from memdiver.app.composition import key_material_scope
from memdiver.app.session import ToolSession

logger = logging.getLogger("memdiver.api.routers.heap")

router = APIRouter()


def _keyed_payload(passphrase: Optional[str], key_hex: Optional[str],
                   kem_key_hex: Optional[str], produce: Callable):
    """Run a heap producer under the request's key material; emit its payload.

    The status block is dropped, as on the inspect surface (the Web UI reads
    the key/tag state from the dedicated /tag-status endpoints).
    """
    with key_material_scope(decode_key_material(passphrase, key_hex, kem_key_hex)):
        return produce().payload


@router.get("/detect")
def heap_detect(
    dump_path: str,
    allocator: str = "auto",
    base_va: Optional[int] = Query(None, ge=0),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Ranked allocator candidates for ``dump_path``, each with its evidence.

    ``allocator`` other than ``auto`` is echoed back as the verdict
    (``hinted: true``).
    """
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_detect_result(
                              session, dump_path, allocator, base_va=base_va))


@router.get("/summary")
def heap_summary(
    dump_path: str,
    allocator: str = "auto",
    base_va: Optional[int] = Query(None, ge=0),
    max_chunks: int = Query(tools_heap.DEFAULT_MAX_CHUNKS, ge=1),
    regions: Optional[List[str]] = Query(None),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Whole-heap overview: allocator, regions, state counts, size histogram,
    per-role byte counts, metadata bytes, coverage and diagnostics."""
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_summary_result(
                              session, dump_path, allocator, base_va=base_va,
                              max_chunks=max_chunks, regions=regions))


@router.get("/chunks")
def heap_chunks(
    dump_path: str,
    allocator: str = "auto",
    state: Optional[str] = None,
    min_size: Optional[int] = Query(None, ge=0),
    max_size: Optional[int] = Query(None, ge=0),
    va_start: Optional[int] = Query(None, ge=0),
    va_end: Optional[int] = Query(None, ge=0),
    offset: Optional[int] = None,
    length: Optional[int] = None,
    view: str = "vas",
    page: int = 0,
    page_size: int = tools_heap.DEFAULT_CHUNK_PAGE_SIZE,
    base_va: Optional[int] = Query(None, ge=0),
    max_chunks: int = Query(tools_heap.DEFAULT_MAX_CHUNKS, ge=1),
    regions: Optional[List[str]] = Query(None),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """One page of the chunk table, filtered by state, size and a window.

    The window is EITHER ``va_start``/``va_end`` (half-open VAs) OR
    ``offset``/``length`` in ``view``. ``page`` is 0-based; ``page_size`` is
    capped at ``MAX_CHUNK_PAGE_SIZE`` (the producer validates both).
    """
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_chunks_result(
                              session, dump_path, allocator, state=state,
                              min_size=min_size, max_size=max_size,
                              va_start=va_start, va_end=va_end,
                              offset=offset, length=length, view=view,
                              page=page, page_size=page_size, base_va=base_va,
                              max_chunks=max_chunks, regions=regions))


@router.get("/chunk-at")
def heap_chunk_at(
    dump_path: str,
    allocator: str = "auto",
    va: Optional[int] = Query(None, ge=0),
    offset: Optional[int] = Query(None, ge=0),
    view: str = "vas",
    base_va: Optional[int] = Query(None, ge=0),
    max_chunks: int = Query(tools_heap.DEFAULT_MAX_CHUNKS, ge=1),
    regions: Optional[List[str]] = Query(None),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """The chunk containing ``va`` (or a ``view`` offset — give exactly one),
    the role of that byte, and the chunks either side of it."""
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_chunk_at_result(
                              session, dump_path, allocator, va=va,
                              offset=offset, view=view, base_va=base_va,
                              max_chunks=max_chunks, regions=regions))


@router.get("/free-lists")
def heap_free_lists(
    dump_path: str,
    allocator: str = "auto",
    kind: Optional[str] = None,
    base_va: Optional[int] = Query(None, ge=0),
    max_chunks: int = Query(tools_heap.DEFAULT_MAX_CHUNKS, ge=1),
    regions: Optional[List[str]] = Query(None),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Every walked free list (tcache bins, fastbins, …), optionally only
    those of one ``kind``, with cycle and corruption flags."""
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_free_lists_result(
                              session, dump_path, allocator, kind=kind,
                              base_va=base_va, max_chunks=max_chunks,
                              regions=regions))


@router.get("/roles")
def heap_roles(
    dump_path: str,
    allocator: str = "auto",
    view: str = "vas",
    offset: int = 0,
    length: int = tools_heap.DEFAULT_ROLES_LENGTH,
    base_va: Optional[int] = Query(None, ge=0),
    max_chunks: int = Query(tools_heap.DEFAULT_MAX_CHUNKS, ge=1),
    regions: Optional[List[str]] = Query(None),
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
    session: ToolSession = Depends(get_tool_session),
):
    """Byte-role runs (``{offset, length, role}`` in ``view`` offsets) and
    chunk starts of the window ``[offset, offset + length)``. ``length`` is
    capped at ``MAX_ROLES_LENGTH`` (the producer validates the window)."""
    return _keyed_payload(passphrase, key_hex, kem_key_hex,
                          lambda: tools_heap.heap_roles_result(
                              session, dump_path, allocator, view=view,
                              offset=offset, length=length, base_va=base_va,
                              max_chunks=max_chunks, regions=regions))
