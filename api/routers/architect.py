"""Architect router — static checking, pattern generation, and export."""

from __future__ import annotations

import logging
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from memdiver.api.models import KeyMaterialFields
from memdiver.api.services.key_material import decode_key_material
from memdiver.app.composition import open_dump, raise_if_locked
from memdiver.architect.json_exporter import JsonExporter
from memdiver.architect.pattern_generator import PatternGenerator
from memdiver.architect.static_checker import StaticChecker
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from memdiver.architect.yara_exporter import (
    YaraExporter,
    key_locator_from_pattern,
)
from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import KeyStatus

logger = logging.getLogger("memdiver.api.routers.architect")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CheckStaticRequest(KeyMaterialFields):
    """Request body for static byte checking across dumps.

    Inherits the optional ``passphrase`` / ``key_hex`` / ``kem_key_hex``
    decryption fields (spec §10) from :class:`KeyMaterialFields`, the same
    shape ``POST /api/analysis/consensus`` and ``POST /api/inspect/tag-status``
    use. Without them an encrypted ``.msl`` reads back empty, and the route
    would report an empty region as a result rather than as a locked
    container.

    ``offset`` is a MEMORY offset for ``.msl`` inputs — the flattened-VAS
    coordinate every other MemDiver surface presents — and a plain file
    offset for raw dumps. See :func:`check_static`.
    """

    dump_paths: list[str]
    offset: int
    length: int


class GeneratePatternRequest(BaseModel):
    """Request body for wildcard pattern generation."""

    reference_hex: str
    static_mask: list[bool]
    name: str = "unnamed"
    min_static_ratio: float = 0.3


class ExportRequest(BaseModel):
    """Request body for pattern export (YARA or JSON)."""

    pattern: dict
    format: str = "yara"
    rule_name: Optional[str] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _read_static_regions(
    paths: List[Path],
    offset: int,
    length: int,
    key_material: Dict[str, Any],
) -> List[bytes]:
    """Read ``[offset, offset+length)`` from each dump's memory projection.

    All sources are held open together inside one :class:`ExitStack` and the
    bytes are copied out before any of them closes, mirroring
    ``app.export_service.manual_export_pattern``.

    Raises:
        EncryptedDumpLockedError: if any input is an encrypted container that
            the supplied key material cannot open. Such a source does not
            raise on read — it reads back EMPTY — which
            :meth:`StaticChecker.check_regions` would then report as an empty
            (vacuously all-static) region instead of a locked dump.
    """
    with ExitStack() as stack:
        regions = []
        for path in paths:
            source = stack.enter_context(open_dump(path, **key_material))
            # The ONE shared guard (``app.composition.raise_if_locked``). This
            # used to be a local copy precisely because the only spelling of it
            # was another module's private ``_raise_if_locked``; promoting it to
            # a public app-layer helper removed that reason.
            raise_if_locked(source)
            regions.append(source.read_range(offset, length))
    return regions


@router.post("/check-static")
def check_static(req: CheckStaticRequest):
    """Check which bytes are static across multiple dump files.

    The region is read through each dump's ``DumpSource`` memory projection
    (``open_dump(...).read_range``) — the flattened VAS view for ``.msl``
    inputs, raw bytes for ``.dump`` / ``.bin`` inputs — so ``req.offset`` is
    interpreted in the SAME space MemDiver presents offsets in, and supplied
    key material decrypts encrypted ``.msl`` containers.

    This previously called ``StaticChecker.check``, which reads RAW FILE
    bytes and slices them at ``offset``. For a ``.msl`` input that silently
    compared container bytes — magic header, block metadata, ciphertext — at
    a numeric position the rest of the product labels a memory offset: wrong
    bytes, HTTP 200, no error. And with no key fields on the request an
    encrypted container yielded ciphertext or nothing at all. Same bug and
    same fix as ``app.export_service.manual_export_pattern``;
    :meth:`StaticChecker.check_regions` is the shared byte-comparison core,
    so the staticness semantics (including the shorter-region tail rule) are
    unchanged.
    """
    paths = []
    for p in req.dump_paths:
        path = Path(p)
        if not path.is_file():
            raise FileNotFoundServiceError(f"File not found: {p}")
        paths.append(path)

    if len(paths) < 2:
        raise CapabilityError(
            "Need at least 2 dump paths",
            category=ErrorCategory.INVALID_INPUT,
        )

    km = decode_key_material(req.passphrase, req.key_hex, req.kem_key_hex) or {}
    # No local translation: an ``EncryptedDumpLockedError`` (or any other
    # ``CapabilityError``) from the read propagates to the app's single global
    # handler (``api.main._capability_error_handler``), which renders it with
    # ``exc.status`` and the structured ``exc.to_dict()`` envelope. The router's
    # OWN failures above and below now raise the same transport-agnostic type,
    # so the whole router speaks one error contract instead of splitting between
    # FastAPI's ``{"detail": ...}`` and the funnel's ``{"error", "code",
    # "category"}``. Statuses are unchanged (NOT_FOUND -> 404, INVALID_INPUT /
    # PRECONDITION / UNSUPPORTED -> 400).
    regions = _read_static_regions(paths, req.offset, req.length, km)

    static_mask, reference = StaticChecker.check_regions(regions)
    ratio = StaticChecker.static_ratio(static_mask)
    anchors = PatternGenerator.find_anchors(static_mask)

    return {
        "static_mask": static_mask,
        "reference_hex": reference.hex(),
        "static_ratio": round(ratio, 4),
        "anchors": [{"start": s, "length": l} for s, l in anchors],
    }


@router.post("/generate-pattern")
def generate_pattern(req: GeneratePatternRequest):
    """Generate a wildcard byte pattern from reference bytes and mask."""
    try:
        reference = bytes.fromhex(req.reference_hex)
    except ValueError as exc:
        raise CapabilityError(
            f"Invalid hex: {exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc

    pattern = PatternGenerator.generate(
        reference, req.static_mask, req.name, req.min_static_ratio,
    )
    if pattern is None:
        # PRECONDITION, not INVALID_INPUT: the request itself is well-formed;
        # it is the DATA (too few static bytes for ``min_static_ratio``) that
        # cannot yield a usable pattern. Both categories render 400, so the
        # wire status is identical either way.
        raise CapabilityError(
            "Insufficient static bytes for pattern generation",
            category=ErrorCategory.PRECONDITION,
        )
    return pattern


@router.post("/export")
def export_pattern(req: ExportRequest):
    """Export a pattern as YARA rule or JSON signature."""
    fmt = req.format.lower()

    # The key locator is whatever the *posted pattern* already carries: this
    # endpoint receives a finished pattern dict, never the hit or the
    # consensus slab it came from, so there is nothing else here from which
    # the key's position could be derived. A pattern produced by
    # ``emit-plugin`` / the experiment orchestrator carries
    # ``key_offset``/``key_length``; one straight out of
    # ``/architect/generate-pattern`` does not, and then the metas are
    # correctly omitted rather than invented.
    key_offset, key_length = key_locator_from_pattern(req.pattern)

    # ``req.pattern`` is a free-form client-supplied dict, so a malformed
    # ``wildcard_pattern`` is a BAD REQUEST, not a server fault. Before the
    # exporter validated its byte string, a pattern using the wrong key names
    # silently produced ``$key = {  }`` -- a rule that returned HTTP 200 and
    # then failed to compile on the analyst's machine. Mirrors the 400 that
    # ``/generate-pattern`` raises for an unusable pattern.
    #
    # ``_render_export``'s own unknown-format failure is already a
    # ``CapabilityError`` and is NOT a ``ValueError``, so it passes through this
    # handler untouched and reaches the global funnel directly.
    try:
        return _render_export(req, fmt, key_offset, key_length)
    except ValueError as exc:
        raise CapabilityError(
            str(exc), category=ErrorCategory.INVALID_INPUT,
        ) from exc


def _render_export(req: "ExportRequest", fmt: str,
                   key_offset, key_length) -> Dict[str, Any]:
    """Render the requested artifact for ``fmt``.

    Raises:
        ValueError: from an exporter, for a pattern carrying no usable byte
            string. The caller re-raises it as an INVALID_INPUT
            ``CapabilityError``.
        UnsupportedFormatError: for a format name that is not one of
            ``yara`` / ``json`` / ``volatility3``. Already a
            ``CapabilityError``, so it propagates straight to the global
            handler (UNSUPPORTED -> 400).
    """
    if fmt == "yara":
        content = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
            key_offset=key_offset, key_length=key_length,
        )
    elif fmt == "json":
        sig = JsonExporter.export(
            req.pattern, description=req.description or "",
        )
        content = JsonExporter.to_string(sig)
    elif fmt in ("volatility3", "vol3"):
        yara_rule = YaraExporter.export(
            req.pattern, rule_name=req.rule_name, description=req.description,
            key_offset=key_offset, key_length=key_length,
        )
        content = Volatility3Exporter.export(
            req.pattern, plugin_name=req.rule_name,
            description=req.description, yara_rule=yara_rule,
        )
    else:
        raise UnsupportedFormatError(
            f"Unknown format: {req.format}. Use 'yara', 'json', or 'volatility3'.",
        )

    return {"format": fmt, "content": content}
