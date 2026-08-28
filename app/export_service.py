"""Export compute — single source of truth for the pattern-export pipeline.

This module is the ``app``-layer home of the consensus → volatile-region →
static-check → pattern-generate → export pipeline that backs the
``memdiver export`` CLI command, the ``POST /api/analysis/auto-export`` HTTP
route, and the ``export_pattern`` MCP tool. It was relocated here (from
``api/services/analysis_service.py``) so the shared compute lives DOWN in the
``app`` layer next to its producer (:func:`memdiver.app.tools_pipeline.export_pattern`)
instead of the ``app`` producer importing UP into ``api/services``. The old
module now re-exports these symbols as a backward-compatible shim.

The two historical bugs this pipeline closed (documented on the original
module) remain closed here — nothing in this move changed behavior:

- The API used to call ``ConsensusVector.build(paths)`` — flat file bytes —
  producing KEY_CANDIDATE offsets into the MSL binary layout rather than
  memory, so the exported pattern was unusable for locating the key at
  runtime.
- The CLI called ``build_from_sources`` (the correct ASLR-aware path) but
  forgot to open the DumpSource objects, crashing on every MSL input.

Both are handled by :func:`auto_export_pattern`, which opens every source
through a proper context-manager lifecycle, uses ``build_from_sources`` so the
consensus offsets are memory-relative (ASLR-invariant), and derives the static
mask and reference bytes from the consensus vector itself.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from memdiver.app.composition import open_dump
from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
)
from memdiver.core.service_result import KeyStatus
from memdiver.engine.consensus import ConsensusVector

logger = logging.getLogger("memdiver.app.export_service")


class AnalysisServiceError(CapabilityError, ValueError):
    """Base class for user-correctable service errors.

    Carries an integer ``status`` hint so HTTP transports can translate
    directly to an appropriate response code without the service layer
    having to import from ``fastapi``.

    Re-based onto the transport-agnostic :class:`CapabilityError` so the
    same error carries an :class:`ErrorCategory` for non-HTTP transports,
    while ``ValueError`` is retained in the bases to preserve the historic
    ``except ValueError`` / ``isinstance(err, ValueError)`` contract.
    """

    def __init__(
        self,
        message: str,
        status: int = 400,
        *,
        category: ErrorCategory = ErrorCategory.INVALID_INPUT,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message,
            category=category,
            status=status,
            code=code,
            details=details,
        )


class DumpsNotFoundError(AnalysisServiceError):
    def __init__(self, missing: List[str]) -> None:
        super().__init__(
            f"Files not found: {missing[:3]}",
            status=404,
            category=ErrorCategory.NOT_FOUND,
        )
        self.missing = missing


class TooFewDumpsError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__(
            "Need at least 2 dumps",
            status=400,
            category=ErrorCategory.PRECONDITION,
        )


class NoVolatileRegionsError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__(
            "No KEY_CANDIDATE regions found",
            status=404,
            category=ErrorCategory.NOT_FOUND,
        )


class EmptyRegionError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__(
            "Failed to read region",
            status=500,
            category=ErrorCategory.INTERNAL,
        )


class InsufficientStaticError(AnalysisServiceError):
    def __init__(self, ratio: float, required: float) -> None:
        msg = (
            f"Insufficient static bytes for pattern "
            f"({ratio * 100:.1f}% static, need {required * 100:.1f}%)"
        )
        super().__init__(msg, status=400, category=ErrorCategory.PRECONDITION)
        self.ratio = ratio
        self.required = required


class UnknownFormatError(AnalysisServiceError):
    def __init__(self, fmt: str) -> None:
        super().__init__(
            f"Unknown format: {fmt}",
            status=400,
            category=ErrorCategory.UNSUPPORTED,
        )
        self.format = fmt


SUPPORTED_FORMATS = ("yara", "json", "volatility3", "vol3")


def auto_export_pattern(
    dump_paths: List[Union[str, Path]],
    *,
    fmt: str = "volatility3",
    name: str = "memdiver_pattern",
    align: bool = True,
    context: int = 32,
    min_static_ratio: float = 0.3,
    key_material: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run the full auto-export pipeline and return the export payload.

    Args:
        dump_paths: Paths to the N input dumps. Must contain at least 2.
        fmt: Output format — one of ``SUPPORTED_FORMATS``.
        name: Pattern name.
        align: When True use ``get_aligned_candidates``; otherwise
            ``get_volatile_regions``.
        context: Static-anchor bytes of padding on each side of the
            detected volatile region.
        min_static_ratio: Minimum ratio of static bytes required for a
            pattern to be emitted by ``PatternGenerator``.
        key_material: Optional decryption kwargs (``key``/``passphrase``/
            ``kem_private_key``) forwarded to ``open_dump`` so encrypted
            ``.msl`` inputs can be read (spec §10).

    Returns:
        A dict with keys ``format``, ``content``, ``pattern`` and
        ``region``, matching the shape the ``/auto-export`` HTTP route
        returned before PR 4. The ``region`` sub-dict carries
        ``offset``, ``length``, ``key_start``, ``key_end`` — all
        memory-relative offsets into the consensus vector (i.e. into the
        aligned-page space for native MSL inputs or into the flat-file
        space for raw inputs).

    Raises:
        AnalysisServiceError: on user-correctable errors. Each subclass
            exposes a ``status`` attribute that HTTP transports can map
            directly to an HTTP status code.
    """
    from memdiver.architect.pattern_generator import PatternGenerator

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise DumpsNotFoundError(missing)
    if len(paths) < 2:
        raise TooFewDumpsError()

    fmt_lower = fmt.lower()
    if fmt_lower not in SUPPORTED_FORMATS:
        raise UnknownFormatError(fmt)

    # Open every source through a proper context manager so the underlying
    # readers (and mmaps) are released on normal exit AND on error.
    # Nested `with` via an exit stack so every opened source is paired.
    from contextlib import ExitStack

    with ExitStack() as stack:
        sources = [stack.enter_context(open_dump(p, **(key_material or {})))
                   for p in paths]

        # A locked (missing/wrong-key) encrypted .msl reads back empty, which
        # the consensus below would misattribute as "no KEY_CANDIDATE regions".
        # Surface the lock explicitly before that empty-region handling; a
        # decrypted-but-empty dump still falls through to NoVolatileRegionsError.
        for source in sources:
            key = KeyStatus.from_source(source)
            if not key.decrypted:
                raise EncryptedDumpLockedError(key.hint)

        cm = ConsensusVector()
        cm.build_from_sources(sources)

    # Sources are closed once the consensus is built; reference_bytes
    # and variance are copies held on `cm` and outlive the sources.

    if cm.size == 0:
        raise NoVolatileRegionsError()

    if align:
        volatile = cm.get_aligned_candidates()
    else:
        volatile = cm.get_volatile_regions(min_length=16)

    if not volatile:
        raise NoVolatileRegionsError()

    best = max(volatile, key=lambda r: r.end - r.start)
    offset = max(0, best.start - context)
    end = min(cm.size, best.end + context)
    length = end - offset
    if length <= 0:
        raise EmptyRegionError()

    reference = cm.reference_bytes[offset:end]
    if not reference:
        raise EmptyRegionError()

    # Static mask derived directly from the consensus variance: a byte is
    # static across all aligned inputs iff its variance is exactly zero.
    # This replaces StaticChecker.check(), which re-read file bytes at
    # absolute file offsets — valid for the flat-file consensus path but
    # semantically wrong for the ASLR-aligned consensus path (the aligned
    # offsets don't map back to a single file offset per dump).
    import numpy as np

    var_slice = cm.variance[offset:end]
    if isinstance(var_slice, np.ndarray):
        static_mask = (var_slice == 0.0).tolist()
    else:
        static_mask = [v == 0.0 for v in var_slice]

    pattern = PatternGenerator.generate(
        reference, static_mask, name, min_static_ratio,
    )
    if pattern is None:
        ratio = (sum(static_mask) / len(static_mask)) if static_mask else 0.0
        raise InsufficientStaticError(ratio, min_static_ratio)

    content = _render_content(
        pattern, fmt_lower,
        key_offset=best.start - offset,
        key_length=best.end - best.start,
    )

    return {
        "format": fmt_lower,
        "content": content,
        "pattern": pattern,
        "region": {
            "offset": offset,
            "length": length,
            "key_start": best.start,
            "key_end": best.end,
        },
    }


def manual_export_pattern(
    dump_paths: List[Union[str, Path]],
    offset: int,
    length: int,
    *,
    fmt: str = "volatility3",
    name: str = "memdiver_pattern",
    min_static_ratio: float = 0.3,
    key_material: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Export a pattern from a user-specified offset + length.

    This is the manual counterpart to ``auto_export_pattern``. The user
    already knows where the key is (e.g. from previous analysis or from
    a reverse-engineering session) and passes the offset explicitly.

    The region is read through each dump's DumpSource memory projection
    (``open_dump(...).read_range``): the flattened VAS view for ``.msl``
    inputs and raw bytes for ``.dump`` inputs. This means the user's offset
    is interpreted in the SAME space MemDiver presents offsets in (memory
    for ``.msl``), and it lets ``key_material`` decrypt encrypted ``.msl``
    containers — the previous implementation read raw file bytes via
    ``StaticChecker.check`` and silently ignored any supplied key.

    Args:
        key_material: Optional decryption kwargs (``key``/``passphrase``/
            ``kem_private_key``) forwarded to ``open_dump`` so encrypted
            ``.msl`` inputs can be read (spec §10).

    Raises the same ``AnalysisServiceError`` subclasses as the auto path
    on user-correctable errors.
    """
    from memdiver.architect.pattern_generator import PatternGenerator
    from memdiver.architect.static_checker import StaticChecker

    paths = [Path(p) for p in dump_paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise DumpsNotFoundError(missing)
    if len(paths) < 2:
        raise TooFewDumpsError()
    if length <= 0:
        raise EmptyRegionError()

    fmt_lower = fmt.lower()
    if fmt_lower not in SUPPORTED_FORMATS:
        raise UnknownFormatError(fmt)

    # Read the requested region from each dump through its memory projection
    # so .msl offsets are memory-relative and encrypted containers decrypt.
    from contextlib import ExitStack

    with ExitStack() as stack:
        sources = [stack.enter_context(open_dump(p, **(key_material or {})))
                   for p in paths]
        regions = [s.read_range(offset, length) for s in sources]

    static_mask, reference = StaticChecker.check_regions(regions)
    if not reference:
        raise EmptyRegionError()

    pattern = PatternGenerator.generate(
        reference, static_mask, name, min_static_ratio,
    )
    if pattern is None:
        ratio = (sum(static_mask) / len(static_mask)) if static_mask else 0.0
        raise InsufficientStaticError(ratio, min_static_ratio)

    # key_start == offset on this path, so the key begins at pattern offset 0.
    content = _render_content(
        pattern, fmt_lower, key_offset=0, key_length=length,
    )

    return {
        "format": fmt_lower,
        "content": content,
        "pattern": pattern,
        "region": {
            "offset": offset,
            "length": length,
            "key_start": offset,
            "key_end": offset + length,
        },
    }


def _render_content(
    pattern: Dict[str, Any],
    fmt: str,
    key_offset: int | None = None,
    key_length: int | None = None,
) -> str:
    """Dispatch pattern dict to the requested exporter.

    ``key_offset``/``key_length`` locate the key bytes *inside* the exported
    pattern, so a consumer of the rule knows which slice of a hit is the key
    rather than only that the surrounding structure matched. Both are
    forwarded to the YARA exporter, which emits them as meta lines only when
    supplied.

    Note that on the MANUAL export path the caller's offset IS the key start
    (``key_start == offset``), so ``key_offset`` is 0 there -- the pattern has
    no static-anchor context prepended. Only the auto path, which pads the
    detected volatile region with ``context`` bytes on each side, produces a
    non-zero ``key_offset``.
    """
    if fmt == "yara":
        from memdiver.architect.yara_exporter import YaraExporter

        return YaraExporter.export(
            pattern, key_offset=key_offset, key_length=key_length,
        )
    if fmt == "json":
        from memdiver.architect.json_exporter import JsonExporter

        sig = JsonExporter.export(pattern)
        return JsonExporter.to_string(sig)
    if fmt in ("volatility3", "vol3"):
        from memdiver.architect.volatility3_exporter import Volatility3Exporter
        from memdiver.architect.yara_exporter import YaraExporter

        yara_rule = YaraExporter.export(
            pattern, key_offset=key_offset, key_length=key_length,
        )
        return Volatility3Exporter.export(pattern, yara_rule=yara_rule)
    # Should be unreachable because of the earlier format check, but keep
    # the safety net here so the dispatch is self-contained.
    raise UnknownFormatError(fmt)
