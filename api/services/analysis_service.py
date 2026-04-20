"""Analysis service — single source of truth for the auto-export pipeline.

This module exists to decouple analysis business logic from its two
transports (the FastAPI route at ``/api/analysis/auto-export`` and the
CLI command ``memdiver export --auto``). Prior to PR 4, each transport
had its own inlined copy of the consensus → volatile-region → static
check → pattern generate → export pipeline, and they had diverged:

- The API called ``ConsensusVector.build(paths)`` — flat file bytes.
  For ASLR-shifted native MSL inputs this produces KEY_CANDIDATE offsets
  that point into the MSL binary layout (e.g. the raw byte position of
  the key inside the file) rather than memory, so the exported pattern
  is unusable for locating the key at runtime.

- The CLI called ``ConsensusVector.build_from_sources(sources)`` — the
  correct ASLR-aware path — but forgot to open the DumpSource objects,
  so the first line inside ``build_from_sources`` raised
  ``RuntimeError("MslDumpSource not opened; use context manager")`` and
  the CLI crashed on every MSL input.

Both bugs are closed here by a single service function,
``auto_export_pattern``, that:

1. Opens every source through a proper context-manager lifecycle.
2. Uses ``build_from_sources`` so the consensus offsets are memory-
   relative (ASLR-invariant).
3. Derives the static mask and reference bytes from the consensus vector
   itself — ``ConsensusVector.reference_bytes[start:end]`` and
   ``variance[start:end] == 0`` — instead of passing the memory-relative
   offsets back to ``StaticChecker.check`` (which reads raw file bytes
   at arbitrary offsets and would produce garbage for aligned inputs).

The route handler and the CLI command both become thin shell adapters
over this function. See PR 4 in
``.claude-work/plans/curried-jumping-lantern.md`` for the rationale and
the ASLR regression test outcomes that promoted the router-as-service
refactor from "deferred" to "ship now".
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.dump_source import open_dump
from engine.consensus import ConsensusVector

logger = logging.getLogger("memdiver.api.services.analysis_service")


class AnalysisServiceError(ValueError):
    """Base class for user-correctable service errors.

    Carries an integer ``status`` hint so HTTP transports can translate
    directly to an appropriate response code without the service layer
    having to import from ``fastapi``.
    """

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class DumpsNotFoundError(AnalysisServiceError):
    def __init__(self, missing: List[str]) -> None:
        super().__init__(f"Files not found: {missing[:3]}", status=404)
        self.missing = missing


class TooFewDumpsError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__("Need at least 2 dumps", status=400)


class NoVolatileRegionsError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__("No KEY_CANDIDATE regions found", status=404)


class EmptyRegionError(AnalysisServiceError):
    def __init__(self) -> None:
        super().__init__("Failed to read region", status=500)


class InsufficientStaticError(AnalysisServiceError):
    def __init__(self, ratio: float, required: float) -> None:
        msg = (
            f"Insufficient static bytes for pattern "
            f"({ratio * 100:.1f}% static, need {required * 100:.1f}%)"
        )
        super().__init__(msg, status=400)
        self.ratio = ratio
        self.required = required


class UnknownFormatError(AnalysisServiceError):
    def __init__(self, fmt: str) -> None:
        super().__init__(f"Unknown format: {fmt}", status=400)
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
    from architect.pattern_generator import PatternGenerator

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
        sources = [stack.enter_context(open_dump(p)) for p in paths]

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

    content = _render_content(pattern, fmt_lower)

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
) -> Dict[str, Any]:
    """Export a pattern from a user-specified absolute file offset + length.

    This is the manual counterpart to ``auto_export_pattern``. The user
    already knows where the key is (e.g. from previous analysis or from
    a reverse-engineering session) and passes the file-relative offset
    explicitly. Because the offset is a flat-file offset — not a
    memory-relative aligned offset — the service reads file bytes
    directly via ``StaticChecker.check`` and hands them to
    ``PatternGenerator`` unchanged. The semantic mismatch that bites the
    auto path (aligned offsets fed into a file-byte reader) does not
    apply here because the user's offset IS a file offset.

    Raises the same ``AnalysisServiceError`` subclasses as the auto path
    on user-correctable errors.
    """
    from architect.pattern_generator import PatternGenerator
    from architect.static_checker import StaticChecker

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

    static_mask, reference = StaticChecker.check(paths, offset, length)
    if not reference:
        raise EmptyRegionError()

    pattern = PatternGenerator.generate(
        reference, static_mask, name, min_static_ratio,
    )
    if pattern is None:
        ratio = (sum(static_mask) / len(static_mask)) if static_mask else 0.0
        raise InsufficientStaticError(ratio, min_static_ratio)

    content = _render_content(pattern, fmt_lower)

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


def _render_content(pattern: Dict[str, Any], fmt: str) -> str:
    """Dispatch pattern dict to the requested exporter."""
    if fmt == "yara":
        from architect.yara_exporter import YaraExporter

        return YaraExporter.export(pattern)
    if fmt == "json":
        from architect.json_exporter import JsonExporter

        sig = JsonExporter.export(pattern)
        return JsonExporter.to_string(sig)
    if fmt in ("volatility3", "vol3"):
        from architect.volatility3_exporter import Volatility3Exporter
        from architect.yara_exporter import YaraExporter

        yara_rule = YaraExporter.export(pattern)
        return Volatility3Exporter.export(pattern, yara_rule=yara_rule)
    # Should be unreachable because of the earlier format check, but keep
    # the safety net here so the dispatch is self-contained.
    raise UnknownFormatError(fmt)
