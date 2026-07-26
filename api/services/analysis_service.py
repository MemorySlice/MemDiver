"""Backward-compatible shim for the relocated export-compute module.

The auto/manual pattern-export pipeline (``auto_export_pattern``,
``manual_export_pattern``, the ``AnalysisServiceError`` hierarchy and the
``_render_content`` dispatcher) used to live here. It has moved DOWN into the
``app`` layer — :mod:`memdiver.app.export_service` — so the ``app`` producer
(:func:`memdiver.app.tools_pipeline.export_pattern`) no longer imports UP into
``api/services``. That inverted dependency is what this relocation removes.

This module is retained as a re-export shim so any external importer of
``memdiver.api.services.analysis_service`` keeps working unchanged. All names
below are the SAME objects defined in :mod:`memdiver.app.export_service`.
"""

from __future__ import annotations

from memdiver.app.export_service import (
    SUPPORTED_FORMATS,
    AnalysisServiceError,
    DumpsNotFoundError,
    EmptyRegionError,
    InsufficientStaticError,
    NoVolatileRegionsError,
    TooFewDumpsError,
    UnknownFormatError,
    _render_content,
    auto_export_pattern,
    manual_export_pattern,
)

__all__ = [
    "SUPPORTED_FORMATS",
    "AnalysisServiceError",
    "DumpsNotFoundError",
    "EmptyRegionError",
    "InsufficientStaticError",
    "NoVolatileRegionsError",
    "TooFewDumpsError",
    "UnknownFormatError",
    "auto_export_pattern",
    "manual_export_pattern",
    "_render_content",
]
