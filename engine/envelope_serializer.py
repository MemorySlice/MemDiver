"""Bridge from a neutral :class:`ServiceResult` envelope to a JSON-ready dict.

This is the serialization seam between the transport-agnostic
:mod:`memdiver.core.service_result` envelope and the concrete engine result
dataclasses. It reuses the existing per-type serializers in
:mod:`memdiver.engine.serializer` rather than duplicating any field mapping,
and it attaches the envelope's status under a reserved ``"_status"`` key.

Unlike ``core.service_result`` this module is free to import from ``engine``
(that is the whole point — it knows the concrete payload types). It still does
NOT import ``fastapi`` or ``mcp``: producing a plain ``dict`` keeps every
transport free to render it however it likes.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict

from memdiver.core.discovery import DatasetInfo
from memdiver.core.service_result import ServiceResult
from memdiver.engine.convergence import ConvergenceSweepResult
from memdiver.engine.results import (
    AnalysisResult,
    LibraryReport,
    SecretHit,
    StaticRegion,
)
from memdiver.engine.serializer import (
    serialize_convergence_result,
    serialize_dataset_info,
    serialize_hit,
    serialize_report,
    serialize_result,
    serialize_static_region,
    serialize_verification_result,
)
from memdiver.engine.verification import VerificationResult

# Reserved top-level key under which the status envelope is attached.
STATUS_KEY = "_status"

# Map each concrete payload dataclass type to its existing serializer.
_PAYLOAD_SERIALIZERS: Dict[type, Callable[[Any], Dict[str, Any]]] = {
    AnalysisResult: serialize_result,
    LibraryReport: serialize_report,
    SecretHit: serialize_hit,
    StaticRegion: serialize_static_region,
    ConvergenceSweepResult: serialize_convergence_result,
    VerificationResult: serialize_verification_result,
    DatasetInfo: serialize_dataset_info,
}


def _serialize_payload(payload: Any) -> Dict[str, Any]:
    """Resolve the right serializer for ``payload`` and apply it.

    * A registered dataclass type uses its dedicated serializer.
    * A plain ``dict`` is passed through unchanged.
    * Any other dataclass falls back to a shallow ``dataclasses`` conversion.
    """
    serializer = _PAYLOAD_SERIALIZERS.get(type(payload))
    if serializer is not None:
        return serializer(payload)
    if isinstance(payload, dict):
        return dict(payload)
    if dataclasses.is_dataclass(payload) and not isinstance(payload, type):
        return {f.name: getattr(payload, f.name) for f in dataclasses.fields(payload)}
    return {"value": payload}


def serialize_envelope(env: ServiceResult, *, include_status: bool = True) -> Dict[str, Any]:
    """Serialize a :class:`ServiceResult` to a JSON-compatible dict.

    The payload is serialized via its registered engine serializer (or a
    fallback). When ``include_status`` is True the envelope's status block is
    attached under the reserved :data:`STATUS_KEY` (``"_status"``).
    """
    result = _serialize_payload(env.payload)
    if include_status:
        result[STATUS_KEY] = env.status.to_dict()
    return result
