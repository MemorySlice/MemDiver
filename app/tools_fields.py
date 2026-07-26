"""App-layer producer for neighborhood field inference.

Thin wrapper around :func:`engine.vol3_emit.extract_inferred_fields` (which
itself calls ``PatternGenerator.infer_fields``) so every surface shares the
same static / dynamic / key_material segmentation of a hit's neighborhood
variance profile. This is the authoritative producer the frontend consumes
instead of re-porting ``infer_fields`` in TypeScript.
"""

from __future__ import annotations

from typing import List, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.vol3_emit import extract_inferred_fields


def infer_fields_result(
    neighborhood_variance: List[float],
    neighborhood_start: int,
    offset: int,
    length: int,
    variance_threshold: Optional[float] = None,
) -> List[dict]:
    """Segment a hit's neighborhood variance into inferred fields.

    Reuses ``extract_inferred_fields`` so the segmentation cannot fork from the
    plugin-emission path. The threshold, when omitted, resolves to
    ``engine.vol3_emit.PLUGIN_STATIC_THRESHOLD`` inside that wrapper.

    :returns: A list of field dicts, each
        ``{offset, length, type, label, mean_variance}`` where ``type`` is one
        of ``"static" | "key_material" | "dynamic"``. An empty
        ``neighborhood_variance`` yields ``[]``.
    :raises CapabilityError: on structurally invalid input.
    """
    if length < 0:
        raise CapabilityError(
            "length must be non-negative",
            category=ErrorCategory.INVALID_INPUT,
        )
    if offset < neighborhood_start:
        raise CapabilityError(
            "offset must not precede neighborhood_start",
            category=ErrorCategory.INVALID_INPUT,
        )
    if variance_threshold is not None and variance_threshold < 0:
        raise CapabilityError(
            "variance_threshold must be non-negative",
            category=ErrorCategory.INVALID_INPUT,
        )

    hit = {
        "offset": int(offset),
        "length": int(length),
        "neighborhood_start": int(neighborhood_start),
        "neighborhood_variance": list(neighborhood_variance),
    }
    return extract_inferred_fields(hit, variance_threshold=variance_threshold)
