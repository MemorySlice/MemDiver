"""App-layer producer for algorithm availability gating.

Server-side source of truth for "which analysis algorithms can run given the
current inputs, and why not" — the logic the frontend previously duplicated in
``frontend/src/utils/algorithm-availability.ts``. Only three algorithms carry a
gating rule; every other algorithm name is available by default.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence

# Algorithms with a non-default availability rule. Every other algorithm name
# is unconditionally available (mirrors the ``default`` branch of the TS
# ``getAlgorithmAvailability`` switch).
_DIFFERENTIAL = "differential"
_EXACT_MATCH = "exact_match"
_CONSTRAINT_VALIDATOR = "constraint_validator"

#: The algorithms that carry a gating rule. Evaluated when the caller does not
#: name an explicit set; every other name defaults to available.
GATED_ALGORITHMS = (_DIFFERENTIAL, _EXACT_MATCH, _CONSTRAINT_VALIDATOR)

# Human-readable reasons, copied VERBATIM from algorithm-availability.ts so the
# UI text does not drift when the frontend switches to the backend.
_REASON_DIFFERENTIAL = "Requires 2+ memory dumps for cross-run variance analysis"
_REASON_EXACT_MATCH = "Requires keylog reference data (ground truth)"
_REASON_CONSTRAINT_VALIDATOR = "Requires candidate keys from prior analysis"


def _availability_for(
    algo: str,
    dump_count: int,
    has_keylog: bool,
    has_candidate_keys: bool,
) -> Dict[str, object]:
    """Availability of a single algorithm (mirrors ``getAlgorithmAvailability``)."""
    if algo == _DIFFERENTIAL:
        if dump_count < 2:
            return {"available": False, "reason": _REASON_DIFFERENTIAL}
        return {"available": True, "reason": None}
    if algo == _EXACT_MATCH:
        if not has_keylog:
            return {"available": False, "reason": _REASON_EXACT_MATCH}
        return {"available": True, "reason": None}
    if algo == _CONSTRAINT_VALIDATOR:
        if not has_candidate_keys:
            return {"available": False, "reason": _REASON_CONSTRAINT_VALIDATOR}
        return {"available": True, "reason": None}
    return {"available": True, "reason": None}


def algorithm_availability(
    dump_count: int,
    has_keylog: bool,
    has_candidate_keys: bool,
    algorithms: Optional[Sequence[str]] = None,
    mode: Optional[str] = None,
) -> Dict[str, Dict[str, object]]:
    """Return ``{algo: {available, reason}}`` for the given input context.

    Mirrors ``getAvailableAlgorithms`` in the frontend: applies the same three
    gating rules with the same verbatim reason strings. ``algorithms`` selects
    which names to evaluate; when omitted, only :data:`GATED_ALGORITHMS` are
    returned (every other name is available by default). ``mode`` mirrors the
    unused ``inputMode`` of the TS context and is accepted but ignored.
    """
    names = list(algorithms) if algorithms is not None else list(GATED_ALGORITHMS)
    return {
        algo: _availability_for(algo, dump_count, has_keylog, has_candidate_keys)
        for algo in names
    }
