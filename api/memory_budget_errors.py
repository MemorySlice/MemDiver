"""HTTP mapping for the memory-budget guard's refusal.

``core.memory_budget.check_budget`` raises a PRECONDITION ``CapabilityError``
with ``code="memory_budget_exceeded"``. On the REST surface that refusal is
NOT a generic 400: it is ``507 Insufficient Storage`` with a flat body the
frontend can act on (show estimate vs budget, offer "Run anyway", re-send the
request with ``force_memory: true``)::

    {"error": msg, "code": "memory_budget_exceeded", "category": "PRECONDITION",
     "message": msg, "estimate_bytes": int, "budget_bytes": int, "details": {...}}
"""

from __future__ import annotations

from typing import Any, Dict

from memdiver.core.service_errors import CapabilityError

#: Machine-readable code ``check_budget`` stamps on its refusal.
MEMORY_BUDGET_EXCEEDED_CODE = "memory_budget_exceeded"

#: HTTP status for a budget refusal (``507 Insufficient Storage``).
MEMORY_BUDGET_HTTP_STATUS = 507


def is_memory_budget_error(exc: BaseException) -> bool:
    """True when ``exc`` is the memory-budget guard's refusal."""
    return (
        isinstance(exc, CapabilityError)
        and exc.code == MEMORY_BUDGET_EXCEEDED_CODE
    )


def memory_budget_fields(exc: CapabilityError) -> Dict[str, Any]:
    """The machine-readable fields of a budget refusal (code + the two numbers).

    Shared by the HTTP body and the background-task failure record so the two
    surfaces carry the identical keys.
    """
    details = dict(exc.details or {})
    return {
        "code": MEMORY_BUDGET_EXCEEDED_CODE,
        "estimate_bytes": details.get("estimate_bytes"),
        "budget_bytes": details.get("budget_bytes"),
        "details": details,
    }


def memory_budget_error_body(exc: CapabilityError) -> Dict[str, Any]:
    """Flat JSON body for the 507 response."""
    body = exc.to_dict()
    body["message"] = exc.message
    body.update(memory_budget_fields(exc))
    return body


def reraise_if_memory_budget(exc: CapabilityError) -> None:
    """Re-raise a budget refusal so the global handler maps it to 507.

    Routes that translate ``CapabilityError`` to ``HTTPException`` locally
    call this first, so the refusal is never downgraded to a ``{"detail"}``
    400 the frontend cannot recognise.
    """
    if is_memory_budget_error(exc):
        raise exc
