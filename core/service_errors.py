"""Generalized, transport-agnostic error model for MemDiver services.

This module is deliberately base-dependency only (stdlib imports) so that
any layer — library, CLI, FastAPI route, MCP tool — can raise and catch a
single, structured error type without dragging in ``fastapi``, ``mcp``, or
any other optional transport dependency.

The two public names are :class:`ErrorCategory` (a coarse classification of
what went wrong) and :class:`CapabilityError` (the exception carrying that
classification plus an HTTP-status hint, an optional machine-readable
``code``, and free-form ``details``). Transports translate a
``CapabilityError`` into their own idiom (an HTTP response, an MCP error
payload, a CLI message) by reading ``.category`` / ``.status`` / ``.code``
or calling :meth:`CapabilityError.to_dict`.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, Optional


class ErrorCategory(enum.Enum):
    """Coarse classification of a user- or caller-correctable error."""

    NOT_FOUND = "not_found"
    INVALID_INPUT = "invalid_input"
    PRECONDITION = "precondition"
    UNSUPPORTED = "unsupported"
    INTERNAL = "internal"


# Default HTTP-status hint derived from the category when none is supplied.
_CATEGORY_STATUS: Dict[ErrorCategory, int] = {
    ErrorCategory.NOT_FOUND: 404,
    ErrorCategory.INVALID_INPUT: 400,
    ErrorCategory.PRECONDITION: 400,
    ErrorCategory.UNSUPPORTED: 400,
    ErrorCategory.INTERNAL: 500,
}


class CapabilityError(Exception):
    """Structured, transport-agnostic service error.

    Args:
        message: Human-readable message. ``str(err)`` returns this verbatim.
        category: Coarse :class:`ErrorCategory`. Defaults to ``INVALID_INPUT``.
        status: Explicit HTTP-status hint. When ``None`` it is derived from
            ``category`` (NOT_FOUND→404, INVALID_INPUT→400, PRECONDITION→400,
            UNSUPPORTED→400, INTERNAL→500).
        code: Optional machine-readable error code for structured transports.
        details: Optional free-form mapping with extra context.
    """

    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory = ErrorCategory.INVALID_INPUT,
        status: Optional[int] = None,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.status = status if status is not None else _CATEGORY_STATUS[category]
        self.code = code
        self.details = details

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """Return a structured payload suitable for optional transports."""
        return {
            "error": self.message,
            "code": self.code,
            "category": self.category.name,
        }

    def to_error_body(self) -> Dict[str, Any]:
        """Legacy flat error dict: the message plus any details merged at top level.

        Distinct from :meth:`to_dict` (which adds ``code``/``category``) — this is
        the shape the inspect/pipeline surface presenters reproduce for backward
        compatibility.
        """
        body: Dict[str, Any] = {"error": self.message}
        if self.details:
            body.update(self.details)
        return body


# ---------------------------------------------------------------------------
# Concrete subclasses with sensible default categories/codes.
#
# Each only pre-fills a default and still forwards ``status``, ``details``,
# and any explicit ``category``/``code`` override through to
# :class:`CapabilityError`. They intentionally add no new behaviour.
# ---------------------------------------------------------------------------


class FileNotFoundServiceError(CapabilityError):
    """A required file (dump, key, dataset) could not be located."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("category", ErrorCategory.NOT_FOUND)
        super().__init__(message, **kwargs)


class OffsetOutOfRangeError(CapabilityError):
    """A requested offset/length falls outside the readable range."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("category", ErrorCategory.INVALID_INPUT)
        super().__init__(message, **kwargs)


class UnknownAlgorithmError(CapabilityError):
    """A referenced algorithm name is not registered."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("category", ErrorCategory.INVALID_INPUT)
        kwargs.setdefault("code", "algo.unknown")
        super().__init__(message, **kwargs)


class UnsupportedFormatError(CapabilityError):
    """The input format/operation is recognised but not supported."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("category", ErrorCategory.UNSUPPORTED)
        super().__init__(message, **kwargs)
