"""Unit tests for the transport-agnostic error model.

Covers :mod:`memdiver.core.service_errors` (category→status defaults and
``to_dict`` shape) plus the re-basing of ``AnalysisServiceError`` onto
:class:`CapabilityError` while preserving its historic ``ValueError``
identity, ``.status`` hints, and per-subclass fields.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.api.services.analysis_service import (
    AnalysisServiceError,
    DumpsNotFoundError,
    EmptyRegionError,
    InsufficientStaticError,
    NoVolatileRegionsError,
    TooFewDumpsError,
    UnknownFormatError,
)


# -- CapabilityError: category -> status defaults ------------------------


@pytest.mark.parametrize(
    "category,expected_status",
    [
        (ErrorCategory.NOT_FOUND, 404),
        (ErrorCategory.INVALID_INPUT, 400),
        (ErrorCategory.PRECONDITION, 400),
        (ErrorCategory.UNSUPPORTED, 400),
        (ErrorCategory.INTERNAL, 500),
    ],
)
def test_category_status_defaults(category, expected_status):
    err = CapabilityError("boom", category=category)
    assert err.status == expected_status


def test_default_category_is_invalid_input():
    err = CapabilityError("boom")
    assert err.category is ErrorCategory.INVALID_INPUT
    assert err.status == 400


def test_explicit_status_overrides_category_default():
    err = CapabilityError("boom", category=ErrorCategory.NOT_FOUND, status=418)
    assert err.status == 418


def test_str_returns_message():
    err = CapabilityError("something went wrong")
    assert str(err) == "something went wrong"
    assert err.message == "something went wrong"


def test_to_dict_shape():
    err = CapabilityError(
        "bad thing",
        category=ErrorCategory.UNSUPPORTED,
        code="E_UNSUP",
        details={"hint": "try json"},
    )
    assert err.to_dict() == {
        "error": "bad thing",
        "code": "E_UNSUP",
        "category": "UNSUPPORTED",
    }


def test_to_dict_code_defaults_none():
    err = CapabilityError("plain")
    assert err.to_dict() == {
        "error": "plain",
        "code": None,
        "category": "INVALID_INPUT",
    }


# -- AnalysisServiceError re-basing --------------------------------------


def test_analysis_error_is_capability_error():
    err = AnalysisServiceError("generic")
    assert isinstance(err, CapabilityError)


def test_analysis_error_still_is_value_error():
    """Backward-compat: historic ``except ValueError`` must still catch it."""
    err = AnalysisServiceError("generic")
    assert isinstance(err, ValueError)


def test_analysis_error_base_defaults():
    err = AnalysisServiceError("generic")
    assert err.status == 400
    assert err.category is ErrorCategory.INVALID_INPUT
    assert str(err) == "generic"


# -- Subclasses preserve status, category, message, and extra fields -----


def test_dumps_not_found():
    err = DumpsNotFoundError(["a", "b", "c", "d"])
    assert err.status == 404
    assert err.category is ErrorCategory.NOT_FOUND
    assert err.missing == ["a", "b", "c", "d"]
    assert str(err) == "Files not found: ['a', 'b', 'c']"


def test_too_few_dumps():
    err = TooFewDumpsError()
    assert err.status == 400
    assert err.category is ErrorCategory.PRECONDITION
    assert str(err) == "Need at least 2 dumps"


def test_no_volatile_regions():
    err = NoVolatileRegionsError()
    assert err.status == 404
    assert err.category is ErrorCategory.NOT_FOUND


def test_empty_region():
    err = EmptyRegionError()
    assert err.status == 500
    assert err.category is ErrorCategory.INTERNAL


def test_insufficient_static():
    err = InsufficientStaticError(0.12, 0.3)
    assert err.status == 400
    assert err.category is ErrorCategory.PRECONDITION
    assert err.ratio == 0.12
    assert err.required == 0.3
    assert "12.0% static" in str(err)


def test_unknown_format():
    err = UnknownFormatError("bmp")
    assert err.status == 400
    assert err.category is ErrorCategory.UNSUPPORTED
    assert err.format == "bmp"
    assert str(err) == "Unknown format: bmp"
