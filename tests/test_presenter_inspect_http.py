"""Unit tests for the API inspect presenter + hard-error wrapper.

``present_inspect_http`` is the API surface: it emits ONLY a ServiceResult's
payload and DROPS the key/tag status block (the Web UI reads the diagnostic
from the dedicated /tag-status endpoints instead). ``_http_inspect`` preserves
today's HTTP contract by turning the producers' hard-error raises back into the
legacy 200-with-error-dict bodies.

These tests exercise both functions directly with fixed inputs, so they do not
touch the filesystem or FastAPI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from memdiver.api.routers.inspect import _http_inspect, present_inspect_http
from memdiver.core.service_errors import (
    CapabilityError,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import (
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)
from memdiver.msl.enums import TagStatus


def _result(payload: dict, tag_status: TagStatus, *, decrypted: bool,
            resolution: Resolution) -> ServiceResult:
    """Build a fixed ServiceResult with a chosen key/tag status block."""
    key = KeyStatus(tag_status=tag_status, decrypted=decrypted,
                    hint=None if decrypted else "some hint")
    return ServiceResult(
        payload=payload,
        status=StatusBlock(resolution=resolution, key=key),
    )


# --- present_inspect_http: emits payload only, never the status block -------

@pytest.mark.parametrize(
    "tag_status, decrypted, resolution",
    [
        (TagStatus.MISSING_KEY, False, Resolution.UNRESOLVED),   # missing_key
        (TagStatus.CORRUPTED, False, Resolution.UNRESOLVED),     # corrupted
        (TagStatus.VALID, True, Resolution.OK),                  # valid
        (TagStatus.NOT_ENCRYPTED, True, Resolution.OK),          # not_encrypted
    ],
)
def test_present_returns_exactly_payload_for_each_status(
    tag_status, decrypted, resolution,
):
    payload = {"region_count": 3, "coverage": 0.5, "offsets": [1, 2, 3]}
    result = _result(payload, tag_status, decrypted=decrypted,
                     resolution=resolution)

    presented = present_inspect_http(result)

    # Exactly the payload object, byte-for-byte — no status/tag leakage.
    assert presented is payload
    assert presented == payload
    for leaked in ("status", "resolution", "key", "tag_status", "hint",
                   "decrypted", "diagnostics"):
        assert leaked not in presented


def test_present_locked_empty_payload_reads_back_empty():
    """A locked dump's natural EMPTY payload passes through unchanged."""
    payload = {"regions": [], "region_count": 0, "length": 0}
    result = _result(payload, TagStatus.MISSING_KEY, decrypted=False,
                     resolution=Resolution.UNRESOLVED)

    presented = present_inspect_http(result)

    assert presented == {"regions": [], "region_count": 0, "length": 0}
    assert "tag_status" not in presented
    assert "hint" not in presented


# --- _http_inspect: reproduces the legacy 200-with-error-dict bodies --------

def test_http_inspect_passes_through_success_payload():
    payload = {"offset": 0, "length": 16}
    result = ServiceResult.ok(payload)
    assert _http_inspect(lambda: result) == payload


def test_http_inspect_file_not_found_matches_legacy_dict():
    def produce():
        raise FileNotFoundServiceError("File not found: /nope.msl")

    assert _http_inspect(produce) == {"error": "File not found: /nope.msl"}


def test_http_inspect_offset_out_of_range_merges_details():
    def produce():
        raise OffsetOutOfRangeError(
            "offset out of range",
            details={
                "offset": 999,
                "file_size": 128,
                "view": "raw",
                "format": "msl",
            },
        )

    assert _http_inspect(produce) == {
        "error": "offset out of range",
        "offset": 999,
        "file_size": 128,
        "view": "raw",
        "format": "msl",
    }


def test_http_inspect_empty_byte_pattern_matches_legacy_dict():
    """Reproduces search_bytes_result's bare CapabilityError (no details)."""
    def produce():
        raise CapabilityError("Empty byte pattern")

    assert _http_inspect(produce) == {"error": "Empty byte pattern"}


def test_http_inspect_invalid_hex_pattern_matches_legacy_dict():
    """Reproduces search_bytes_result's invalid-hex CapabilityError."""
    def produce():
        raise CapabilityError("Invalid hex byte pattern: 'zz'")

    assert _http_inspect(produce) == {"error": "Invalid hex byte pattern: 'zz'"}


def test_http_inspect_unsupported_format_matches_legacy_dict():
    """Reproduces resolve_va_result's UnsupportedFormatError (no details)."""
    def produce():
        raise UnsupportedFormatError("VA translation requires an MSL dump")

    assert _http_inspect(produce) == {
        "error": "VA translation requires an MSL dump",
    }
