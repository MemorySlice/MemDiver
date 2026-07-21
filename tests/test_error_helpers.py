"""Unit tests for the two shared error-rendering helpers introduced by the
/simplify pass: ``CapabilityError.to_error_body`` and ``KeyStatus.locked_error_dict``.

Both centralize a legacy dict shape that the inspect/pipeline presenters used to
build inline at multiple call sites. These tests lock the exact shapes so the
centralization can never silently drift from the byte-for-byte contract.
"""

from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    OffsetOutOfRangeError,
)
from memdiver.core.service_result import KeyStatus
from memdiver.msl.enums import TagStatus


def test_to_error_body_message_only():
    err = CapabilityError("boom")
    assert err.to_error_body() == {"error": "boom"}


def test_to_error_body_merges_details_at_top_level():
    err = OffsetOutOfRangeError(
        "offset out of range",
        details={"offset": 99, "file_size": 10, "view": "vas", "format": "msl"},
    )
    assert err.to_error_body() == {
        "error": "offset out of range",
        "offset": 99,
        "file_size": 10,
        "view": "vas",
        "format": "msl",
    }


def test_to_error_body_is_distinct_from_to_dict():
    err = CapabilityError("bad", category=ErrorCategory.INVALID_INPUT, code="x.y")
    # to_dict carries code/category; to_error_body is the flat legacy shape.
    assert err.to_error_body() == {"error": "bad"}
    assert err.to_dict() == {"error": "bad", "code": "x.y", "category": "INVALID_INPUT"}


def test_locked_error_dict_missing_key():
    key = KeyStatus.from_source(_Stub(TagStatus.MISSING_KEY))
    assert key.decrypted is False
    assert key.locked_error_dict() == {
        "error": "dump is encrypted; supply --key-file / --passphrase / --kem-key-file",
        "tag_status": "missing_key",
    }


def test_locked_error_dict_corrupted():
    key = KeyStatus.from_source(_Stub(TagStatus.CORRUPTED))
    assert key.locked_error_dict() == {
        "error": "AEAD verification failed (wrong key or tampered file)",
        "tag_status": "corrupted",
    }


class _Stub:
    def __init__(self, tag_status):
        self.tag_status = tag_status
