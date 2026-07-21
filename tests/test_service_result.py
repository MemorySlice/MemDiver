"""Tests for the neutral result envelope in ``memdiver.core.service_result``."""

from dataclasses import dataclass

import pytest

from memdiver.core.service_result import (
    Diagnostic,
    KeyStatus,
    Resolution,
    ServiceResult,
    Severity,
    StatusBlock,
)
from memdiver.msl.enums import TagStatus


@dataclass
class _StubSource:
    """Minimal stand-in for a reader/dump source exposing ``tag_status``."""

    tag_status: TagStatus


def test_construct_each_dataclass():
    diag = Diagnostic(code="x.y", message="hello")
    assert diag.severity is Severity.WARNING
    assert diag.details == {}

    key = KeyStatus()
    assert key.tag_status is TagStatus.NOT_ENCRYPTED
    assert key.decrypted is True
    assert key.hint is None

    block = StatusBlock()
    assert block.resolution is Resolution.OK
    assert isinstance(block.key, KeyStatus)
    assert block.diagnostics == ()

    result = ServiceResult(payload={"a": 1})
    assert result.payload == {"a": 1}
    assert isinstance(result.status, StatusBlock)


@pytest.mark.parametrize(
    "status, expected_decrypted, expected_hint",
    [
        (
            TagStatus.MISSING_KEY,
            False,
            "dump is encrypted; supply --key-file / --passphrase / --kem-key-file",
        ),
        (
            TagStatus.CORRUPTED,
            False,
            "AEAD verification failed (wrong key or tampered file)",
        ),
        (TagStatus.VALID, True, None),
        (TagStatus.NOT_ENCRYPTED, True, None),
    ],
)
def test_key_status_from_source(status, expected_decrypted, expected_hint):
    key = KeyStatus.from_source(_StubSource(tag_status=status))
    assert key.tag_status is status
    assert key.decrypted is expected_decrypted
    assert key.hint == expected_hint


def test_from_source_defaults_when_attribute_missing():
    key = KeyStatus.from_source(object())
    assert key.tag_status is TagStatus.NOT_ENCRYPTED
    assert key.decrypted is True
    assert key.hint is None


def test_ok_classmethod():
    result = ServiceResult.ok(payload=[1, 2, 3])
    assert result.payload == [1, 2, 3]
    assert result.status == StatusBlock()


def test_with_key_flips_resolution_to_unresolved():
    missing = KeyStatus.from_source(_StubSource(tag_status=TagStatus.MISSING_KEY))
    result = ServiceResult.ok(payload={}).with_key(missing)
    assert result.status.resolution is Resolution.UNRESOLVED
    assert result.status.key is missing
    assert result.payload == {}


def test_with_key_keeps_resolution_when_decrypted():
    valid = KeyStatus.from_source(_StubSource(tag_status=TagStatus.VALID))
    result = ServiceResult.ok(payload={"k": "v"}).with_key(valid)
    assert result.status.resolution is Resolution.OK
    assert result.status.key is valid


def test_with_key_preserves_existing_diagnostics():
    diag = Diagnostic(code="c", message="m", severity=Severity.INFO)
    base = ServiceResult(
        payload={},
        status=StatusBlock(diagnostics=(diag,)),
    )
    valid = KeyStatus.from_source(_StubSource(tag_status=TagStatus.VALID))
    result = base.with_key(valid)
    assert result.status.diagnostics == (diag,)


def test_diagnostic_to_dict_shape_and_order():
    diag = Diagnostic(
        code="c1",
        message="msg",
        severity=Severity.INFO,
        details={"n": 1},
    )
    d = diag.to_dict()
    assert list(d.keys()) == ["code", "message", "severity", "details"]
    assert d == {
        "code": "c1",
        "message": "msg",
        "severity": "info",
        "details": {"n": 1},
    }


def test_key_status_to_dict_shape_and_order():
    key = KeyStatus.from_source(_StubSource(tag_status=TagStatus.MISSING_KEY))
    d = key.to_dict()
    assert list(d.keys()) == ["tag_status", "decrypted", "hint"]
    assert d == {
        "tag_status": "missing_key",
        "decrypted": False,
        "hint": "dump is encrypted; supply --key-file / --passphrase / --kem-key-file",
    }


def test_status_block_to_dict_shape_and_order():
    diag = Diagnostic(code="c", message="m")
    block = StatusBlock(
        resolution=Resolution.PARTIAL,
        key=KeyStatus(),
        diagnostics=(diag,),
    )
    d = block.to_dict()
    assert list(d.keys()) == ["resolution", "key", "diagnostics"]
    assert d["resolution"] == "partial"
    assert d["key"] == KeyStatus().to_dict()
    assert d["diagnostics"] == [diag.to_dict()]
