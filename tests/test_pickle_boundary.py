"""Pickle / JSON boundary tests for the neutral result envelope.

The envelope will cross a ``ProcessPool`` boundary later, so every value type
must survive a ``pickle`` round-trip, and the serialized dict must be
JSON-serializable.
"""

import json
import pickle

from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnknownAlgorithmError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import (
    Diagnostic,
    KeyStatus,
    Resolution,
    ServiceResult,
    Severity,
    StatusBlock,
)
from memdiver.engine.envelope_serializer import serialize_envelope
from memdiver.engine.results import AnalysisResult, LibraryReport
from memdiver.msl.enums import TagStatus


def _populated_envelope() -> ServiceResult:
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(
            library="libssl",
            protocol_version="TLS 1.3",
            phase="handshake",
            num_runs=2,
        )
    )
    diag = Diagnostic(
        code="scan.partial",
        message="one region skipped",
        severity=Severity.INFO,
        details={"skipped": 1},
    )
    key = KeyStatus(tag_status=TagStatus.VALID, decrypted=True)
    return ServiceResult(
        payload=result,
        status=StatusBlock(
            resolution=Resolution.PARTIAL,
            key=key,
            diagnostics=(diag,),
        ),
    )


def test_service_result_pickle_round_trip():
    env = _populated_envelope()
    restored = pickle.loads(pickle.dumps(env))
    assert restored.status.resolution is Resolution.PARTIAL
    assert restored.status.key == env.status.key
    assert restored.status.diagnostics == env.status.diagnostics
    assert restored.payload.total_hits == env.payload.total_hits
    assert restored.payload.libraries[0].library == "libssl"


def test_status_block_equality_after_pickle():
    block = StatusBlock(
        resolution=Resolution.UNRESOLVED,
        key=KeyStatus.from_source(
            type("S", (), {"tag_status": TagStatus.MISSING_KEY})()
        ),
        diagnostics=(Diagnostic(code="c", message="m"),),
    )
    assert pickle.loads(pickle.dumps(block)) == block


def test_capability_error_pickle_round_trip():
    err = CapabilityError(
        "boom",
        category=ErrorCategory.PRECONDITION,
        code="x.y",
        details={"k": "v"},
    )
    restored = pickle.loads(pickle.dumps(err))
    assert restored.message == "boom"
    assert restored.category is ErrorCategory.PRECONDITION
    assert restored.status == err.status
    assert restored.code == "x.y"
    assert restored.details == {"k": "v"}


def test_subclass_error_pickle_round_trip():
    err = UnknownAlgorithmError("no such algo")
    restored = pickle.loads(pickle.dumps(err))
    assert isinstance(restored, UnknownAlgorithmError)
    assert restored.category is ErrorCategory.INVALID_INPUT
    assert restored.code == "algo.unknown"
    assert restored.message == "no such algo"


def test_file_not_found_service_error_defaults_and_pickle():
    err = FileNotFoundServiceError("File not found: /nope.msl")
    assert err.category is ErrorCategory.NOT_FOUND
    assert err.status == 404
    assert err.code is None
    restored = pickle.loads(pickle.dumps(err))
    assert isinstance(restored, FileNotFoundServiceError)
    assert restored.category is ErrorCategory.NOT_FOUND
    assert restored.message == "File not found: /nope.msl"


def test_offset_out_of_range_error_defaults_and_pickle():
    err = OffsetOutOfRangeError("offset out of range", details={"offset": 99})
    assert err.category is ErrorCategory.INVALID_INPUT
    assert err.status == 400
    assert err.details == {"offset": 99}
    restored = pickle.loads(pickle.dumps(err))
    assert isinstance(restored, OffsetOutOfRangeError)
    assert restored.category is ErrorCategory.INVALID_INPUT
    assert restored.details == {"offset": 99}


def test_unsupported_format_error_defaults_and_pickle():
    err = UnsupportedFormatError("format not supported")
    assert err.category is ErrorCategory.UNSUPPORTED
    assert err.status == 400
    restored = pickle.loads(pickle.dumps(err))
    assert isinstance(restored, UnsupportedFormatError)
    assert restored.category is ErrorCategory.UNSUPPORTED
    assert restored.message == "format not supported"


def test_subclasses_forward_explicit_overrides_to_base():
    """Subclasses only *default* category/code — explicit kwargs must win."""
    err = UnknownAlgorithmError(
        "custom", category=ErrorCategory.PRECONDITION, code="custom.code", status=418
    )
    assert err.category is ErrorCategory.PRECONDITION
    assert err.code == "custom.code"
    assert err.status == 418


def test_serialized_envelope_is_json_serializable():
    env = _populated_envelope()
    payload = serialize_envelope(env, include_status=True)
    text = json.dumps(payload)
    assert isinstance(text, str)
    # round-trips back to an equal dict
    assert json.loads(text) == payload
