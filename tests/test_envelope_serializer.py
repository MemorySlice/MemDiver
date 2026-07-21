"""Tests for the envelope -> dict bridge in ``memdiver.engine.envelope_serializer``."""

from memdiver.core.service_result import (
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)
from memdiver.engine.envelope_serializer import (
    STATUS_KEY,
    serialize_envelope,
)
from memdiver.engine.results import AnalysisResult, LibraryReport


def _sample_analysis_result() -> AnalysisResult:
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(
            library="libssl",
            protocol_version="TLS 1.3",
            phase="handshake",
            num_runs=3,
        )
    )
    result.metadata = {"note": "sample"}
    return result


def test_include_status_true_attaches_status():
    env = ServiceResult.ok(_sample_analysis_result())
    out = serialize_envelope(env, include_status=True)
    assert STATUS_KEY in out
    assert out[STATUS_KEY] == env.status.to_dict()
    # payload fields from serialize_result are present
    assert "libraries" in out
    assert "total_hits" in out
    assert out["libraries"][0]["library"] == "libssl"


def test_include_status_false_omits_status():
    env = ServiceResult.ok(_sample_analysis_result())
    out = serialize_envelope(env, include_status=False)
    assert STATUS_KEY not in out
    assert "libraries" in out


def test_status_reflects_key_state():
    missing = KeyStatus.from_source(
        type("S", (), {"tag_status": __import__(
            "memdiver.msl.enums", fromlist=["TagStatus"]
        ).TagStatus.MISSING_KEY})()
    )
    env = ServiceResult.ok(_sample_analysis_result()).with_key(missing)
    out = serialize_envelope(env, include_status=True)
    assert out[STATUS_KEY]["resolution"] == Resolution.UNRESOLVED.value
    assert out[STATUS_KEY]["key"]["decrypted"] is False


def test_dict_payload_passthrough_is_not_mutated():
    payload = {"foo": "bar"}
    env = ServiceResult(payload=payload, status=StatusBlock())
    out = serialize_envelope(env, include_status=True)
    assert out["foo"] == "bar"
    assert STATUS_KEY in out
    # original payload dict must be untouched
    assert STATUS_KEY not in payload


def test_library_report_payload_uses_report_serializer():
    report = LibraryReport(
        library="libcrypto",
        protocol_version="TLS 1.2",
        phase="steady",
        num_runs=1,
    )
    env = ServiceResult.ok(report)
    out = serialize_envelope(env, include_status=False)
    assert out["library"] == "libcrypto"
    assert out["protocol_version"] == "TLS 1.2"
    assert out["hits"] == []
