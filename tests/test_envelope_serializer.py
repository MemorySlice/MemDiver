"""Tests for the envelope -> dict bridge in ``memdiver.engine.envelope_serializer``."""

from dataclasses import dataclass
from pathlib import Path

from memdiver.core.discovery import DatasetInfo
from memdiver.core.service_result import (
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)
from memdiver.engine.convergence import ConvergenceSweepResult
from memdiver.engine.envelope_serializer import (
    STATUS_KEY,
    serialize_envelope,
)
from memdiver.engine.results import AnalysisResult, LibraryReport, SecretHit, StaticRegion
from memdiver.engine.verification import VerificationResult


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


def test_secret_hit_payload_uses_hit_serializer():
    hit = SecretHit(
        secret_type="aes_key",
        offset=128,
        length=32,
        dump_path=Path("/tmp/dump.bin"),
        library="libssl",
        phase="handshake",
        run_id=1,
    )
    env = ServiceResult.ok(hit)
    out = serialize_envelope(env, include_status=False)
    assert out["secret_type"] == "aes_key"
    assert out["dump_path"] == "/tmp/dump.bin"
    assert out["confidence"] == 1.0


def test_static_region_payload_uses_static_region_serializer():
    region = StaticRegion(start=0, end=64, mean_variance=0.0, classification="invariant")
    env = ServiceResult.ok(region)
    out = serialize_envelope(env, include_status=False)
    assert out["start"] == 0
    assert out["end"] == 64
    # `length` is a derived property on StaticRegion, not a dataclass field;
    # only the dedicated serializer knows to compute it, so its presence
    # proves the right serializer (not the dataclass-fields fallback) ran.
    assert out["length"] == 64


def test_convergence_sweep_result_payload_uses_convergence_serializer():
    result = ConvergenceSweepResult(points=[], total_dumps=10, max_fp=2)
    env = ServiceResult.ok(result)
    out = serialize_envelope(env, include_status=False)
    assert out["points"] == []
    assert out["total_dumps"] == 10
    assert out["max_fp"] == 2


def test_verification_result_payload_uses_verification_serializer():
    result = VerificationResult(
        offset=0, key_hex="aa" * 16, cipher_name="aes-128-gcm", verified=True
    )
    env = ServiceResult.ok(result)
    out = serialize_envelope(env, include_status=False)
    assert out["cipher_name"] == "aes-128-gcm"
    assert out["verified"] is True


def test_dataset_info_payload_uses_dataset_info_serializer():
    info = DatasetInfo(
        protocol_versions={"TLS 1.3"},
        scenarios={},
        libraries={"libssl": {"TLS 1.3"}},
        phases={},
        normalized_phases={},
        total_runs=5,
        protocols_info={},
        root=Path("/tmp/dataset"),
    )
    env = ServiceResult.ok(info)
    out = serialize_envelope(env, include_status=False)
    assert out["root"] == "/tmp/dataset"
    # sorted(set) via serialize_dataset_info, not the raw set on the dataclass
    assert out["protocol_versions"] == ["TLS 1.3"]
    assert out["total_runs"] == 5


def test_unregistered_dataclass_falls_back_to_shallow_field_dict():
    @dataclass
    class _NotRegistered:
        a: int
        b: str

    env = ServiceResult.ok(_NotRegistered(a=1, b="x"))
    out = serialize_envelope(env, include_status=False)
    assert out == {"a": 1, "b": "x"}


def test_non_dataclass_non_dict_payload_falls_back_to_value_key():
    env = ServiceResult.ok(42)
    out = serialize_envelope(env, include_status=False)
    assert out == {"value": 42}
