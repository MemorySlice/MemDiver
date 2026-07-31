"""Tests for engine.serializer module."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.discovery import DatasetInfo
from memdiver.engine.results import AnalysisResult, LibraryReport, SecretHit, StaticRegion
from memdiver.engine.serializer import (
    _convert_value,
    serialize_dataset_info,
    serialize_hit,
    serialize_report,
    serialize_result,
    serialize_static_region,
    summarize_result,
)


def test_convert_path():
    assert _convert_value(Path("/tmp/test")) == "/tmp/test"


def test_convert_bytes():
    assert _convert_value(b"\xde\xad") == "dead"


def test_convert_set():
    assert _convert_value({"b", "a"}) == ["a", "b"]


def test_serialize_hit():
    hit = SecretHit(
        secret_type="CLIENT_RANDOM",
        offset=100,
        length=32,
        dump_path=Path("/tmp/test.dump"),
        library="openssl",
        phase="pre_abort",
        run_id=1,
    )
    d = serialize_hit(hit)
    assert d["dump_path"] == "/tmp/test.dump"
    assert d["secret_type"] == "CLIENT_RANDOM"
    assert isinstance(d, dict)


def test_serialize_static_region():
    region = StaticRegion(start=0, end=16, mean_variance=0.01, classification="invariant")
    d = serialize_static_region(region)
    assert d["length"] == 16
    assert d["start"] == 0


def test_serialize_report():
    report = LibraryReport(
        library="openssl",
        protocol_version="13",
        phase="pre_abort",
        num_runs=3,
    )
    d = serialize_report(report)
    assert d["library"] == "openssl"
    assert d["hits"] == []


def test_serialize_result():
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(library="test", protocol_version="13", phase="pre_abort", num_runs=1)
    )
    d = serialize_result(result)
    assert d["total_hits"] == 0
    assert len(d["libraries"]) == 1


def test_serialize_dataset_info():
    info = DatasetInfo(
        protocol_versions={"12", "13"},
        root=Path("/tmp/data"),
        total_runs=5,
    )
    d = serialize_dataset_info(info)
    assert d["root"] == "/tmp/data"
    assert d["protocol_versions"] == ["12", "13"]
    assert d["total_runs"] == 5


def _representative_result() -> AnalysisResult:
    """An AnalysisResult with two libraries and a mix of hits/metadata."""
    result = AnalysisResult(metadata={"source": "unit-test"})
    result.libraries.append(
        LibraryReport(
            library="openssl",
            protocol_version="13",
            phase="pre_abort",
            num_runs=3,
            hits=[
                SecretHit(
                    secret_type="CLIENT_RANDOM",
                    offset=100,
                    length=32,
                    dump_path=Path("/tmp/a.dump"),
                    library="openssl",
                    phase="pre_abort",
                    run_id=1,
                ),
                SecretHit(
                    secret_type="SERVER_RANDOM",
                    offset=200,
                    length=32,
                    dump_path=Path("/tmp/a.dump"),
                    library="openssl",
                    phase="pre_abort",
                    run_id=2,
                ),
            ],
        )
    )
    result.libraries.append(
        LibraryReport(
            library="gnutls",
            protocol_version="12",
            phase="post_handshake",
            num_runs=1,
        )
    )
    return result


def test_summarize_result_equivalence_lock():
    """summarize_result must be byte-identical to the runner's legacy
    _result_summary for the serialized-dict inputs the runner passes."""
    from memdiver.app.pipeline.analysis_task_runner import _result_summary

    result = _representative_result()
    serialized = serialize_result(result)

    canonical = summarize_result(serialized)
    legacy = _result_summary(serialized)
    assert canonical == legacy
    # Delegation means the wrapper now IS summarize_result; also confirm the
    # dataclass path matches the serialized-dict path.
    assert summarize_result(result) == canonical

    # Lock the exact shape and values.
    assert canonical == {
        "library_count": 2,
        "total_hits": 2,
        "libraries": [
            {"library": "openssl", "phase": "pre_abort", "num_runs": 3, "hit_count": 2},
            {"library": "gnutls", "phase": "post_handshake", "num_runs": 1, "hit_count": 0},
        ],
    }


def test_summarize_result_json_safe():
    """The summary must survive json.dumps for the ProcessPool boundary."""
    summary = summarize_result(_representative_result())
    text = json.dumps(summary)
    assert json.loads(text) == summary


def test_json_roundtrip():
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(
            library="test",
            protocol_version="13",
            phase="pre_abort",
            num_runs=1,
            hits=[
                SecretHit(
                    secret_type="KEY",
                    offset=0,
                    length=32,
                    dump_path=Path("/tmp/x.dump"),
                    library="test",
                    phase="pre_abort",
                    run_id=1,
                    metadata={"raw": b"\xaa\xbb"},
                )
            ],
        )
    )
    d = serialize_result(result)
    text = json.dumps(d)
    parsed = json.loads(text)
    assert parsed["total_hits"] == 1
    assert parsed["libraries"][0]["hits"][0]["metadata"]["raw"] == "aabb"
