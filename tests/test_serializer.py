"""Tests for engine.serializer module."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.discovery import DatasetInfo
from engine.results import AnalysisResult, LibraryReport, SecretHit, StaticRegion
from engine.serializer import (
    _convert_value,
    serialize_dataset_info,
    serialize_hit,
    serialize_report,
    serialize_result,
    serialize_static_region,
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
