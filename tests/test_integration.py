"""Integration tests — end-to-end flows using synthetic fixture dataset."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from tests.fixtures.generate_fixtures import (
    generate_dataset, DATASET_ROOT,
    TLS12_SECRET_OFFSET,
    TLS12_SECRET_VALUES_BY_RUN,
)
from core.discovery import DatasetScanner, RunDiscovery
from core.input_schemas import AnalyzeRequest
from engine.pipeline import AnalysisPipeline
from core.variance import ByteClass
from engine.consensus import ConsensusVector
from engine.serializer import serialize_result


@pytest.fixture(scope="module", autouse=True)
def fixture_dataset():
    """Ensure fixture dataset exists before tests run."""
    return generate_dataset()


# --- DatasetScanner tests ---

def test_fast_scan_discovers_fixture_dataset():
    info = DatasetScanner(DATASET_ROOT).fast_scan()
    assert {"12", "13"} <= info.protocol_versions  # TLS versions present
    assert "2" in info.protocol_versions  # SSH version present
    assert "scenario_a" in info.scenarios["12"]
    assert "scenario_a" in info.scenarios["13"]
    assert "12/scenario_a/openssl" in info.phases
    assert "13/scenario_a/boringssl" in info.phases
    assert info.total_runs == 6  # 2 TLS12 + 2 TLS13 + 2 SSH2
    # Both libraries should appear in scenario_a (H1 fix)
    assert "openssl" in info.libraries["scenario_a"]
    assert "boringssl" in info.libraries["scenario_a"]


def test_fast_scan_phases_populated():
    info = DatasetScanner(DATASET_ROOT).fast_scan()
    assert "12/scenario_a/openssl" in info.phases
    assert "13/scenario_a/boringssl" in info.phases
    assert len(info.phases["12/scenario_a/openssl"]) == 4
    assert len(info.phases["13/scenario_a/boringssl"]) == 6


# --- RunDiscovery tests ---

def test_discover_library_runs_openssl():
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    runs = RunDiscovery.discover_library_runs(openssl_dir)
    assert len(runs) == 2
    assert len(runs[0].dumps) == 4
    assert len(runs[0].secrets) == 1
    assert runs[0].secrets[0].secret_type == "CLIENT_RANDOM"
    assert runs[0].secrets[0].secret_value == TLS12_SECRET_VALUES_BY_RUN[1]


def test_discover_library_runs_boringssl():
    boringssl_dir = DATASET_ROOT / "TLS13" / "scenario_a" / "boringssl"
    runs = RunDiscovery.discover_library_runs(boringssl_dir)
    assert len(runs) == 2
    assert len(runs[0].dumps) == 6
    assert len(runs[0].secrets) == 5


# --- Pipeline analysis tests ---

def test_pipeline_analyze_finds_tls12_secret():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    report = pipeline.analyze_library(
        openssl_dir, phase="pre_abort", protocol_version="12", expand_keys=False,
    )
    assert report.library == "openssl"
    assert report.num_runs == 2
    assert len(report.hits) > 0
    offsets = {(h.secret_type, h.offset) for h in report.hits}
    assert ("CLIENT_RANDOM", TLS12_SECRET_OFFSET) in offsets


def test_pipeline_analyze_finds_tls13_secrets():
    pipeline = AnalysisPipeline()
    boringssl_dir = DATASET_ROOT / "TLS13" / "scenario_a" / "boringssl"
    report = pipeline.analyze_library(
        boringssl_dir, phase="pre_abort", protocol_version="13", expand_keys=False,
    )
    hit_types = {h.secret_type for h in report.hits}
    assert "CLIENT_TRAFFIC_SECRET_0" in hit_types
    assert "SERVER_TRAFFIC_SECRET_0" in hit_types
    assert "EXPORTER_SECRET" in hit_types
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" not in hit_types
    assert "SERVER_HANDSHAKE_TRAFFIC_SECRET" not in hit_types


def test_pipeline_analyze_zeroed_phase():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    report = pipeline.analyze_library(
        openssl_dir, phase="post_abort", protocol_version="12", expand_keys=False,
    )
    assert len(report.hits) == 0


def test_pipeline_run_multi_library():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    request = AnalyzeRequest(
        library_dirs=[openssl_dir], phase="pre_abort",
        protocol_version="12", expand_keys=False,
    )
    result = pipeline.run(request)
    assert len(result.libraries) == 1
    assert result.total_hits > 0


# --- ConsensusVector tests ---

def test_consensus_cross_run_variance():
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    runs = RunDiscovery.discover_library_runs(openssl_dir)
    dump_paths = [runs[0].dumps[0].path, runs[1].dumps[0].path]
    cm = ConsensusVector()
    cm.build(dump_paths)
    # Secret region (different across runs due to per-run XOR) should be key_candidate
    for i in range(TLS12_SECRET_OFFSET, TLS12_SECRET_OFFSET + 32):
        assert cm.classifications[i] == ByteClass.KEY_CANDIDATE
    # Padding region (0x00 vs 0xFE) should NOT be invariant
    assert cm.classifications[0] != ByteClass.INVARIANT


# --- Serialization tests ---

def test_full_flow_serialize():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    request = AnalyzeRequest(
        library_dirs=[openssl_dir], phase="pre_abort",
        protocol_version="12", expand_keys=False,
    )
    result = pipeline.run(request)
    data = serialize_result(result)
    assert isinstance(data, dict)
    assert "libraries" in data
    assert "total_hits" in data
    assert data["total_hits"] > 0
    json.dumps(data)  # Must be JSON-serializable
