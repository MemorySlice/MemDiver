"""Phase normalization integration tests using synthetic fixture dataset."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from tests.fixtures.generate_fixtures import generate_dataset, DATASET_ROOT
from core.discovery import DatasetScanner, RunDiscovery
from core.phase_normalizer import PhaseNormalizer, CANONICAL_PHASE_ORDER
from engine.pipeline import AnalysisPipeline


@pytest.fixture(scope="module", autouse=True)
def fixture_dataset():
    """Ensure fixture dataset exists before tests run."""
    return generate_dataset()


def test_normalizer_maps_openssl_phases():
    runs = RunDiscovery.discover_library_runs(
        DATASET_ROOT / "TLS12" / "scenario_a" / "openssl",
    )
    mappings = PhaseNormalizer().normalize_run(runs[0])
    assert mappings["pre_handshake"].canonical_phase == "pre_handshake_end"
    assert mappings["post_handshake"].canonical_phase == "post_handshake_end"
    assert mappings["pre_abort"].canonical_phase == "pre_second_event"
    assert mappings["post_abort"].canonical_phase == "post_second_event"


def test_normalizer_maps_boringssl_phases():
    runs = RunDiscovery.discover_library_runs(
        DATASET_ROOT / "TLS13" / "scenario_a" / "boringssl",
    )
    mappings = PhaseNormalizer().normalize_run(runs[0])
    assert len(mappings) == 6
    assert mappings["pre_handshake"].canonical_phase == "pre_handshake_end"
    assert mappings["post_handshake"].canonical_phase == "post_handshake_end"
    assert mappings["pre_abort"].canonical_phase == "pre_second_event"
    assert mappings["post_abort"].canonical_phase == "post_second_event"
    assert mappings["pre_cleanup"].canonical_phase == "pre_cleanup"
    assert mappings["post_cleanup"].canonical_phase == "post_cleanup"


def test_pipeline_normalize_resolves_canonical():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    report = pipeline.analyze_library(
        openssl_dir, phase="pre_second_event", protocol_version="12",
        normalize=True, expand_keys=False,
    )
    assert len(report.hits) > 0
    hit_types = {h.secret_type for h in report.hits}
    assert "CLIENT_RANDOM" in hit_types
    # Output phase name should be canonical when normalize=True
    assert report.phase == "pre_second_event"
    for hit in report.hits:
        assert hit.phase == "pre_second_event"


def test_pipeline_normalize_false_canonical_no_match():
    pipeline = AnalysisPipeline()
    openssl_dir = DATASET_ROOT / "TLS12" / "scenario_a" / "openssl"
    report = pipeline.analyze_library(
        openssl_dir, phase="pre_second_event", protocol_version="12",
        normalize=False, expand_keys=False,
    )
    assert len(report.hits) == 0


def test_fast_scan_normalized_phases_populated():
    info = DatasetScanner(DATASET_ROOT).fast_scan()
    assert "12/scenario_a/openssl" in info.normalized_phases
    openssl_norm = info.normalized_phases["12/scenario_a/openssl"]
    assert "pre_handshake_end" in openssl_norm
    assert "post_second_event" in openssl_norm
    boringssl_norm = info.normalized_phases["13/scenario_a/boringssl"]
    assert "pre_cleanup" in boringssl_norm
    assert "post_cleanup" in boringssl_norm


def test_canonical_phase_order():
    expected = [
        "pre_key_update", "post_key_update",
        "pre_handshake_end", "post_handshake_end",
        "pre_second_event", "post_second_event",
        "pre_cleanup", "post_cleanup",
    ]
    assert CANONICAL_PHASE_ORDER == expected
    normalizer = PhaseNormalizer()
    runs = RunDiscovery.discover_library_runs(
        DATASET_ROOT / "TLS13" / "scenario_a" / "boringssl",
    )
    canonical_phases = normalizer.available_canonical_phases(runs)
    for phase in canonical_phases:
        assert phase in CANONICAL_PHASE_ORDER
