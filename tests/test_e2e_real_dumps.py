"""End-to-end tests using REAL BoringSSL TLS 1.3 memory dumps.

These tests exercise the full pipeline against actual memory dumps from the
100_iterations_Abort_KeyUpdate BoringSSL dataset. They verify discovery,
keylog parsing, analysis, key expansion, serialization, entropy, and the
FastAPI API layer using real data rather than synthetic fixtures.

All tests are guarded by ``REAL_DUMPS_AVAILABLE`` so they skip gracefully
on machines where the dataset is not present.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from tests._paths import dataset_root, SKIP_REASON

# ---------------------------------------------------------------------------
# Paths to real data (resolved via env/CLI/config; skip if unavailable)
# ---------------------------------------------------------------------------

DATASET_ROOT = dataset_root()
BORINGSSL_DIR = (
    DATASET_ROOT / "TLS13" / "100_iterations_Abort_KeyUpdate" / "boringssl"
    if DATASET_ROOT is not None
    else None
)
RUN1_DIR = BORINGSSL_DIR / "boringssl_run_13_1" if BORINGSSL_DIR is not None else None
RUN2_DIR = BORINGSSL_DIR / "boringssl_run_13_2" if BORINGSSL_DIR is not None else None

REAL_DUMPS_AVAILABLE = BORINGSSL_DIR is not None and BORINGSSL_DIR.is_dir()

real_dumps = pytest.mark.skipif(
    not REAL_DUMPS_AVAILABLE, reason=SKIP_REASON
)

# ---------------------------------------------------------------------------
# Imports (always importable even without real data)
# ---------------------------------------------------------------------------

from core.discovery import DatasetScanner, RunDiscovery
from core.keylog import KeylogParser
from core.entropy import shannon_entropy, compute_entropy_profile
from core.dump_source import RawDumpSource
from engine.pipeline import AnalysisPipeline
from engine.serializer import (
    serialize_result,
    deserialize_result,
    serialize_report,
    deserialize_report,
)
from core.input_schemas import AnalyzeRequest


# ===================================================================
# 1. Discovery tests — multi-level scan
# ===================================================================


@real_dumps
class TestDiscoveryAtAllLevels:
    """Verify DatasetScanner.fast_scan() at dataset, protocol, scenario,
    and library directory levels."""

    def test_scan_at_dataset_level(self):
        info = DatasetScanner(DATASET_ROOT).fast_scan()
        assert "13" in info.protocol_versions
        assert info.total_runs > 0

    def test_scan_at_protocol_level(self):
        proto_dir = DATASET_ROOT / "TLS13"
        info = DatasetScanner(proto_dir).fast_scan()
        assert "13" in info.protocol_versions
        assert info.total_runs > 0

    def test_scan_at_scenario_level(self):
        scenario_dir = DATASET_ROOT / "TLS13" / "100_iterations_Abort_KeyUpdate"
        info = DatasetScanner(scenario_dir).fast_scan()
        assert "13" in info.protocol_versions
        assert "boringssl" in info.libraries.get(
            "100_iterations_Abort_KeyUpdate", set()
        )
        assert info.total_runs >= 100

    def test_scan_at_library_level(self):
        info = DatasetScanner(BORINGSSL_DIR).fast_scan()
        assert info.total_runs >= 100
        # Should discover phases from at least one run
        found_phases = False
        for key, phases in info.phases.items():
            if phases:
                found_phases = True
                break
        assert found_phases, "No phases discovered at library level"


# ===================================================================
# 2. Keylog parsing
# ===================================================================


@real_dumps
class TestKeylogParsingRealDump:
    """Parse a real keylog.csv and verify TLS 1.3 secret types."""

    def test_parse_keylog_run1(self):
        keylog_path = RUN1_DIR / "keylog.csv"
        secrets = KeylogParser.parse(keylog_path)
        secret_types = {s.secret_type for s in secrets}
        expected = {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        }
        assert expected <= secret_types, (
            f"Missing types: {expected - secret_types}"
        )

    def test_secrets_have_32_byte_values(self):
        keylog_path = RUN1_DIR / "keylog.csv"
        secrets = KeylogParser.parse(keylog_path)
        for s in secrets:
            assert len(s.secret_value) == 32, (
                f"{s.secret_type} has {len(s.secret_value)} byte value, expected 32"
            )

    def test_different_runs_have_different_keys(self):
        secrets1 = KeylogParser.parse(RUN1_DIR / "keylog.csv")
        secrets2 = KeylogParser.parse(RUN2_DIR / "keylog.csv")
        values1 = {s.secret_value for s in secrets1}
        values2 = {s.secret_value for s in secrets2}
        assert values1.isdisjoint(values2), (
            "Run 1 and Run 2 should have completely different key material"
        )


# ===================================================================
# 3-5. Analysis pipeline at different phases
# ===================================================================


@real_dumps
class TestAnalysisPipelinePreAbort:
    """Run full pipeline on pre_abort — EXPORTER_SECRET should be found."""

    def test_exporter_secret_found(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="pre_abort",
            protocol_version="13",
            max_runs=2,
            expand_keys=False,
        )
        assert report.library == "boringssl"
        assert report.num_runs == 2
        hit_types = {h.secret_type for h in report.hits}
        assert "EXPORTER_SECRET" in hit_types, (
            f"EXPORTER_SECRET not found. Found: {hit_types}"
        )

    def test_handshake_secrets_absent_pre_abort(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="pre_abort",
            protocol_version="13",
            max_runs=2,
            expand_keys=False,
        )
        hit_types = {h.secret_type for h in report.hits}
        # BoringSSL zeros handshake secrets after use
        assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" not in hit_types
        assert "SERVER_HANDSHAKE_TRAFFIC_SECRET" not in hit_types


@real_dumps
class TestAnalysisPipelinePreKeyUpdate:
    """Run on pre_server_key_update — expect more hits."""

    def test_traffic_secrets_found(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="pre_server_key_update",
            protocol_version="13",
            max_runs=2,
            expand_keys=False,
        )
        hit_types = {h.secret_type for h in report.hits}
        assert "CLIENT_TRAFFIC_SECRET_0" in hit_types
        assert "SERVER_TRAFFIC_SECRET_0" in hit_types
        assert "EXPORTER_SECRET" in hit_types


@real_dumps
class TestAnalysisPipelinePostAbort:
    """Run on post_abort — EXPORTER_SECRET should still be present."""

    def test_exporter_secret_persists_post_abort(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="post_abort",
            protocol_version="13",
            max_runs=2,
            expand_keys=False,
        )
        hit_types = {h.secret_type for h in report.hits}
        assert "EXPORTER_SECRET" in hit_types, (
            f"EXPORTER_SECRET should persist post_abort. Found: {hit_types}"
        )


# ===================================================================
# 6-7. Derived key expansion
# ===================================================================


@real_dumps
class TestKeyExpansion:
    """Verify derived key expansion (KEY_128, IV) on real data."""

    def test_expand_keys_produces_derived(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="pre_server_key_update",
            protocol_version="13",
            max_runs=2,
            expand_keys=True,
        )
        hit_types = {h.secret_type for h in report.hits}
        # Derived key types contain markers like KEY_ or IV_
        derived_types = {t for t in hit_types if "KEY_" in t or "IV_" in t}
        assert len(derived_types) > 0, (
            f"No derived keys found with expand_keys=True. Types: {hit_types}"
        )

    def test_no_expand_skips_derived(self):
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_library(
            BORINGSSL_DIR,
            phase="pre_server_key_update",
            protocol_version="13",
            max_runs=2,
            expand_keys=False,
        )
        hit_types = {h.secret_type for h in report.hits}
        derived_types = {t for t in hit_types if "KEY_" in t or "IV_" in t}
        assert len(derived_types) == 0, (
            f"Derived keys found with expand_keys=False: {derived_types}"
        )


# ===================================================================
# 8. Cross-run key uniqueness
# ===================================================================


@real_dumps
class TestCrossRunKeyUniqueness:
    """Keys from run_13_1 should NOT appear in run_13_2 dumps."""

    def test_run1_keys_absent_from_run2(self):
        # Parse run1 secrets
        secrets1 = KeylogParser.parse(RUN1_DIR / "keylog.csv")
        assert len(secrets1) > 0

        # Get a pre_abort dump from run2
        run2_dumps = list(RUN2_DIR.glob("*pre_abort.dump"))
        assert len(run2_dumps) > 0, "No pre_abort dump found in run2"
        dump_path = run2_dumps[0]
        dump_data = dump_path.read_bytes()

        # None of run1's secret values should be in run2's dump
        for s in secrets1:
            assert s.secret_value not in dump_data, (
                f"{s.secret_type} from run1 found in run2 dump at offset "
                f"{dump_data.find(s.secret_value)}"
            )


# ===================================================================
# 9. Hex inspection via DumpSource
# ===================================================================


@real_dumps
class TestHexInspection:
    """Read hex data from a real dump and verify ELF header."""

    def test_dump_starts_with_elf(self):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        src = RawDumpSource(dump_path)
        with src:
            data = src.read_all()
        assert data[:4] == b"\x7fELF", (
            f"Expected ELF magic, got {data[:4].hex()}"
        )

    def test_dump_size_reasonable(self):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        src = RawDumpSource(dump_path)
        with src:
            size = src.size
        # Real dumps are typically in the MB range
        assert size > 1_000_000, f"Dump too small: {size} bytes"
        assert size < 100_000_000, f"Dump unexpectedly large: {size} bytes"


# ===================================================================
# 10. Entropy computation
# ===================================================================


@real_dumps
class TestEntropyComputation:
    """Compute entropy on real dump sections and check sensible values."""

    def test_entropy_of_elf_header_low(self):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        data = dump_path.read_bytes()[:256]
        ent = shannon_entropy(data)
        # ELF header has lots of zeros -> low entropy
        assert 0.0 < ent < 5.0, f"ELF header entropy={ent}, expected low"

    def test_entropy_profile_produces_samples(self):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        # Read a 4KB chunk from middle of the dump
        with open(dump_path, "rb") as f:
            f.seek(100_000)
            data = f.read(4096)
        profile = compute_entropy_profile(data, window=32, step=16)
        assert len(profile) > 0
        # All entropy values should be in valid range
        for offset, ent in profile:
            assert 0.0 <= ent <= 8.0, f"Entropy {ent} out of range at {offset}"

    @pytest.mark.parametrize("window_size", [16, 32, 64])
    def test_entropy_profile_window_sizes(self, window_size):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        with open(dump_path, "rb") as f:
            data = f.read(2048)
        profile = compute_entropy_profile(data, window=window_size, step=8)
        assert len(profile) > 0


# ===================================================================
# 11. Serialization roundtrip
# ===================================================================


@real_dumps
class TestSerializationRoundtrip:
    """Run analysis, serialize to JSON, deserialize, verify data matches."""

    def test_roundtrip_preserves_hits(self):
        pipeline = AnalysisPipeline()
        request = AnalyzeRequest(
            library_dirs=[BORINGSSL_DIR],
            phase="pre_abort",
            protocol_version="13",
            expand_keys=False,
            max_runs=2,
        )
        result = pipeline.run(request)
        assert result.total_hits > 0

        # Serialize
        data = serialize_result(result)
        json_str = json.dumps(data)

        # Deserialize
        parsed = json.loads(json_str)
        restored = deserialize_result(parsed)

        # Verify
        assert restored.total_hits == result.total_hits
        assert len(restored.libraries) == len(result.libraries)
        for orig_lib, rest_lib in zip(result.libraries, restored.libraries):
            assert rest_lib.library == orig_lib.library
            assert rest_lib.phase == orig_lib.phase
            assert len(rest_lib.hits) == len(orig_lib.hits)
            for orig_hit, rest_hit in zip(orig_lib.hits, rest_lib.hits):
                assert rest_hit.secret_type == orig_hit.secret_type
                assert rest_hit.offset == orig_hit.offset
                assert rest_hit.length == orig_hit.length


# ===================================================================
# 12-15. FastAPI endpoint tests
# ===================================================================

try:
    from fastapi.testclient import TestClient
    from api.main import create_app
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

needs_fastapi = pytest.mark.skipif(
    not _HAS_FASTAPI, reason="FastAPI not installed"
)


@pytest.fixture
def api_client():
    if not _HAS_FASTAPI:
        pytest.skip("FastAPI not installed")
    app = create_app()
    return TestClient(app)


@real_dumps
@needs_fastapi
class TestAPIScanEndpoint:
    """Test POST /api/dataset/scan with real dataset."""

    def test_scan_returns_protocols(self, api_client):
        resp = api_client.post(
            "/api/dataset/scan",
            json={"root": str(DATASET_ROOT)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Should find TLS 1.3 at minimum
        versions = data.get("protocol_versions", [])
        assert "13" in versions, f"Expected '13' in {versions}"

    def test_scan_at_library_level(self, api_client):
        resp = api_client.post(
            "/api/dataset/scan",
            json={"root": str(BORINGSSL_DIR)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("total_runs", 0) >= 100


@real_dumps
@needs_fastapi
class TestAPIAnalysisEndpoint:
    """Test POST /api/analysis/run with real data."""

    def test_analysis_returns_hits(self, api_client):
        resp = api_client.post(
            "/api/analysis/run",
            json={
                "library_dirs": [str(BORINGSSL_DIR)],
                "phase": "pre_abort",
                "protocol_version": "13",
                "max_runs": 2,
                "expand_keys": False,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Response should have hits or libraries with hits
        total_hits = data.get("total_hits", 0)
        if total_hits == 0:
            # Some API formats nest differently
            for lib in data.get("libraries", []):
                total_hits += len(lib.get("hits", []))
        assert total_hits > 0, f"Expected hits in analysis response: {data.keys()}"


@real_dumps
@needs_fastapi
class TestAPIHexEndpoint:
    """Test GET /api/inspect/hex with real dump."""

    def test_hex_returns_data(self, api_client):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        resp = api_client.get(
            "/api/inspect/hex",
            params={
                "dump_path": str(dump_path),
                "offset": 0,
                "length": 64,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Should contain hex representation (API returns 'hex_lines')
        hex_lines = data.get("hex_lines", [])
        assert len(hex_lines) > 0, (
            f"No hex_lines in response: {list(data.keys())}"
        )
        # Verify ELF magic appears in first line
        assert "ELF" in hex_lines[0]


@real_dumps
@needs_fastapi
class TestAPIEntropyEndpoint:
    """Test GET /api/inspect/entropy with real dump."""

    def test_entropy_returns_profile(self, api_client):
        dump_path = next(RUN1_DIR.glob("*pre_abort.dump"))
        resp = api_client.get(
            "/api/inspect/entropy",
            params={
                "dump_path": str(dump_path),
                "offset": 0,
                "length": 4096,
                "window": 32,
                "step": 16,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Should have profile or samples
        profile = data.get("profile", data.get("samples", []))
        assert len(profile) > 0 or "high_entropy_regions" in data, (
            f"No entropy data in response: {list(data.keys())}"
        )
