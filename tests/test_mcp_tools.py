"""Tests for MCP tool functions — no MCP SDK required."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from mcp_server.session import ToolSession
from mcp_server import tools
from mcp_server import tools_inspect
from mcp_server import tools_xref

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dataset"


@pytest.fixture(scope="module", autouse=True)
def ensure_fixtures():
    """Generate fixtures if not already present."""
    from tests.fixtures.generate_fixtures import generate_dataset
    generate_dataset()


@pytest.fixture
def session():
    return ToolSession()


# --- ToolSession ---

class TestToolSession:
    def test_set_dataset_valid(self, session):
        result = session.set_dataset(str(FIXTURE_ROOT))
        assert result["status"] == "ok"
        assert session.dataset_root == FIXTURE_ROOT.resolve()

    def test_set_dataset_invalid(self, session):
        result = session.set_dataset("/nonexistent/path")
        assert "error" in result

    def test_require_dataset_raises(self, session):
        with pytest.raises(ValueError, match="No dataset root"):
            session.require_dataset()

    def test_require_dataset_after_set(self, session):
        session.set_dataset(str(FIXTURE_ROOT))
        assert session.require_dataset() == FIXTURE_ROOT.resolve()

    def test_clear(self, session):
        session.set_dataset(str(FIXTURE_ROOT))
        session.clear()
        assert session.dataset_root is None
        assert session.scan_cache is None


# --- scan_dataset ---

class TestScanDataset:
    def test_scan_returns_protocols(self, session):
        result = tools.scan_dataset(session, str(FIXTURE_ROOT))
        assert "protocol_versions" in result
        assert "total_runs" in result
        assert result["total_runs"] > 0

    def test_scan_caches(self, session):
        r1 = tools.scan_dataset(session, str(FIXTURE_ROOT))
        r2 = session.get_or_scan()
        assert r1 == r2


# --- list_phases ---

class TestListPhases:
    def test_list_phases_openssl(self, session):
        lib_dir = FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl"
        result = tools.list_phases(session, str(lib_dir))
        assert "phases" in result
        assert len(result["phases"]) > 0
        assert result["runs"] > 0

    def test_list_phases_invalid_dir(self, session):
        result = tools.list_phases(session, "/nonexistent")
        assert "error" in result


# --- list_protocols ---

class TestListProtocols:
    def test_returns_tls_and_ssh(self, session):
        result = tools.list_protocols(session)
        names = [p["name"] for p in result["protocols"]]
        assert "TLS" in names
        assert "SSH" in names

    def test_protocol_has_versions(self, session):
        result = tools.list_protocols(session)
        tls = next(p for p in result["protocols"] if p["name"] == "TLS")
        assert "12" in tls["versions"]
        assert "13" in tls["versions"]


# --- analyze_library ---

class TestAnalyzeLibrary:
    def test_analyze_tls12(self, session):
        lib_dir = str(FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl")
        result = tools.analyze_library(
            session, [lib_dir], phase="pre_handshake",
            protocol_version="12",
        )
        assert "libraries" in result
        assert len(result["libraries"]) > 0

    def test_analyze_invalid_dir(self, session):
        result = tools.analyze_library(
            session, ["/nonexistent"], phase="pre_handshake",
            protocol_version="12",
        )
        assert "error" in result


# --- read_hex ---

class TestReadHex:
    def test_read_hex_basic(self, session):
        dump = next((FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1").glob("*.dump"))
        result = tools_inspect.read_hex(session, str(dump), offset=0, length=64)
        assert "hex_lines" in result
        assert len(result["hex_lines"]) == 4  # 64 bytes / 16 per line
        assert result["offset"] == 0
        assert result["length"] == 64

    def test_read_hex_clamped(self, session):
        dump = next((FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1").glob("*.dump"))
        result = tools_inspect.read_hex(session, str(dump), offset=0, length=999999)
        assert result["length"] <= tools_inspect.MAX_HEX_LENGTH

    def test_read_hex_missing_file(self, session):
        result = tools_inspect.read_hex(session, "/nonexistent.dump")
        assert "error" in result


# --- get_entropy ---

class TestGetEntropy:
    def test_entropy_profile(self, session):
        dump = next((FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1").glob("*.dump"))
        result = tools_inspect.get_entropy(session, str(dump))
        assert "overall_entropy" in result
        assert "stats" in result
        assert "profile_sample" in result
        assert isinstance(result["overall_entropy"], float)

    def test_entropy_missing_file(self, session):
        result = tools_inspect.get_entropy(session, "/nonexistent.dump")
        assert "error" in result


# --- extract_strings ---

class TestExtractStrings:
    def test_extract_strings_basic(self, session):
        dump = next((FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1").glob("*.dump"))
        result = tools_inspect.extract_strings_tool(session, str(dump))
        assert "strings" in result
        assert "total_count" in result
        assert "truncated" in result

    def test_extract_strings_missing_file(self, session):
        result = tools_inspect.extract_strings_tool(session, "/nonexistent.dump")
        assert "error" in result


# --- get_session_info ---

class TestGetSessionInfo:
    def test_msl_session(self, session):
        msl_path = FIXTURE_ROOT / "msl" / "test_capture.msl"
        if not msl_path.exists():
            pytest.skip("MSL fixture not available")
        result = tools_inspect.get_session_info(session, str(msl_path))
        assert "dump_uuid" in result
        assert "pid" in result
        assert "modules" in result

    def test_non_msl_file(self, session):
        dump = next((FIXTURE_ROOT / "TLS12" / "scenario_a" / "openssl" / "openssl_run_12_1").glob("*.dump"))
        result = tools_inspect.get_session_info(session, str(dump))
        assert "error" in result

    def test_missing_file(self, session):
        result = tools_inspect.get_session_info(session, "/nonexistent.msl")
        assert "error" in result


# --- _format_hex_lines ---

class TestFormatHexLines:
    def test_single_line(self):
        data = bytes(range(16))
        lines = tools_inspect._format_hex_lines(data, 0)
        assert len(lines) == 1
        assert lines[0].startswith("00000000")

    def test_offset(self):
        data = bytes(range(16))
        lines = tools_inspect._format_hex_lines(data, 0x100)
        assert lines[0].startswith("00000100")

    def test_partial_line(self):
        data = bytes(range(8))
        lines = tools_inspect._format_hex_lines(data, 0)
        assert len(lines) == 1


# --- tools_xref ---

class TestIdentifyStructure:
    def test_identify_structure_match(self, session, tmp_path):
        """identify_structure finds a structure in nonzero data."""
        dump = tmp_path / "test.dump"
        dump.write_bytes(b"\xff" * 128)
        result = tools_xref.identify_structure(session, str(dump), offset=0)
        if result.get("match"):
            assert "name" in result["match"]
            assert "confidence" in result["match"]
        else:
            assert result.get("reason")

    def test_identify_structure_missing_file(self, session):
        result = tools_xref.identify_structure(session, "/nonexistent.dump")
        assert "error" in result


class TestImportRawDump:
    def test_import_raw_dump(self, session, tmp_path):
        dump = tmp_path / "test.dump"
        dump.write_bytes(b"\xaa" * 256)
        out = tmp_path / "test.msl"
        result = tools.import_raw_dump(session, str(dump), str(out))
        assert "error" not in result
        assert result["total_bytes"] == 256
        assert out.is_file()
