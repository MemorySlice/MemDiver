"""Tests for architect.json_exporter module."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from architect.json_exporter import JsonExporter


def test_export_basic():
    """Valid pattern dict produces JSON-serializable dict with expected keys."""
    pattern = {"name": "test_sig", "length": 48, "static_ratio": 0.6, "wildcard_pattern": "AA ?? CC"}
    result = JsonExporter.export(pattern)
    assert result["name"] == "test_sig"
    assert result["key_spec"]["length"] == 48
    assert "pattern" in result
    assert "metadata" in result
    # Must be JSON-serializable
    json.dumps(result)


def test_export_with_library_version():
    """Pattern with library and version includes them in applicable_to."""
    pattern = {"name": "lib_test", "length": 32}
    result = JsonExporter.export(pattern, library="openssl", tls_version="13")
    assert result["applicable_to"]["libraries"] == ["openssl"]
    assert result["applicable_to"]["protocol_versions"] == ["13"]


def test_to_string():
    """Export result converts to valid JSON string."""
    pattern = {"name": "str_test", "length": 16}
    sig = JsonExporter.export(pattern)
    s = JsonExporter.to_string(sig)
    parsed = json.loads(s)
    assert parsed["name"] == "str_test"


def test_save_to_file():
    """Save writes valid JSON to file."""
    pattern = {"name": "file_test", "length": 32}
    sig = JsonExporter.export(pattern)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = Path(f.name)
    JsonExporter.save(sig, tmp_path)
    assert tmp_path.exists()
    with open(tmp_path) as f:
        loaded = json.load(f)
    assert loaded["name"] == "file_test"
    tmp_path.unlink()


def test_export_empty_pattern():
    """Minimal/empty dict returns dict with defaults."""
    result = JsonExporter.export({})
    assert result["name"] == "unnamed"
    assert result["key_spec"]["length"] == 32
    assert result["applicable_to"] == {}
