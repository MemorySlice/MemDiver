"""Tests for architect.yara_exporter module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from architect.yara_exporter import YaraExporter, _sanitize_identifier


def test_export_basic():
    """Valid pattern dict produces YARA rule with required sections."""
    pattern = {"name": "test_pattern", "wildcard_pattern": "AA BB CC", "length": 3, "static_ratio": 0.5}
    rule = YaraExporter.export(pattern)
    assert "rule test_pattern" in rule
    assert "strings:" in rule
    assert "condition:" in rule
    assert "$key" in rule
    assert "AA BB CC" in rule


def test_export_with_tags():
    """Pattern with tags list produces YARA rule with tag annotation."""
    pattern = {"name": "tagged", "wildcard_pattern": "FF", "length": 1}
    rule = YaraExporter.export(pattern, tags=["tls", "crypto"])
    assert ": tls crypto" in rule


def test_export_missing_name():
    """Pattern without 'name' key uses fallback name."""
    pattern = {"wildcard_pattern": "00", "length": 1}
    rule = YaraExporter.export(pattern)
    assert "rule memdiver_pattern" in rule


def test_sanitize_identifier_special_chars():
    """Special characters become underscores, leading digits get r_ prefix."""
    assert _sanitize_identifier("my-pattern.v2") == "my_pattern_v2"
    assert _sanitize_identifier("3illegal") == "r_3illegal"


def test_sanitize_identifier_empty():
    """Empty string returns 'unnamed_rule'."""
    assert _sanitize_identifier("") == "unnamed_rule"
