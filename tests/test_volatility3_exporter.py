"""Tests for Volatility3 plugin exporter."""
import pytest
from architect.volatility3_exporter import (
    Volatility3Exporter,
    _sanitize_class_name,
    _longest_static_run,
)


class TestSanitizeClassName:
    def test_simple_name(self):
        assert _sanitize_class_name("hello_world") == "HelloWorld"

    def test_special_chars(self):
        assert _sanitize_class_name("my-pattern.v2") == "MyPatternV2"

    def test_leading_digit(self):
        result = _sanitize_class_name("123test")
        assert not result[0].isdigit()
        assert "123" in result or "Test" in result

    def test_empty(self):
        assert _sanitize_class_name("") == ""


class TestLongestStaticRun:
    def test_all_static(self):
        assert _longest_static_run("aa bb cc") == ("aabbcc", 0)

    def test_mixed(self):
        assert _longest_static_run("aa ?? bb cc dd ?? ee") == ("bbccdd", 2)

    def test_all_wildcards(self):
        assert _longest_static_run("?? ?? ??") == ("", 0)

    def test_single_byte(self):
        assert _longest_static_run("ff") == ("ff", 0)

    def test_empty(self):
        assert _longest_static_run("") == ("", 0)


class TestVolatility3Exporter:
    @pytest.fixture
    def sample_pattern(self):
        return {
            "name": "aes256_key",
            "length": 32,
            "hex_pattern": " ".join(f"{i:02x}" for i in range(32)),
            "wildcard_pattern": "aa bb ?? ?? " + " ".join(f"{i:02x}" for i in range(4, 32)),
            "static_ratio": 0.9375,
            "static_count": 30,
            "volatile_count": 2,
        }

    def test_export_basic(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        assert "class MemDiverScanAes256Key" in source
        assert "YARA_RULE" in source
        assert "PluginInterface" in source
        assert "def run(self)" in source

    def test_export_compiles(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        compile(source, "<generated>", "exec")  # Must not raise SyntaxError

    def test_export_custom_name(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern, plugin_name="CustomScanner")
        assert "class CustomScanner" in source

    def test_export_embeds_yara(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        assert "rule " in source
        assert "$key" in source

    def test_export_custom_yara(self, sample_pattern):
        custom_rule = 'rule custom { strings: $s = { AA BB } condition: $s }'
        source = Volatility3Exporter.export(sample_pattern, yara_rule=custom_rule)
        assert "rule custom" in source

    def test_export_fallback_scanner(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        assert "NEEDLE" in source
        assert "NEEDLE_OFFSET" in source
        assert "BytesScanner" in source

    def test_export_entropy_function(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        assert "_entropy" in source
        assert "math.log2" in source

    def test_export_pid_requirement(self, sample_pattern):
        source = Volatility3Exporter.export(sample_pattern)
        assert '"pid"' in source
        assert "pid_filter" in source or "pid" in source

    def test_export_description(self, sample_pattern):
        source = Volatility3Exporter.export(
            sample_pattern, description="Find AES-256 keys in process memory"
        )
        assert "Find AES-256 keys" in source

    def test_save(self, sample_pattern, tmp_path):
        source = Volatility3Exporter.export(sample_pattern)
        out = tmp_path / "test_plugin.py"
        Volatility3Exporter.save(source, out)
        assert out.exists()
        assert out.read_text() == source
