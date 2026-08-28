"""Tests for Volatility3 plugin exporter."""
import ast

import pytest
import yara

from memdiver.architect.volatility3_exporter import (
    Volatility3Exporter,
    _sanitize_class_name,
    _longest_static_run,
)
from memdiver.architect.yara_exporter import key_locator_from_pattern


def _embedded_yara_meta(plugin_source: str) -> dict:
    """Compile the plugin's embedded YARA_RULE and return its meta dict."""
    tree = ast.parse(plugin_source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "YARA_RULE" in targets and isinstance(node.value, ast.Constant):
            rules = list(yara.compile(source=node.value.value))
            assert len(rules) == 1, f"expected one rule, got {len(rules)}"
            return dict(rules[0].meta)
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


class TestKeyLocatorFromPattern:
    """The locator a pattern dict carries, read defensively.

    The dict can arrive verbatim from an HTTP request body, so any JSON value
    is possible; anything non-integral must become ``None`` (meta omitted)
    rather than crash ``int()`` inside the exporter.
    """

    def test_present_ints(self):
        assert key_locator_from_pattern(
            {"key_offset": 64, "key_length": 32}) == (64, 32)

    def test_absent(self):
        assert key_locator_from_pattern({}) == (None, None)

    def test_explicit_none(self):
        assert key_locator_from_pattern(
            {"key_offset": None, "key_length": None}) == (None, None)

    def test_partial(self):
        assert key_locator_from_pattern({"key_length": 16}) == (None, 16)

    @pytest.mark.parametrize("bad", ["n/a", object(), [1], {"a": 1}, True])
    def test_non_integral_becomes_none(self, bad):
        assert key_locator_from_pattern(
            {"key_offset": bad, "key_length": bad}) == (None, None)

    def test_numeric_string_and_float_are_accepted(self):
        assert key_locator_from_pattern(
            {"key_offset": "64", "key_length": 32.0}) == (64, 32)


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

    def test_export_generated_yara_carries_pattern_key_locator(self, sample_pattern):
        """GAP C: the yara fallback must pass through the pattern's locator.

        ``vol3_emit`` and the experiment orchestrator enrich the pattern dict
        with ``key_offset``/``key_length``; when no ``yara_rule`` is supplied
        the rule this exporter builds itself must carry them, so it matches
        what every other emission path produces.
        """
        pattern = dict(sample_pattern, key_offset=8, key_length=16)
        source = Volatility3Exporter.export(pattern)
        meta = _embedded_yara_meta(source)
        assert meta["key_offset"] == 8
        assert meta["key_length"] == 16

    def test_export_generated_yara_omits_locator_when_pattern_lacks_it(
        self, sample_pattern
    ):
        """A bare PatternGenerator pattern knows no key position: omit, never
        invent. (The plugin template's KEY_OFFSET/KEY_LENGTH keep their
        documented 0/pattern-length fallbacks -- only the metas are omitted.)"""
        source = Volatility3Exporter.export(sample_pattern)
        meta = _embedded_yara_meta(source)
        assert "key_offset" not in meta
        assert "key_length" not in meta
        assert "KEY_OFFSET = 0" in source

    def test_export_generated_yara_survives_non_integral_locator(
        self, sample_pattern
    ):
        """A hostile/non-integral locator must not break rule generation."""
        pattern = dict(sample_pattern, key_offset="nope", key_length=None)
        meta = _embedded_yara_meta(Volatility3Exporter.export(pattern))
        assert "key_offset" not in meta
        assert "key_length" not in meta

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

    @pytest.mark.parametrize("bad_ratio", [None, "n/a", object()])
    def test_export_compiles_with_non_numeric_static_ratio(
        self, sample_pattern, bad_ratio
    ):
        """A None/non-numeric static_ratio must still emit a compilable plugin.

        Regression: static_ratio was substituted as a bare token, so a
        None/non-numeric value produced ``StaticRatio: None`` -> a plugin that
        failed to import. It must be coerced to a numeric literal (0.0 here).
        """
        pattern = dict(sample_pattern)
        pattern["static_ratio"] = bad_ratio
        source = Volatility3Exporter.export(pattern)
        compile(source, "<generated>", "exec")  # Must not raise SyntaxError
        assert "0.0," in source

    def test_export_static_ratio_is_numeric_literal(self, sample_pattern):
        """A valid float static_ratio is emitted as a numeric literal."""
        source = Volatility3Exporter.export(sample_pattern)
        compile(source, "<generated>", "exec")
        assert "0.9375," in source

    def test_save(self, sample_pattern, tmp_path):
        source = Volatility3Exporter.export(sample_pattern)
        out = tmp_path / "test_plugin.py"
        Volatility3Exporter.save(source, out)
        assert out.exists()
        assert out.read_text() == source
