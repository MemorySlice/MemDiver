"""Integration-level tests for the architect/ module pipeline.

These tests exercise the full StaticChecker -> PatternGenerator -> *Exporter
chain on small synthesized inputs, complementing the per-class unit tests
in test_static_checker.py, test_pattern_generator.py, test_yara_exporter.py,
test_json_exporter.py, and test_volatility3_exporter.py.

Focus is on the structural contracts of the public API rather than exact
byte-for-byte output, so refactors of internal formatting won't break tests.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from architect.json_exporter import JsonExporter
from architect.pattern_generator import PatternGenerator
from architect.static_checker import StaticChecker
from architect.volatility3_exporter import Volatility3Exporter
from architect.yara_exporter import YaraExporter


# ---------------------------------------------------------------------------
# Helpers - small synthesized dumps written to tmp files.
# ---------------------------------------------------------------------------


def _write_dumps(payloads: list[bytes]) -> list[Path]:
    """Persist each payload to a tempfile and return their Paths."""
    paths: list[Path] = []
    for data in payloads:
        f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
        f.write(data)
        f.close()
        paths.append(Path(f.name))
    return paths


def _cleanup(paths: list[Path]) -> None:
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# StaticChecker.check - multi-dump contract
# ---------------------------------------------------------------------------


def test_static_checker_all_static_input_yields_full_mask():
    """Identical dumps yield an all-True mask and reference equals dump 0."""
    static_block = bytes(range(64))
    paths = _write_dumps([static_block, static_block, static_block])
    try:
        mask, reference = StaticChecker.check(paths, offset=0, length=64)
        assert len(mask) == 64
        assert all(mask), "expected every byte static across identical dumps"
        assert reference == static_block
    finally:
        _cleanup(paths)


def test_static_checker_mixed_input_reflects_per_byte_stability():
    """Per-byte mask flips False at any position that diverges between dumps.

    Length is bounded by the shortest region read across all dumps -- when
    one dump is shorter than the requested window, comparison stops there.
    """
    base = bytearray(b"\xAA" * 64)
    dump_a = bytes(base)
    # dump_b: differs at offsets 5, 17, 42
    dump_b_buf = bytearray(base)
    dump_b_buf[5] = 0x11
    dump_b_buf[17] = 0x22
    dump_b_buf[42] = 0x33
    dump_b = bytes(dump_b_buf)
    # dump_c: same as dump_a (identical bytes -> no further mask changes)
    dump_c = bytes(base)

    paths = _write_dumps([dump_a, dump_b, dump_c])
    try:
        mask, reference = StaticChecker.check(paths, offset=0, length=64)
        # Reference always comes from the first dump.
        assert reference == dump_a
        assert len(mask) == 64
        # Bytes 5, 17, 42 should be flagged volatile by dump_b.
        assert mask[5] is False
        assert mask[17] is False
        assert mask[42] is False
        # Spot check a couple of unchanged bytes.
        assert mask[0] is True
        assert mask[63] is True
    finally:
        _cleanup(paths)


# ---------------------------------------------------------------------------
# PatternGenerator.generate - happy path + threshold rejection
# ---------------------------------------------------------------------------


def test_pattern_generator_generate_returns_structured_dict():
    """Happy path produces a dict with the documented keys + correct length."""
    reference = bytes(range(32))
    # 22/32 = ~69% static (above default threshold of 0.3)
    mask = [True] * 22 + [False] * 10
    pattern = PatternGenerator.generate(reference, mask, name="testpat")

    assert pattern is not None
    for key in ("name", "length", "hex_pattern", "wildcard_pattern",
                "static_ratio", "static_count", "volatile_count"):
        assert key in pattern, f"missing key: {key}"
    assert pattern["name"] == "testpat"
    assert pattern["length"] == 32
    assert pattern["static_count"] == 22
    assert pattern["volatile_count"] == 10
    # The wildcard_pattern is space-separated tokens -- 32 bytes -> 32 tokens.
    tokens = pattern["wildcard_pattern"].split()
    assert len(tokens) == 32
    # Volatile positions render as "??", static positions as 2-char hex.
    assert tokens[-1] == "??"
    assert tokens[0] == "00"


def test_pattern_generator_below_threshold_returns_none():
    """Static ratio below min_static_ratio -> generate returns None.

    Discovered contract: PatternGenerator.generate does NOT raise -- it
    returns None and logs a warning. Callers handle the None.
    """
    reference = b"\x00" * 32
    # 5/32 = ~15% static, below the default 30% threshold.
    mask = [True] * 5 + [False] * 27
    result = PatternGenerator.generate(
        reference, mask, name="too_volatile", min_static_ratio=0.3,
    )
    assert result is None


# ---------------------------------------------------------------------------
# PatternGenerator.infer_fields - region classification
# ---------------------------------------------------------------------------


def test_infer_fields_segments_static_dynamic_and_key_regions():
    """Variance array with three contiguous regions is classified correctly.

    Region layout (24 bytes):
      [0..7]   low variance  -> 'static'
      [8..15]  high variance -> 'dynamic'
      [16..23] would be 'static' by variance, but key region overrides
    """
    variance = (
        [10.0] * 8           # static (well below threshold)
        + [50_000.0] * 8     # dynamic (well above threshold)
        + [10.0] * 8         # 'key_material' due to key_offset override
    )
    fields = PatternGenerator.infer_fields(
        variance, key_offset=16, key_length=8, threshold=2000.0,
    )

    assert len(fields) == 3
    types = [f["type"] for f in fields]
    assert types == ["static", "dynamic", "key_material"]
    assert fields[0]["offset"] == 0 and fields[0]["length"] == 8
    assert fields[1]["offset"] == 8 and fields[1]["length"] == 8
    assert fields[2]["offset"] == 16 and fields[2]["length"] == 8
    # Key region carries the special 'key' label per the contract.
    assert fields[2]["label"] == "key"


# ---------------------------------------------------------------------------
# YaraExporter.export - structural assertions
# ---------------------------------------------------------------------------


def test_yara_exporter_emits_valid_rule_structure():
    """YARA output is a non-empty rule string referencing the pattern's hex."""
    reference = bytes.fromhex("deadbeefcafebabe" + "00" * 24)
    mask = [True] * 32  # everything static -- guaranteed to embed full hex
    pattern = PatternGenerator.generate(reference, mask, name="yara_test")
    assert pattern is not None

    rule = YaraExporter.export(pattern, rule_name="my_rule")

    assert isinstance(rule, str) and rule.strip(), "expected non-empty YARA rule"
    assert "rule " in rule
    assert "condition:" in rule
    assert "strings:" in rule
    # The rule should contain the pattern's hex (uppercased per YARA convention).
    assert "DEADBEEFCAFEBABE" in rule.replace(" ", "")
    # User-supplied rule name flows through.
    assert "rule my_rule" in rule


# ---------------------------------------------------------------------------
# JsonExporter.export - JSON round-trip + required fields
# ---------------------------------------------------------------------------


def test_json_exporter_emits_round_trippable_signature():
    """to_string output round-trips through json.loads with required keys intact."""
    reference = bytes(range(48))
    mask = [True] * 36 + [False] * 12  # 75% static
    pattern = PatternGenerator.generate(reference, mask, name="json_test")
    assert pattern is not None

    sig = JsonExporter.export(
        pattern,
        library="boringssl",
        tls_version="13",
        description="round-trip test",
    )
    serialized = JsonExporter.to_string(sig)

    parsed = json.loads(serialized)
    for key in ("name", "description", "applicable_to", "key_spec",
                "pattern", "metadata"):
        assert key in parsed, f"missing key: {key}"
    assert parsed["name"] == "json_test"
    # applicable_to reflects the optional library + tls_version inputs.
    assert parsed["applicable_to"]["libraries"] == ["boringssl"]
    assert parsed["applicable_to"]["protocol_versions"] == ["13"]
    # metadata preserves the source pattern's wildcard form.
    assert parsed["metadata"]["wildcard_pattern"] == pattern["wildcard_pattern"]


# ---------------------------------------------------------------------------
# Volatility3Exporter.export - structural Python-source assertions
# ---------------------------------------------------------------------------


def test_volatility3_exporter_emits_plugin_python_source():
    """Volatility3 export is non-empty Python source with the expected scaffold."""
    reference = bytes.fromhex("0102030405060708") + b"\x00" * 56
    mask = [True] * 64
    pattern = PatternGenerator.generate(reference, mask, name="vol3_demo")
    assert pattern is not None

    source = Volatility3Exporter.export(pattern, plugin_name="MyVolPlugin")

    assert isinstance(source, str) and source.strip()
    # Must declare a class with the exact name the caller passed.
    assert "class MyVolPlugin" in source
    # Must define the run(self) entrypoint that Volatility3 invokes.
    assert "def run(self)" in source
    # Must reference the pattern name somewhere (constants / docstring).
    assert "vol3_demo" in source
    # Must embed the YARA rule constant (cross-class integration point).
    assert "YARA_RULE" in source
