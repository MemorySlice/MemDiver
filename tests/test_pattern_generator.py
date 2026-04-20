"""Tests for architect.pattern_generator module - PatternGenerator wildcard patterns."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from architect.pattern_generator import PatternGenerator


def test_generate_empty_inputs():
    """Empty reference_bytes or static_mask should return None."""
    assert PatternGenerator.generate(b"", [True, True]) is None
    assert PatternGenerator.generate(b"\x41\x42", []) is None
    assert PatternGenerator.generate(b"", []) is None


def test_generate_all_static():
    """All-static mask should produce static_ratio == 1.0 and no '??' in wildcard pattern."""
    result = PatternGenerator.generate(
        reference_bytes=b"\x41\x42\x43\x44",
        static_mask=[True, True, True, True],
        name="all_static",
    )
    assert result is not None
    assert result["static_ratio"] == 1.0
    assert "??" not in result["wildcard_pattern"]
    assert result["wildcard_pattern"] == "41 42 43 44"
    assert result["static_count"] == 4
    assert result["volatile_count"] == 0


def test_generate_below_min_ratio():
    """A mask with less than 30% static bytes should return None (below min_static_ratio=0.3)."""
    # 1 out of 5 = 20% static -> below default threshold of 0.3
    result = PatternGenerator.generate(
        reference_bytes=b"\x41\x42\x43\x44\x45",
        static_mask=[True, False, False, False, False],
        name="low_static",
    )
    assert result is None


def test_generate_mixed():
    """Mixed mask should produce '??' at volatile positions and hex at static positions."""
    result = PatternGenerator.generate(
        reference_bytes=b"\x41\x42\x43\x44",
        static_mask=[True, False, True, False],
        name="mixed_pattern",
    )
    assert result is not None
    assert result["static_ratio"] == 0.5
    parts = result["wildcard_pattern"].split(" ")
    assert parts[0] == "41"  # static
    assert parts[1] == "??"  # volatile
    assert parts[2] == "43"  # static
    assert parts[3] == "??"  # volatile
    assert result["static_count"] == 2
    assert result["volatile_count"] == 2


def test_find_anchors():
    """find_anchors should identify contiguous static runs of sufficient length."""
    # 6 static + 4 volatile + 5 static -> two anchors: (0, 6) and (10, 5)
    static_mask = [True] * 6 + [False] * 4 + [True] * 5
    anchors = PatternGenerator.find_anchors(static_mask, min_anchor_length=4)
    assert len(anchors) == 2
    assert anchors[0] == (0, 6)
    assert anchors[1] == (10, 5)


# ---- infer_fields tests ----


def test_infer_fields_basic():
    """Segments a simple low-high-low variance profile with a known key region."""
    # 4 bytes low variance | 4 bytes key | 4 bytes low variance
    variance = [10.0] * 4 + [50000.0] * 4 + [10.0] * 4
    fields = PatternGenerator.infer_fields(variance, key_offset=4, key_length=4)
    assert len(fields) == 3
    assert fields[0]["type"] == "static"
    assert fields[0]["offset"] == 0
    assert fields[0]["length"] == 4
    assert fields[1]["type"] == "key_material"
    assert fields[1]["offset"] == 4
    assert fields[1]["length"] == 4
    assert fields[1]["label"] == "key"
    assert fields[2]["type"] == "static"
    assert fields[2]["offset"] == 8
    assert fields[2]["length"] == 4


def test_infer_fields_with_dynamic_region():
    """Dynamic (high-variance non-key) bytes are labeled 'dynamic'."""
    # 2 static | 2 key | 2 dynamic | 2 static
    variance = [5.0, 5.0, 99999.0, 99999.0, 8000.0, 8000.0, 5.0, 5.0]
    fields = PatternGenerator.infer_fields(variance, key_offset=2, key_length=2)
    types = [f["type"] for f in fields]
    assert types == ["static", "key_material", "dynamic", "static"]


def test_infer_fields_key_overrides_variance():
    """Key region is labeled key_material even if its variance is below threshold."""
    variance = [10.0] * 8  # all low variance
    fields = PatternGenerator.infer_fields(variance, key_offset=2, key_length=4)
    key = next(f for f in fields if f["type"] == "key_material")
    assert key["offset"] == 2
    assert key["length"] == 4


def test_infer_fields_empty():
    """Empty variance returns empty list."""
    assert PatternGenerator.infer_fields([], key_offset=0, key_length=0) == []


def test_infer_fields_sequential_labels():
    """Multiple static or dynamic regions get sequential labels."""
    # static_0 | key | dynamic_0 | static_1
    variance = [5.0, 5.0, 50000.0, 50000.0, 8000.0, 8000.0, 5.0, 5.0]
    fields = PatternGenerator.infer_fields(variance, key_offset=2, key_length=2)
    labels = [f["label"] for f in fields]
    assert labels == ["static_0", "key", "dynamic_0", "static_1"]
