"""Tests for core.classify module.

Covers ByteClassifier.classify with empty regions, single runs,
identical runs, differing runs, and key boundary precision.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.classify import ByteClassifier
from core.models import ComparisonRegion


def test_classify_empty():
    """Region with empty run_data returns empty classification list."""
    region = ComparisonRegion(secret_type="TEST", key_length=16, context_size=8)
    assert ByteClassifier.classify(region) == []


def test_classify_single_run():
    """Single run: context bytes are 'same', key bytes are 'key'."""
    before = b"\x00" * 8
    key = b"\xAA" * 16
    after = b"\x00" * 8
    region = ComparisonRegion(
        secret_type="TEST",
        key_length=16,
        context_size=8,
        run_data=[(before, key, after)],
    )
    classes = ByteClassifier.classify(region)
    total_len = 8 + 16 + 8  # 32
    assert len(classes) == total_len
    # Context before: all "same"
    for c in classes[:8]:
        assert c == "same"
    # Key region: all "key"
    for c in classes[8:24]:
        assert c == "key"
    # Context after: all "same"
    for c in classes[24:]:
        assert c == "same"


def test_classify_identical_runs():
    """Two identical runs: non-key bytes are 'same', key bytes are 'key'."""
    before = b"\x11" * 4
    key = b"\xFF" * 8
    after = b"\x22" * 4
    run_data = [(before, key, after), (before, key, after)]
    region = ComparisonRegion(
        secret_type="TEST",
        key_length=8,
        context_size=4,
        run_data=run_data,
    )
    classes = ByteClassifier.classify(region)
    assert len(classes) == 16
    for c in classes[:4]:
        assert c == "same"
    for c in classes[4:12]:
        assert c == "key"
    for c in classes[12:]:
        assert c == "same"


def test_classify_differing_runs():
    """Two runs with different context bytes produce 'different' at changed offsets."""
    before1 = b"\x00" * 4
    before2 = b"\xFF" * 4
    key = b"\xAA" * 8
    after = b"\x00" * 4
    region = ComparisonRegion(
        secret_type="TEST",
        key_length=8,
        context_size=4,
        run_data=[(before1, key, after), (before2, key, after)],
    )
    classes = ByteClassifier.classify(region)
    assert len(classes) == 16
    # Before context differs between runs
    for c in classes[:4]:
        assert c == "different"
    # Key region is always "key"
    for c in classes[4:12]:
        assert c == "key"
    # After context is identical
    for c in classes[12:]:
        assert c == "same"


def test_classify_key_boundary():
    """Key classification is exact: key_start <= pos < key_end."""
    before = b"\x00" * 3
    key = b"\xBB" * 5
    after = b"\x00" * 3
    region = ComparisonRegion(
        secret_type="TEST",
        key_length=5,
        context_size=3,
        run_data=[(before, key, after)],
    )
    classes = ByteClassifier.classify(region)
    # Positions 0,1,2 = context before (same)
    # Positions 3,4,5,6,7 = key
    # Positions 8,9,10 = context after (same)
    assert classes[2] == "same"   # last byte before key
    assert classes[3] == "key"    # first key byte
    assert classes[7] == "key"    # last key byte
    assert classes[8] == "same"   # first byte after key
