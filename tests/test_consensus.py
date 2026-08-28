"""Tests for engine.consensus module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pytest

from memdiver.core.variance import ByteClass, VarianceThresholds, classify_variance
from memdiver.engine.consensus import ConsensusVector, INVARIANT_MAX, STRUCTURAL_MAX, POINTER_MAX
from memdiver.engine.results import StaticRegion


def _make_dumps(data_list):
    """Create temporary dump files from byte data."""
    paths = []
    for data in data_list:
        f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
        f.write(data)
        f.close()
        paths.append(Path(f.name))
    return paths


def test_consensus_identical_dumps():
    """Identical dumps should have zero variance everywhere."""
    data = b"\x42" * 100
    paths = _make_dumps([data, data, data])
    cm = ConsensusVector()
    cm.build(paths)
    assert cm.size == 100
    assert all(v == 0.0 for v in cm.variance)
    assert all(c == ByteClass.INVARIANT for c in cm.classifications)


def test_consensus_different_dumps():
    """Different dumps should show non-zero variance."""
    d1 = b"\x00" * 50 + b"\xFF" * 50
    d2 = b"\x00" * 50 + b"\x00" * 50
    d3 = b"\x00" * 50 + b"\x80" * 50
    paths = _make_dumps([d1, d2, d3])
    cm = ConsensusVector()
    cm.build(paths)
    # First 50 bytes should be invariant
    assert all(cm.classifications[i] == ByteClass.INVARIANT for i in range(50))
    # Last 50 bytes should have non-zero variance
    assert any(cm.variance[i] > 0 for i in range(50, 100))


def test_consensus_static_regions():
    """Should find contiguous static regions."""
    data1 = b"\x00" * 100 + b"\xFF" * 32 + b"\x00" * 100
    data2 = b"\x00" * 100 + b"\x00" * 32 + b"\x00" * 100
    paths = _make_dumps([data1, data2])
    cm = ConsensusVector()
    cm.build(paths)
    static = cm.get_static_regions(min_length=32)
    assert len(static) >= 1
    assert any(r.length >= 32 for r in static)


def test_consensus_classification_counts():
    cm = ConsensusVector()
    cm.classifications = ["invariant"] * 50 + ["key_candidate"] * 10
    cm.size = 60
    counts = cm.classification_counts()
    assert counts["invariant"] == 50
    assert counts["key_candidate"] == 10


def test_consensus_too_few_dumps():
    """Should handle < 2 dumps gracefully."""
    cm = ConsensusVector()
    cm.build([])
    assert cm.size == 0


def test_consensus_incremental_matches_batch():
    """build_incremental + add_source * N + finalize must agree with build()."""
    import numpy as np

    d1 = b"\x00" * 50 + b"\xFF" * 50
    d2 = b"\x00" * 50 + b"\x00" * 50
    d3 = b"\x00" * 50 + b"\x80" * 50

    batch = ConsensusVector()
    batch.build(_make_dumps([d1, d2, d3]))

    incremental = ConsensusVector()
    incremental.build_incremental(100)
    stats = [incremental.add_source(d) for d in (d1, d2, d3)]
    incremental.finalize()

    assert incremental.size == 100
    assert incremental.num_dumps == 3
    assert np.allclose(incremental.variance, batch.variance, rtol=1e-4, atol=1e-3)
    assert list(incremental.classifications) == list(batch.classifications)
    # Live stats after every add must be monotonic in n
    assert [s[0] for s in stats] == [1, 2, 3]


# ---------------------------------------------------------------------------
# get_regions — one getter over all four classes (A2)
# ---------------------------------------------------------------------------

# A synthetic layout with one run of every class, long enough that the two
# legacy getters hit them at their own default min_length (32 / 16).
_LAYOUT = [
    (40, 0.0),        # [0, 40)    invariant
    (20, 150.0),      # [40, 60)   structural
    (20, 2500.0),     # [60, 80)   pointer
    (20, 9000.0),     # [80, 100)  key_candidate
    (40, 0.0),        # [100, 140) invariant
]


def _vector_from_layout(layout=_LAYOUT, thresholds=None):
    """A ConsensusVector carrying a hand-built variance profile."""
    values = []
    for length, variance in layout:
        values.extend([variance] * length)
    cm = ConsensusVector(thresholds=thresholds)
    cm.variance = np.array(values, dtype=np.float32)
    cm.classifications = classify_variance(cm.variance, thresholds)
    cm.size = len(values)
    cm.num_dumps = 3
    return cm


def test_get_regions_reaches_every_class():
    """STRUCTURAL and POINTER were counted but had no getter at all."""
    cm = _vector_from_layout()
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.INVARIANT)] == [
        (0, 40), (100, 140),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.STRUCTURAL)] == [
        (40, 60),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.POINTER)] == [
        (60, 80),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.KEY_CANDIDATE)] == [
        (80, 100),
    ]


def test_get_regions_carries_label_and_mean_variance():
    cm = _vector_from_layout()
    (structural,) = cm.get_regions(ByteClass.STRUCTURAL)
    assert structural.classification == "structural"
    assert structural.mean_variance == 150.0
    (pointer,) = cm.get_regions(ByteClass.POINTER)
    assert pointer.classification == "pointer"
    assert pointer.mean_variance == 2500.0


def test_get_regions_accepts_a_raw_int_code():
    cm = _vector_from_layout()
    assert cm.get_regions(int(ByteClass.POINTER)) == cm.get_regions(ByteClass.POINTER)


def test_get_regions_multi_class_query_merges_adjacent_runs():
    """A union query keeps a mixed-class secret in one piece."""
    cm = _vector_from_layout()
    regions = cm.get_regions([ByteClass.POINTER, ByteClass.KEY_CANDIDATE])
    assert [(r.start, r.end) for r in regions] == [(60, 100)]
    # Labelled by the most volatile class present.
    assert regions[0].classification == "key_candidate"


def test_get_regions_min_length_filters():
    cm = _vector_from_layout()
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, min_length=40)] == [(0, 40), (100, 140)]
    assert cm.get_regions(ByteClass.STRUCTURAL, min_length=21) == []


def test_get_regions_max_length_bounds():
    cm = _vector_from_layout()
    # Both invariant runs are 40 bytes; the structural run is 20.
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, max_length=39)] == []
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, max_length=40)] == [(0, 40), (100, 140)]


def test_get_regions_max_length_zero_is_unbounded():
    cm = _vector_from_layout()
    assert cm.get_regions(ByteClass.INVARIANT, max_length=0) == cm.get_regions(
        ByteClass.INVARIANT
    )


def test_get_regions_rejects_empty_class_query():
    cm = _vector_from_layout()
    with pytest.raises(ValueError, match="at least one"):
        cm.get_regions([])


def test_get_regions_honours_custom_thresholds():
    """Raising structural_max above 2500 turns the POINTER run STRUCTURAL."""
    wide = VarianceThresholds(0.0, 3000.0, 8000.0)
    cm = _vector_from_layout(thresholds=wide)
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.STRUCTURAL)] == [
        (40, 80),
    ]
    assert cm.get_regions(ByteClass.POINTER) == []


def test_legacy_getters_return_exactly_what_they_returned_before():
    """Pinned against hand-built rows, not against get_regions."""
    cm = _vector_from_layout()
    assert cm.get_static_regions() == [
        StaticRegion(start=0, end=40, mean_variance=0.0,
                     classification="invariant"),
        StaticRegion(start=100, end=140, mean_variance=0.0,
                     classification="invariant"),
    ]
    assert cm.get_volatile_regions() == [
        StaticRegion(start=80, end=100, mean_variance=9000.0,
                     classification="key_candidate"),
    ]


def test_legacy_getters_keep_their_default_min_lengths():
    """32 for static, 16 for volatile — a 20-byte run passes one, not both."""
    layout = [(20, 0.0), (20, 9000.0), (20, 0.0)]
    cm = _vector_from_layout(layout)
    assert cm.get_static_regions() == []
    assert cm.get_static_regions(min_length=20) == [
        StaticRegion(start=0, end=20, mean_variance=0.0,
                     classification="invariant"),
        StaticRegion(start=40, end=60, mean_variance=0.0,
                     classification="invariant"),
    ]
    assert cm.get_volatile_regions() == [
        StaticRegion(start=20, end=40, mean_variance=9000.0,
                     classification="key_candidate"),
    ]
