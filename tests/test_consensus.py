"""Tests for engine.consensus module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.variance import ByteClass
from engine.consensus import ConsensusVector, INVARIANT_MAX, STRUCTURAL_MAX, POINTER_MAX


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
