"""Tests for the differential (cross-run byte variance) analysis algorithm.

Validates error handling for insufficient dumps, identical-dump invariance,
high-variance key-region detection, narrow-region filtering, and the
missing dump_paths key edge case.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from algorithms.unknown_key.differential import DifferentialAlgorithm
from algorithms.base import AnalysisContext


def _make_dump(data: bytes) -> Path:
    """Write data to a temporary .dump file and return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    f.write(data)
    f.close()
    return Path(f.name)


def test_fewer_than_two_dumps():
    """A single dump file is insufficient for differential analysis."""
    algo = DifferentialAlgorithm()
    dump_path = _make_dump(b"\x42" * 256)
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={"dump_paths": [dump_path]},
    )
    result = algo.run(b"\x42" * 256, context)
    assert result.confidence == 0.0
    assert "error" in result.metadata
    os.unlink(dump_path)


def test_two_identical_dumps():
    """Identical dumps produce zero variance everywhere -- no key candidates."""
    algo = DifferentialAlgorithm()
    data = b"\x42" * 256
    dump1 = _make_dump(data)
    dump2 = _make_dump(data)
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={"dump_paths": [dump1, dump2]},
    )
    result = algo.run(data, context)
    assert result.confidence == 0.0
    assert result.matches == []
    # All bytes should be classified as invariant (zero variance).
    counts = result.metadata["classification_counts"]
    assert counts.get("invariant", 0) == 256
    os.unlink(dump1)
    os.unlink(dump2)


def test_two_different_dumps_key_region():
    """A 32-byte differing region surrounded by identical bytes should be detected.

    dump1 has 0x11 bytes at offset 100-132, dump2 has 0xff bytes there.
    The variance at those positions is maximal, producing a key_candidate region.
    """
    algo = DifferentialAlgorithm()
    dump1_data = b"\x00" * 100 + b"\x11" * 32 + b"\x00" * 100
    dump2_data = b"\x00" * 100 + b"\xff" * 32 + b"\x00" * 100
    dump1 = _make_dump(dump1_data)
    dump2 = _make_dump(dump2_data)
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={"dump_paths": [dump1, dump2]},
    )
    result = algo.run(dump1_data, context)
    # The 32-byte high-variance region should match target key length 32.
    assert len(result.matches) > 0
    # At least one match should overlap the [100, 132) region.
    offsets = [(m.offset, m.offset + m.length) for m in result.matches]
    overlaps = any(start <= 110 and end >= 120 for start, end in offsets)
    assert overlaps, f"No match overlaps the key region [100,132). Got: {offsets}"
    os.unlink(dump1)
    os.unlink(dump2)


def test_small_variance_region_filtered():
    """A 10-byte differing region is too narrow for key lengths [32, 48] and gets filtered."""
    algo = DifferentialAlgorithm()
    # Only 10 bytes differ -- well below the minimum target width of 32 - tolerance(8) = 24.
    dump1_data = b"\x00" * 100 + b"\x11" * 10 + b"\x00" * 100
    dump2_data = b"\x00" * 100 + b"\xff" * 10 + b"\x00" * 100
    dump1 = _make_dump(dump1_data)
    dump2 = _make_dump(dump2_data)
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={"dump_paths": [dump1, dump2]},
    )
    result = algo.run(dump1_data, context)
    assert result.matches == []
    os.unlink(dump1)
    os.unlink(dump2)


def test_no_dump_paths():
    """Missing dump_paths key in context.extra produces zero confidence with error."""
    algo = DifferentialAlgorithm()
    context = AnalysisContext(
        library="test",
        tls_version="13",
        phase="pre_abort",
        extra={},
    )
    result = algo.run(b"\x00" * 256, context)
    assert result.confidence == 0.0
    assert "error" in result.metadata
