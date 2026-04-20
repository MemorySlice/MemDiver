"""Tests for algorithms.unknown_key.structure_scan module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.base import AnalysisContext
from algorithms.unknown_key.structure_scan import StructureScanAlgorithm
from core.constants import UNKNOWN_KEY


def _make_context(protocol_version="", library="test", phase="post_handshake"):
    return AnalysisContext(
        library=library,
        protocol_version=protocol_version,
        phase=phase,
    )


def test_finds_embedded_structure():
    """Put 96 bytes of 0xFF at offset 128 — should match a TLS structure."""
    data = bytearray(512)
    data[128:224] = b"\xff" * 96
    algo = StructureScanAlgorithm()
    result = algo.run(bytes(data), _make_context())
    assert len(result.matches) >= 1
    names = [m.metadata["structure_name"] for m in result.matches]
    # Either TLS 1.2 or TLS 1.3 structure (polymorphic collapse changed ranking)
    assert any(n.startswith("tls1") for n in names)


def test_no_match_zero_data():
    """All zeros — too uniform for high-entropy detection, and not_zero
    constraints correctly reject zero-filled BYTES fields.  Use a size
    smaller than any registered structure (minimum is aes_key_block at
    44 bytes) but >= scan window (32) so the algorithm runs but finds
    nothing."""
    data = b"\x00" * 40  # fits scan window but too short for any structure
    algo = StructureScanAlgorithm()
    result = algo.run(data, _make_context())
    assert len(result.matches) == 0
    assert result.confidence == 0.0


def test_small_dump():
    """Dump smaller than scan window returns empty with reason."""
    data = b"\xab" * 8
    algo = StructureScanAlgorithm()
    result = algo.run(data, _make_context())
    assert result.matches == []
    assert result.metadata.get("reason") == "dump too small"


def test_protocol_filter():
    """With protocol_version='13', matches should only be TLS (or generic)."""
    data = bytearray(512)
    data[0:64] = b"\xfe" * 64
    algo = StructureScanAlgorithm()
    result = algo.run(bytes(data), _make_context(protocol_version="13"))
    for m in result.matches:
        assert m.metadata["protocol"] in ("TLS", "")


def test_registry_discovery():
    """structure_scan should be discoverable via AlgorithmRegistry."""
    from algorithms.registry import AlgorithmRegistry

    registry = AlgorithmRegistry()
    registry.discover()
    assert "structure_scan" in registry.names
    algo = registry.get("structure_scan")
    assert algo.mode == UNKNOWN_KEY
