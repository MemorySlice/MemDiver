"""Tests for msl.compress (de)compression dispatcher."""

import pytest

from msl.compress import compress, decompress, is_available
from msl.enums import CompAlgo
from msl.types import MslParseError

try:
    import zstandard
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


def test_decompress_none_passthrough():
    data = b"\x00\x01\x02\xff" * 16
    assert decompress(data, CompAlgo.NONE) is data


@pytest.mark.skipif(not HAS_ZSTD, reason="zstandard not installed")
def test_decompress_zstd_roundtrip():
    original = b"TLS secrets payload" * 50
    compressed = zstandard.ZstdCompressor().compress(original)
    assert decompress(compressed, CompAlgo.ZSTD) == original


@pytest.mark.skipif(not HAS_LZ4, reason="lz4 not installed")
def test_decompress_lz4_roundtrip():
    original = b"memory region data" * 50
    compressed = lz4.frame.compress(original)
    assert decompress(compressed, CompAlgo.LZ4) == original


def test_decompress_unknown_raises():
    fake_algo = CompAlgo(99) if 99 in CompAlgo.__members__.values() else 99
    # Force an unsupported value through the int path
    with pytest.raises(MslParseError, match="Unsupported compression algorithm"):
        decompress(b"\x00", fake_algo)


def test_is_available_none():
    assert is_available(CompAlgo.NONE) is True


def test_is_available_reports_correctly():
    assert is_available(CompAlgo.ZSTD) == HAS_ZSTD
    assert is_available(CompAlgo.LZ4) == HAS_LZ4


# -- compress() — symmetric with decompress() (Tier 1 A.2) --


def test_compress_none_passthrough():
    """CompAlgo.NONE returns the input object unchanged (no copy)."""
    data = b"\x00\x01\x02\xff" * 16
    assert compress(data, CompAlgo.NONE) is data


@pytest.mark.parametrize(
    "algo,available",
    [(CompAlgo.ZSTD, HAS_ZSTD), (CompAlgo.LZ4, HAS_LZ4)],
)
def test_compress_decompress_symmetry(algo, available):
    """compress() output round-trips through decompress() to the original."""
    if not available:
        pytest.skip(f"{algo.name} library not installed")
    original = b"abc123" * 1024
    compressed = compress(original, algo)
    assert compressed != original  # actually transformed
    assert decompress(compressed, algo) == original


@pytest.mark.skipif(not HAS_ZSTD, reason="zstandard not installed")
def test_compress_zstd_reduces_repetitive_payload():
    """Compressible input is genuinely smaller after zstd compression."""
    original = b"A" * 8192
    compressed = compress(original, CompAlgo.ZSTD)
    assert len(compressed) < len(original) // 10


def test_compress_unknown_raises():
    with pytest.raises(MslParseError, match="Unsupported compression algorithm"):
        compress(b"\x00", 99)
