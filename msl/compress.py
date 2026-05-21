"""Block payload (de)compression for MSL files."""

import logging

from .enums import CompAlgo
from .types import MslParseError

logger = logging.getLogger("memdiver.msl.compress")


def compress(payload: bytes, algo: CompAlgo) -> bytes:
    """Compress a block payload using the specified algorithm.

    Mirrors :func:`decompress`. NONE is a pass-through. ZSTD and LZ4
    require their respective optional dependencies; if a library is
    missing, raises ``MslParseError`` (matching the reader's error
    contract so callers can surface a uniform message).

    Args:
        payload: Plaintext block payload bytes.
        algo: Compression algorithm to apply.

    Returns:
        Compressed payload bytes (or the original for ``CompAlgo.NONE``).
    """
    if algo == CompAlgo.NONE:
        return payload

    if algo == CompAlgo.ZSTD:
        try:
            import zstandard
        except ImportError:
            raise MslParseError(
                "zstandard not installed; install with: pip install memdiver"
            )
        logger.debug("Compressing %d bytes with zstd", len(payload))
        return zstandard.ZstdCompressor().compress(payload)

    if algo == CompAlgo.LZ4:
        try:
            import lz4.frame
        except ImportError:
            raise MslParseError(
                "lz4 not installed; install with: pip install memdiver"
            )
        logger.debug("Compressing %d bytes with lz4", len(payload))
        return lz4.frame.compress(payload)

    raise MslParseError(f"Unsupported compression algorithm: {algo}")


def decompress(payload: bytes, algo: CompAlgo) -> bytes:
    """Decompress a block payload using the specified algorithm.

    Args:
        payload: Raw (possibly compressed) block payload bytes.
        algo: Compression algorithm indicator from the block header.

    Returns:
        Decompressed payload bytes.

    Raises:
        MslParseError: If the required library is not installed or the
            algorithm is unsupported.
    """
    if algo == CompAlgo.NONE:
        return payload

    if algo == CompAlgo.ZSTD:
        try:
            import zstandard
        except ImportError:
            raise MslParseError(
                "zstandard not installed; install with: pip install memdiver"
            )
        logger.debug("Decompressing %d bytes with zstd", len(payload))
        return zstandard.ZstdDecompressor().decompress(payload)

    if algo == CompAlgo.LZ4:
        try:
            import lz4.frame
        except ImportError:
            raise MslParseError(
                "lz4 not installed; install with: pip install memdiver"
            )
        logger.debug("Decompressing %d bytes with lz4", len(payload))
        return lz4.frame.decompress(payload)

    raise MslParseError(f"Unsupported compression algorithm: {algo}")


def is_available(algo: CompAlgo) -> bool:
    """Check whether the library for *algo* is importable.

    Returns True for ``CompAlgo.NONE`` (no external dependency needed).
    """
    if algo == CompAlgo.NONE:
        return True

    if algo == CompAlgo.ZSTD:
        try:
            import zstandard  # noqa: F401
            return True
        except ImportError:
            return False

    if algo == CompAlgo.LZ4:
        try:
            import lz4.frame  # noqa: F401
            return True
        except ImportError:
            return False

    return False
