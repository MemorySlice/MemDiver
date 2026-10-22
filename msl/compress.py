"""Block payload (de)compression for MSL files.

On-disk framing (spec §4.2.1, Table 9; producer rules (28)-(29), consumer
rules (19)-(20))::

    +0x00  u64 LE  UncompressedSize   exact size of the inflated payload
    +0x08  var     CompressedData     zstd frame | lz4 block (see below)

The codec byte streams match memslicer (the reference producer):

* ZSTD -- one zstd frame (``zstandard.ZstdCompressor().compress``).
* LZ4  -- one lz4 *block* with a 4-byte LE size prefix
  (``lz4.block.compress(data, store_size=True)``).

memslicer releases up to v0.4.4 zero-padded
``UncompressedSize + CompressedData`` to 8 bytes, which the spec does not
allow (BlockLength = 80 + 8 + len(CompressedData)); newer releases do not
pad. Those legacy files are still read: zstd ignores the trailing zeros, and
lz4 block decoding is exact, so :func:`_inflate_lz4_block` retries with up to
7 trailing zero bytes trimmed.

Legacy (pre-spec) MemDiver files stored the bare codec stream: a zstd frame
or an lz4 *frame*, with no size prefix. They are still read (see
:func:`_is_legacy_payload` for why the two layouts cannot be confused).
:func:`compress` always emits the spec framing.
"""

import logging
import struct

from memdiver.core.install_hints import missing_package_message

from .enums import CompAlgo
from .types import MslParseError

logger = logging.getLogger("memdiver.msl.compress")

# Both codecs are base dependencies, so their absence means a broken
# environment, not a forgotten extra. Hoisted so compress/decompress cannot
# drift apart.
_ZSTD_MISSING = missing_package_message("zstandard (the ZSTD block codec)")
_LZ4_MISSING = missing_package_message("lz4 (the LZ4 block codec)")

_SIZE_PREFIX = struct.Struct("<Q")      # spec UncompressedSize
_LZ4_STORED_SIZE = struct.Struct("<I")  # lz4.block store_size header
_ZSTD_FRAME_MAGIC = b"\x28\xB5\x2F\xFD"  # 0xFD2FB528 LE
_LZ4_FRAME_MAGIC = b"\x04\x22\x4D\x18"   # 0x184D2204 LE
_MAX_LZ4_PAD_TRIM = 7                    # memslicer <= v0.4.4 padded to 8 B


def _import_zstd():
    try:
        import zstandard
    except ImportError:
        raise MslParseError(_ZSTD_MISSING)
    return zstandard


def _import_lz4_block():
    try:
        import lz4.block
    except ImportError:
        raise MslParseError(_LZ4_MISSING)
    return lz4.block


def _import_lz4_frame():
    try:
        import lz4.frame
    except ImportError:
        raise MslParseError(_LZ4_MISSING)
    return lz4.frame


def _is_legacy_payload(payload: bytes, algo: CompAlgo) -> bool:
    """True if *payload* is a legacy bare codec stream (no size prefix).

    The rule is deterministic and cannot misclassify a spec payload:

    * LZ4: legacy iff it starts with the lz4 *frame* magic and byte 4 is
      non-zero. Byte 4 of an lz4 frame is FLG, whose version bits must be
      ``01``, so it is never zero. In a spec payload bytes 4..7 are the high
      half of ``UncompressedSize``, which must be zero: the lz4 block's own
      u32 stored size has to equal it (checked on inflate).
    * ZSTD: legacy iff it starts with the zstd frame magic and offset 8 does
      NOT hold it. A spec payload always carries the zstd frame magic at
      offset 8 (its ``CompressedData`` is a zstd frame), so it is never
      classified legacy, even when the low 32 bits of ``UncompressedSize``
      happen to equal the magic (a ~3.96 GiB payload). Conversely a legacy
      frame would need the magic at offset 8, which falls in its
      Frame_Content_Size / first block header: only possible for content
      >= 640 MiB together with an invalid (>128 KiB) block size, or for
      content >= 2.9 GiB -- beyond anything the legacy writer emitted
      (regions were capped at 1 GiB).
    """
    if algo == CompAlgo.LZ4:
        return payload[:4] == _LZ4_FRAME_MAGIC and payload[4:5] != b"\x00"
    if algo == CompAlgo.ZSTD:
        return (payload[:4] == _ZSTD_FRAME_MAGIC
                and payload[8:12] != _ZSTD_FRAME_MAGIC)
    return False


def _frame(uncompressed_size: int, data: bytes, algo: CompAlgo) -> bytes:
    """Prefix *data* with ``UncompressedSize`` and guard the result."""
    framed = _SIZE_PREFIX.pack(uncompressed_size) + data
    if _is_legacy_payload(framed, algo):
        # Unreachable by construction (see _is_legacy_payload); refuse rather
        # than write a block that a reader would decode as the legacy layout.
        raise MslParseError(
            f"refusing to write ambiguous {algo.name} payload "
            f"(UncompressedSize={uncompressed_size})")
    return framed


def compress(payload: bytes, algo: CompAlgo) -> bytes:
    """Compress a block payload into the spec §4.2.1 on-disk framing.

    Mirrors :func:`decompress`. NONE is a pass-through. ZSTD and LZ4
    require their respective dependencies; if a library is missing,
    raises ``MslParseError`` (matching the reader's error contract so
    callers can surface a uniform message).

    Args:
        payload: Plaintext block payload bytes.
        algo: Compression algorithm to apply.

    Returns:
        ``u64 UncompressedSize`` + compressed data (or the original for
        ``CompAlgo.NONE``). The block's BlockLength is 80 + len(result).
    """
    if algo == CompAlgo.NONE:
        return payload

    if algo == CompAlgo.ZSTD:
        zstandard = _import_zstd()
        logger.debug("Compressing %d bytes with zstd", len(payload))
        return _frame(len(payload),
                      zstandard.ZstdCompressor().compress(payload), algo)

    if algo == CompAlgo.LZ4:
        lz4_block = _import_lz4_block()
        logger.debug("Compressing %d bytes with lz4", len(payload))
        return _frame(len(payload),
                      lz4_block.compress(payload, store_size=True), algo)

    raise MslParseError(f"Unsupported compression algorithm: {algo}")


def _inflate_zstd_frame(data: bytes, expected_size: int) -> bytes:
    """Inflate one zstd frame, rejecting a declared/actual size mismatch."""
    zstandard = _import_zstd()
    try:
        declared = zstandard.frame_content_size(data)
        if declared >= 0 and declared != expected_size:
            raise MslParseError(
                f"zstd block size mismatch: UncompressedSize={expected_size}, "
                f"frame content size={declared}")
        # decompressobj handles frames without a content size and ignores
        # the trailing zero padding of legacy (<= v0.4.4) memslicer files.
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except zstandard.ZstdError as e:
        raise MslParseError(f"malformed zstd block: {e}") from e


def _inflate_lz4_block(data: bytes, expected_size: int) -> bytes:
    """Inflate one size-prefixed lz4 block (lz4.block store_size layout).

    Retries with up to 7 trailing zero bytes trimmed (legacy memslicer's 8-byte
    padding). Only the true end of the block decodes to *expected_size*:
    extra bytes parse as a sequence with a missing/zero match offset and
    a short input truncates the final literal run, both decode errors.
    """
    lz4_block = _import_lz4_block()
    if len(data) < _LZ4_STORED_SIZE.size:
        raise MslParseError("malformed lz4 block: missing stored size")
    stored = _LZ4_STORED_SIZE.unpack_from(data)[0]
    if stored != expected_size:
        raise MslParseError(
            f"lz4 block size mismatch: UncompressedSize={expected_size}, "
            f"lz4 stored size={stored}")
    last_error = None
    for trim in range(_MAX_LZ4_PAD_TRIM + 1):
        if trim and data[len(data) - trim] != 0:
            break  # only zero padding may be trimmed
        if len(data) - trim < _LZ4_STORED_SIZE.size:
            break
        try:
            return lz4_block.decompress(data[:len(data) - trim])
        except lz4_block.LZ4BlockError as e:
            last_error = e
    raise MslParseError(f"malformed lz4 block: {last_error}") from last_error


def _decompress_spec(payload: bytes, algo: CompAlgo) -> bytes:
    """Decode the spec framing: validate and strip ``UncompressedSize``."""
    if len(payload) < _SIZE_PREFIX.size:
        raise MslParseError(
            f"compressed {algo.name} block too small for UncompressedSize "
            f"prefix ({len(payload)} bytes)")
    expected = _SIZE_PREFIX.unpack_from(payload)[0]
    data = payload[_SIZE_PREFIX.size:]
    if algo == CompAlgo.ZSTD:
        logger.debug("Decompressing %d bytes with zstd", len(data))
        result = _inflate_zstd_frame(data, expected)
    else:
        logger.debug("Decompressing %d bytes with lz4", len(data))
        result = _inflate_lz4_block(data, expected)
    if len(result) != expected:  # consumer rule (20)
        raise MslParseError(
            f"decompressed size mismatch: UncompressedSize={expected}, "
            f"got {len(result)}")
    return result


def _decompress_legacy(payload: bytes, algo: CompAlgo) -> bytes:
    """Decode a pre-spec MemDiver payload (bare zstd frame / lz4 frame)."""
    logger.debug("Decompressing %d bytes of legacy %s", len(payload), algo.name)
    if algo == CompAlgo.ZSTD:
        zstandard = _import_zstd()
        try:
            return zstandard.ZstdDecompressor().decompress(payload)
        except zstandard.ZstdError as e:
            raise MslParseError(f"malformed zstd block: {e}") from e
    lz4_frame = _import_lz4_frame()
    try:
        return lz4_frame.decompress(payload)
    except RuntimeError as e:
        raise MslParseError(f"malformed lz4 block: {e}") from e


def decompress(payload: bytes, algo: CompAlgo) -> bytes:
    """Decompress a block payload using the specified algorithm.

    Accepts the spec §4.2.1 framing and, for backward compatibility, the
    legacy MemDiver layout (bare zstd frame / lz4 frame).

    Args:
        payload: Raw (possibly compressed) on-disk block payload bytes.
        algo: Compression algorithm indicator from the block header.

    Returns:
        Decompressed payload bytes.

    Raises:
        MslParseError: If the required library is not installed, the
            algorithm is unsupported, the stream is malformed, or the
            inflated size differs from ``UncompressedSize``.
    """
    if algo == CompAlgo.NONE:
        return payload
    if algo not in (CompAlgo.ZSTD, CompAlgo.LZ4):
        raise MslParseError(f"Unsupported compression algorithm: {algo}")
    payload = bytes(payload)
    if _is_legacy_payload(payload, algo):
        return _decompress_legacy(payload, algo)
    return _decompress_spec(payload, algo)


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
            import lz4.block  # noqa: F401
            return True
        except ImportError:
            return False

    return False
