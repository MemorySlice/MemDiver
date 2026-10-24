"""Sealed extension segments (spec 1.1.1 §10.8, Table 27a).

An encrypted container whose header ``CipherLen`` is non-zero may carry,
after its primary AEAD tag::

    … | primary tag | SealHeader 1 | ciphertext 1 | tag 1 | … | [trailing data]

Each sealed segment is a separate AEAD message (header ``EncAlgo``) under
``SegKey_i`` = HKDF-BLAKE3(CEK, salt=DumpUUID, info="MSL-SEG-v1" ‖ LE16(i)),
with associated data::

    AAD_i = header (CipherLen zeroed) ‖ KEM ct ‖ SealHeader_i (as on disk) ‖ Tag_{i-1}

where ``Tag_0`` is the primary tag. The plaintext is exactly one extension
segment (spec 4.6) with zero ``PrevHash`` fields.

:func:`open_sealed_segments` is the consumer side: segments are parsed in
order and the first failure ends the walk — everything from that
segment's first byte is trailing data, and no plaintext of a segment whose
tag failed is ever returned. :func:`seal_segment` is the producer
primitive (byte-identical to memslicer's ``seal_segment`` for AES-256-GCM).
"""

import os
import struct
from dataclasses import dataclass, replace
from typing import List, Optional, Tuple

from .crypto import (CIPHER_NONCE_LEN, aead_decrypt, aead_encrypt,
                     encryption_aad, hkdf_blake3, nonce_for_cipher)
from .enums import EXTENSION_FORBIDDEN_TYPES, EncAlgo
from .integrity import (SegmentReport, _verify_one_segment, chain_hasher,
                        stream_hasher_factory)
from .reader import MslReader
from .types import ExtensionSegment, MslAuthError, MslCryptoError, MslParseError

SEAL_MAGIC = b"MSLS"            # 4D 53 4C 53 on disk, like block magic b"MSLC"
SEAL_HEADER_SIZE = 64
SEGMENT_KEY_INFO = b"MSL-SEG-v1"
MAX_SEGMENT_INDEX = 0xFFFF
SEAL_TAG_LEN = 16
_NONCE_FIELD_LEN = 24
_SEAL_HEADER = struct.Struct("<4sHHQ24s24s")
_RESERVED = b"\x00" * 24
_ZERO_HASH = b"\x00" * 32


@dataclass(frozen=True)
class SealHeader:
    """The 64-byte cleartext header of a sealed segment (Table 27a).

    ``nonce_field`` is the raw 24-byte ``Nonce`` field; the cipher uses its
    prefix, exactly like the file header ``Nonce`` (Table 5).
    """
    seg_index: int
    seg_cipher_len: int
    nonce_field: bytes
    magic: bytes = SEAL_MAGIC
    seal_hdr_size: int = SEAL_HEADER_SIZE

    def pack(self) -> bytes:
        return _SEAL_HEADER.pack(
            self.magic, self.seal_hdr_size, self.seg_index, self.seg_cipher_len,
            self.nonce_field.ljust(_NONCE_FIELD_LEN, b"\x00"), _RESERVED)

    @classmethod
    def unpack(cls, raw: bytes) -> "SealHeader":
        magic, size, index, cipher_len, nonce_field, _ = _SEAL_HEADER.unpack(raw)
        return cls(index, cipher_len, nonce_field, magic, size)


@dataclass(frozen=True)
class SealContext:
    """What opening sealed segments needs from a tag-verified container."""
    algo: EncAlgo
    cek: bytes
    header: bytes        # the file header exactly as on disk
    kem_ct: bytes
    primary_tag: bytes   # Tag_0
    hash_algo: int
    byte_order: str = "<"

    @property
    def dump_uuid(self) -> bytes:
        return self.header[0x18:0x28]


@dataclass(frozen=True)
class SealedSegment:
    """A sealed segment whose tag AND plaintext segment both verified.

    ``offset`` is the file offset of its SealHeader, ``end`` the offset just
    past its tag. ``segment`` frames ``plaintext`` (block offsets are into
    the plaintext, every header stamped with ``seal_index``).
    """
    seal_index: int
    offset: int
    end: int
    tag: bytes
    plaintext: bytes
    segment: ExtensionSegment
    report: SegmentReport


# -- shared primitives ---------------------------------------------------------

def derive_segment_key(cek: bytes, dump_uuid: bytes, index: int) -> bytes:
    """``SegKey_i`` = HKDF-BLAKE3(CEK, DumpUUID, "MSL-SEG-v1" ‖ LE16(i))."""
    if not 1 <= index <= MAX_SEGMENT_INDEX:
        raise ValueError(f"sealed segment index must be 1..{MAX_SEGMENT_INDEX}")
    return hkdf_blake3(cek, bytes(dump_uuid),
                       SEGMENT_KEY_INFO + index.to_bytes(2, "little"))


def segment_aad(header: bytes, kem_ct: bytes, seal_header: bytes,
                prev_tag: bytes) -> bytes:
    """``AAD_i`` = header (CipherLen zeroed) ‖ KEM ct ‖ SealHeader_i ‖ Tag_{i-1}."""
    return encryption_aad(header, kem_ct) + bytes(seal_header) + bytes(prev_tag)


def seal_segment(ctx: SealContext, prev_tag: bytes, index: int,
                 plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
    """Producer primitive: ``SealHeader ‖ ciphertext ‖ tag`` for segment *index*.

    *plaintext* must be one extension segment with zero PrevHash fields;
    *nonce* (cipher-sized) defaults to a fresh CSPRNG value.
    """
    if not plaintext:
        raise ValueError("sealed segment plaintext is empty")
    nonce = nonce if nonce is not None else os.urandom(CIPHER_NONCE_LEN[ctx.algo])
    raw_header = SealHeader(index, len(plaintext), nonce).pack()
    key = derive_segment_key(ctx.cek, ctx.dump_uuid, index)
    aad = segment_aad(ctx.header, ctx.kem_ct, raw_header, prev_tag)
    return raw_header + aead_encrypt(ctx.algo, key, nonce, aad, bytes(plaintext))


# -- consumer ---------------------------------------------------------------

def open_sealed_segments(ctx: SealContext, data, start: int,
                         first_segment_index: int = 0
                         ) -> Tuple[List[SealedSegment], int]:
    """Verify sealed segments i = 1, 2, … in *data* (the file) from *start*.

    *start* is the offset just past the primary tag; *first_segment_index*
    numbers the segments after the in-stream extension segments. Returns
    ``(segments, trailing_offset)`` — trailing data begins at
    ``trailing_offset`` (``len(data)`` when there is none).
    """
    segments: List[SealedSegment] = []
    offset, prev_tag = start, bytes(ctx.primary_tag)
    while len(segments) < MAX_SEGMENT_INDEX:
        sealed = _open_one(ctx, data, offset, len(segments) + 1, prev_tag,
                           first_segment_index + len(segments))
        if sealed is None:
            break
        segments.append(sealed)
        offset, prev_tag = sealed.end, sealed.tag
    return segments, offset


def _open_one(ctx: SealContext, data, offset: int, index: int,
              prev_tag: bytes, segment_index: int) -> Optional[SealedSegment]:
    """Sealed segment *index* at *offset*, or None on any failure."""
    raw_header = bytes(data[offset:offset + SEAL_HEADER_SIZE])
    seal_header = check_seal_header(raw_header, len(data) - offset, index)
    if seal_header is None:
        return None
    body = offset + SEAL_HEADER_SIZE
    end = body + seal_header.seg_cipher_len + SEAL_TAG_LEN
    sealed = bytes(data[body:end])
    plaintext = _decrypt(ctx, seal_header, raw_header, prev_tag, sealed)
    if plaintext is None:
        return None
    verified = verify_segment_plaintext(plaintext, ctx.hash_algo, ctx.byte_order,
                                        segment_index, index)
    if verified is None:
        return None
    segment, report = verified
    report.start, report.end = offset, end
    return SealedSegment(index, offset, end, sealed[-SEAL_TAG_LEN:],
                         plaintext, segment, report)


def check_seal_header(raw: bytes, remaining: int, index: int) -> Optional[SealHeader]:
    """Parse *raw*; None unless it can start sealed segment *index*.

    *remaining* counts the bytes from the header's first byte to EOF.
    """
    if len(raw) < SEAL_HEADER_SIZE:
        return None
    header = SealHeader.unpack(raw)
    room = remaining - SEAL_HEADER_SIZE - SEAL_TAG_LEN
    if (header.magic != SEAL_MAGIC or header.seal_hdr_size != SEAL_HEADER_SIZE
            or header.seg_index != index
            or not 0 < header.seg_cipher_len <= room):
        return None
    return header


def _decrypt(ctx: SealContext, seal_header: SealHeader, raw_header: bytes,
             prev_tag: bytes, sealed: bytes) -> Optional[bytes]:
    """Authenticate and decrypt ``ciphertext ‖ tag``; None if the tag fails."""
    try:
        key = derive_segment_key(ctx.cek, ctx.dump_uuid, seal_header.seg_index)
        nonce = nonce_for_cipher(ctx.algo, seal_header.nonce_field)
        aad = segment_aad(ctx.header, ctx.kem_ct, raw_header, prev_tag)
        return aead_decrypt(ctx.algo, key, nonce, aad, sealed)
    except (MslAuthError, MslCryptoError, ValueError):
        return None


def verify_segment_plaintext(plaintext: bytes, hash_algo: int, byte_order: str,
                             segment_index: int, seal_index: int
                             ) -> Optional[Tuple[ExtensionSegment, SegmentReport]]:
    """Check *plaintext* is exactly one valid extension segment (spec 4.6).

    Reuses the reader's segment framing and :mod:`integrity`'s SegmentHash /
    BlockCount check, plus: the End-of-Extension block ends exactly at the
    end of *plaintext*, every PrevHash is zero and no evidence block type
    occurs. Returns the stamped segment and its report, or None.
    """
    hasher, factory = chain_hasher(hash_algo), stream_hasher_factory(hash_algo)
    if hasher is None or factory is None:
        return None
    view = _PlaintextBlocks(plaintext, byte_order)
    try:
        segment = view._frame_segment(segment_index, 0)
    except MslParseError:
        return None
    if not _is_whole_clean_segment(segment, len(plaintext)):
        return None
    report = _verify_one_segment(view, segment, _ZERO_HASH, True, hasher, factory)
    if not report.verified:
        return None
    report.seal_index = seal_index
    return _stamp(segment, seal_index), report


def _is_whole_clean_segment(segment: Optional[ExtensionSegment], size: int) -> bool:
    """Terminated, ends at *size*, zero PrevHash, no forbidden block type."""
    return (segment is not None and segment.terminated and segment.end == size
            and all(h.prev_hash == _ZERO_HASH for h in segment.headers)
            and not any(h.block_type in EXTENSION_FORBIDDEN_TYPES
                        for h in segment.headers))


def _stamp(segment: ExtensionSegment, seal_index: int) -> ExtensionSegment:
    """Attribute *segment* and each of its block headers to *seal_index*."""
    headers = tuple(replace(h, seal_index=seal_index) for h in segment.headers)
    terminator = replace(segment.terminator, block_header=headers[-1])
    return replace(segment, headers=headers, terminator=terminator,
                   seal_index=seal_index)


class _PlaintextBlocks:
    """A buffer-only stand-in for :class:`MslReader` over one plaintext.

    Borrows the reader's own framing methods so a sealed segment is framed
    by exactly the code that frames in-stream segments.
    """
    _parse_block_header = MslReader._parse_block_header
    _frame_segment = MslReader._frame_segment
    _decode_terminator = MslReader._decode_terminator
    _block_buffer = MslReader._block_buffer
    read_block_payload = MslReader.read_block_payload

    def __init__(self, buf: bytes, byte_order: str):
        self._buf = buf
        self._byte_order = byte_order
