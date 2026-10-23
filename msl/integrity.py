"""Block chain integrity verification for MSL files.

:func:`verify_chain` checks the capture segment (PrevHash chain, EoC
FileHash, header / EoC BlockCount per consumer rule 13) and then every
extension segment after the EoC (spec 4.6: chain continuity, SegmentHash,
BlockCount). :func:`verify_extension_segments` is the segment part on its
own; :meth:`MslReader.iter_extension_blocks` uses it to hide unverified
segments.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .enums import BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, HashAlgo
from .hashing import _new_hasher, hash_bytes
from .types import MslParseError

logger = logging.getLogger("memdiver.msl.integrity")


@dataclass
class SegmentReport:
    """Verification result of one extension segment (spec 4.6).

    ``verified`` is True only when the segment is terminated and chain
    continuity, SegmentHash and BlockCount all check out; everything from
    the first unverified segment to EOF is trailing data.
    """
    index: int
    start: int
    end: int
    block_count: int          # blocks parsed incl. the terminator (if any)
    producer: str = ""
    terminated: bool = False
    chain_ok: bool = True
    segment_hash_ok: bool = False
    block_count_ok: bool = False
    errors: List[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return (self.terminated and self.chain_ok and self.segment_hash_ok
                and self.block_count_ok)


@dataclass
class IntegrityReport:
    """Result of block chain verification."""
    valid: bool = True
    block_count: int = 0      # capture-segment blocks parsed, incl. EoC
    broken_at: Optional[int] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # True for files written by MemDiver before block 0 chained from the
    # header: block 0 carries a zero PrevHash, so the header is unprotected
    # but every block-to-block link is still checked.
    legacy_unchained_header: bool = False
    # EoC FileHash: True / False when checked, None when absent or all-zero
    # (not recorded -> warning only).
    file_hash_ok: Optional[bool] = None
    # Consumer rule 13: every non-zero count must equal block_count.
    header_block_count: int = 0
    eoc_block_count: int = 0
    block_count_ok: bool = True
    # Extension segments after the EoC (spec 4.6) and the trailing bytes
    # after the last verified one.
    segments: List[SegmentReport] = field(default_factory=list)
    trailing_bytes: int = 0
    # True when the capture segment alone (header .. EoC) verified cleanly;
    # ``valid`` additionally requires every terminated segment to verify.
    capture_ok: bool = True

    @property
    def verified_segments(self) -> List[SegmentReport]:
        return [seg for seg in self.segments if seg.verified]


_ZERO_HASH = b'\x00' * 32


def _sha512_256(data: bytes) -> bytes:
    return hashlib.new("sha512_256", data).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# HashAlgo (header 0x3D) selects the PrevHash function (spec Table 3 / §4.4).
_CHAIN_HASHERS = {
    HashAlgo.BLAKE3: hash_bytes,
    HashAlgo.SHA256: _sha256,
    HashAlgo.SHA512_256: _sha512_256,
}

# Incremental twins of _CHAIN_HASHERS (hashlib-style ``update`` / ``digest``)
# for FileHash / SegmentHash over multi-GB spans.
_STREAM_HASHERS = {
    HashAlgo.BLAKE3: _new_hasher,
    HashAlgo.SHA256: hashlib.sha256,
    HashAlgo.SHA512_256: lambda: hashlib.new("sha512_256"),
}

_HASH_CHUNK = 16 << 20


def chain_hasher(hash_algo: int) -> Optional[Callable[[bytes], bytes]]:
    """Return the PrevHash function for *hash_algo*, or None if unknown."""
    try:
        return _CHAIN_HASHERS.get(HashAlgo(hash_algo))
    except ValueError:
        return None


def stream_hasher_factory(hash_algo: int) -> Optional[Callable[[], object]]:
    """Return a constructor of incremental hashers for *hash_algo*, or None."""
    try:
        return _STREAM_HASHERS.get(HashAlgo(hash_algo))
    except ValueError:
        return None


def _hash_span(buf, start: int, end: int, factory) -> bytes:
    """Incremental hash of ``buf[start:end]`` in bounded chunks."""
    h = factory()
    for off in range(start, end, _HASH_CHUNK):
        h.update(bytes(buf[off:min(off + _HASH_CHUNK, end)]))
    return h.digest()


def expected_block0_prev_hash(reader, hasher: Callable[[bytes], bytes]) -> bytes:
    """Block 0's PrevHash per spec §4.4: hash of all HeaderSize header bytes
    as stored on disk. Encrypted files mandate zeros (§10.6)."""
    if reader.file_header.encrypted:
        return _ZERO_HASH
    header_size = reader.file_header.header_size
    return hasher(bytes(reader._mmap[0:header_size]))


def verify_chain(reader) -> IntegrityReport:
    """Verify the integrity of an open MslReader.

    Capture segment: every block's PrevHash (plaintext files; encrypted
    files rely on the AEAD tag, rule 16), the EoC FileHash (all-zero =
    not recorded -> warning) and consumer rule 13 (header and EoC
    BlockCount vs the parsed count). Then every extension segment after
    the EoC (spec 4.6): chain continuity from H(EoC), SegmentHash and
    BlockCount; an unterminated segment is a warning and trailing data, a
    terminated segment that fails is an error.
    """
    report = IntegrityReport()
    buf = reader._buf
    if buf is None:
        report.valid = False
        report.errors.append("Reader not opened (or encrypted without a key)")
        return report

    # Encrypted files (spec §14.2 rule 16): skip PrevHash verification — all
    # PrevHash fields are zero by mandate (§10.6) and integrity is provided by
    # the AEAD tag, already verified at open() (reader.tag_status). We still
    # walk the decrypted blocks to count them.
    skip_prev_hash = bool(reader.file_header.encrypted)

    hasher = chain_hasher(reader.file_header.hash_algo)
    if hasher is None:
        report.valid = False
        report.errors.append(
            f"Unsupported HashAlgo 0x{reader.file_header.hash_algo:02X}")
        return report
    prev_hash = expected_block0_prev_hash(reader, hasher)
    offset = reader._buf_base
    file_size = len(buf)
    eoc_header = None

    while offset + BLOCK_HEADER_SIZE <= file_size:
        if buf[offset:offset + 4] != BLOCK_MAGIC:
            break
        hdr = reader._parse_block_header(offset)
        if hdr.block_length < BLOCK_HEADER_SIZE:
            report.valid = False
            report.errors.append(f"Invalid block length at 0x{offset:X}")
            report.broken_at = offset
            break

        end = offset + hdr.block_length
        if end > file_size:
            report.valid = False
            report.errors.append(f"Truncated block at 0x{offset:X}")
            report.broken_at = offset
            break

        if (not skip_prev_hash and report.block_count == 0
                and hdr.prev_hash == _ZERO_HASH and prev_hash != _ZERO_HASH):
            # Pre-fix MemDiver files: tolerated, but the header is unverified.
            report.legacy_unchained_header = True
            report.warnings.append(
                "Block 0 PrevHash is zero (legacy MemDiver writer): the file "
                "header is not covered by the chain")
            prev_hash = _ZERO_HASH

        # Check prev_hash matches expected (plaintext files only)
        if not skip_prev_hash and hdr.prev_hash != prev_hash:
            report.valid = False
            report.errors.append(
                f"Hash mismatch at block 0x{offset:X}: "
                f"expected {prev_hash[:8].hex()}..., "
                f"got {hdr.prev_hash[:8].hex()}..."
            )
            if report.broken_at is None:
                report.broken_at = offset

        prev_hash = hasher(bytes(buf[offset:end]))
        report.block_count += 1
        offset = end
        if hdr.block_type == BlockType.END_OF_CAPTURE:
            eoc_header = hdr
            break

    _check_block_counts(reader, report, eoc_header)
    if eoc_header is not None:
        _check_file_hash(reader, report, eoc_header)
    report.capture_ok = report.valid
    if eoc_header is not None:
        _verify_segments_into(reader, report, hasher)
    return report


def _check_block_counts(reader, report: IntegrityReport, eoc_header) -> None:
    """Consumer rule 13: non-zero header / EoC counts must match the parse."""
    report.header_block_count = int(reader.file_header.block_count)
    if eoc_header is not None:
        try:
            report.eoc_block_count = int(
                reader.collect_end_of_capture()[0].block_count)
        except (IndexError, MslParseError, ValueError):
            report.eoc_block_count = 0
    for label, stored in (("header", report.header_block_count),
                          ("EoC", report.eoc_block_count)):
        if stored and stored != report.block_count:
            report.valid = False
            report.block_count_ok = False
            report.errors.append(
                f"{label} BlockCount {stored} != {report.block_count} "
                f"capture-segment blocks parsed (truncated or corrupt)")


def _check_file_hash(reader, report: IntegrityReport, eoc_header) -> None:
    """EoC FileHash = H(bytes 0 .. EoC start); over plaintext when encrypted."""
    stored = bytes(reader._buf[eoc_header.payload_offset:
                               eoc_header.payload_offset + 32])
    if stored == _ZERO_HASH:
        report.warnings.append("EoC FileHash is zero (not recorded by the producer)")
        return
    factory = stream_hasher_factory(reader.file_header.hash_algo)
    if factory is None:  # pragma: no cover - chain_hasher rejected it already
        return
    h = factory()
    if reader.file_header.encrypted:
        # Header + KEM ciphertext (plaintext on disk), then the decrypted
        # blocks before the EoC.
        h.update(bytes(reader._mmap[0:reader._ciphertext_start()]))
    buf = reader._buf
    for off in range(0, eoc_header.file_offset, _HASH_CHUNK):
        h.update(bytes(buf[off:min(off + _HASH_CHUNK, eoc_header.file_offset)]))
    report.file_hash_ok = h.digest() == stored
    if not report.file_hash_ok:
        report.valid = False
        report.errors.append(
            f"EoC FileHash mismatch: stored {stored[:8].hex()}... does not "
            "cover the bytes before the EoC block")


def _verify_segments_into(reader, report: IntegrityReport, hasher) -> None:
    segments, trailing = verify_extension_segments(reader, hasher)
    report.segments = segments
    report.trailing_bytes = trailing
    for seg in segments:
        if seg.verified:
            continue
        if not seg.terminated:
            report.warnings.append(
                f"extension segment {seg.index} at 0x{seg.start:X} is not "
                "terminated by an End-of-Extension block; treated as trailing data")
        else:
            report.valid = False
            report.errors.extend(
                f"extension segment {seg.index}: {err}" for err in seg.errors)
    if trailing:
        report.warnings.append(
            f"{trailing} trailing byte(s) after the last verified segment")


def verify_extension_segments(reader, hasher=None
                              ) -> Tuple[List[SegmentReport], int]:
    """Verify the extension segments of an open reader (spec 4.6).

    Returns ``(reports, trailing_bytes)``. Segments are verified in file
    order and verification is prefix-closed: once a segment fails or is
    unterminated, it and everything after it is trailing data (the reports
    of later segments are still produced, flagged with a broken chain).
    *hasher* defaults to the file's HashAlgo; PrevHash continuity is only
    checked for plaintext files (zero inside an AEAD container).
    """
    if reader._buf is None:
        return [], 0
    if hasher is None:
        hasher = chain_hasher(reader.file_header.hash_algo)
    factory = stream_hasher_factory(reader.file_header.hash_algo)
    if hasher is None or factory is None:
        return [], 0
    segments = reader.scan_extension_segments()
    start = reader._extension_start()
    if start is None:
        return [], 0
    encrypted = bool(reader.file_header.encrypted)
    expected_prev = _ZERO_HASH if encrypted else _hash_preceding_block(reader, start, hasher)
    reports: List[SegmentReport] = []
    verified_end = start
    broken = False
    for seg in segments:
        rep = _verify_one_segment(reader, seg, expected_prev, encrypted, hasher, factory)
        if broken:
            rep.chain_ok = False
            rep.errors.append("follows an unverified segment")
        reports.append(rep)
        if rep.verified and not broken:
            verified_end = seg.end
            expected_prev = _ZERO_HASH if encrypted else hasher(
                bytes(reader._buf[seg.headers[-1].file_offset:seg.end]))
        else:
            broken = True
    return reports, len(reader._buf) - verified_end


def _hash_preceding_block(reader, start: int, hasher) -> bytes:
    """H(EoC block bytes): the block that ends at *start*."""
    for hdr in reader._iter_raw_block_headers():
        if hdr.block_type == BlockType.END_OF_CAPTURE:
            return hasher(bytes(reader._buf[hdr.file_offset:hdr.file_offset + hdr.block_length]))
    return _ZERO_HASH


def _verify_one_segment(reader, seg, expected_prev: bytes, encrypted: bool,
                        hasher, factory) -> SegmentReport:
    buf = reader._buf
    rep = SegmentReport(index=seg.index, start=seg.start, end=seg.end,
                        block_count=len(seg.headers),
                        producer=seg.producer, terminated=seg.terminated)
    if not encrypted:
        for hdr in seg.headers:
            if hdr.prev_hash != expected_prev:
                rep.chain_ok = False
                rep.errors.append(
                    f"PrevHash mismatch at block 0x{hdr.file_offset:X}")
                break
            expected_prev = hasher(bytes(buf[hdr.file_offset:
                                             hdr.file_offset + hdr.block_length]))
    if not seg.terminated:
        rep.errors.append("no End-of-Extension block")
        return rep
    term = seg.terminator
    hashed_end = seg.headers[-1].file_offset
    rep.segment_hash_ok = _hash_span(buf, seg.start, hashed_end, factory) == term.segment_hash
    if not rep.segment_hash_ok:
        rep.errors.append("SegmentHash mismatch")
    rep.block_count_ok = term.block_count == len(seg.headers)
    if not rep.block_count_ok:
        rep.errors.append(
            f"BlockCount {term.block_count} != {len(seg.headers)} blocks parsed")
    return rep
