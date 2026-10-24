"""Sealed extension segments after the primary AEAD tag (spec 1.1.1 §10.8).

Containers come from MemDiver's writer (``CipherLen != 0``); sealed
segments are appended with :func:`memdiver.msl.sealed.seal_segment` and —
for AES-256-GCM, when importable — with memslicer's own ``seal_segment``,
so the reader is checked against the reference producer's bytes. Every
reader case runs in both one-shot and seek mode.
"""

import struct

import pytest

from memdiver.msl import crypto
from memdiver.msl.aead_seek import ONESHOT_ENV
from memdiver.msl.enums import CIPHER_LEN_OFFSET, EncAlgo, TagStatus
from memdiver.msl.integrity import stream_hasher_factory, verify_chain
from memdiver.msl.reader import MslReader
from memdiver.msl.sealed import (SEAL_HEADER_SIZE, SealHeader, check_seal_header,
                                 seal_segment)
from memdiver.msl.writer import ExtensionBlock, MslEncryptionConfig, MslWriter

try:  # interop: the reference producer (memslicer), when installed
    from memslicer.msl.sealed import seal_segment as memslicer_seal_segment
except ImportError:  # pragma: no cover - depends on the environment
    memslicer_seal_segment = None

_KEY = bytes(range(32))
_MANIFEST = 0x005A          # ModuleBuildIdManifest: permitted in a segment
_EOX = 0x0FFE
_TAG = 16
_GARBAGE = b"NOT-A-SEALED-SEGMENT" * 4


@pytest.fixture(params=["oneshot", "seek"])
def mode(request, monkeypatch):
    if request.param == "oneshot":
        monkeypatch.setenv(ONESHOT_ENV, "1")
    else:
        monkeypatch.delenv(ONESHOT_ENV, raising=False)
    return request.param


@pytest.fixture(params=[EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305],
                ids=lambda a: a.name)
def algo(request):
    if not crypto.cipher_is_available(request.param):
        pytest.skip(f"{request.param.name} backend not installed")
    return request.param


# -- builders -------------------------------------------------------------

def _write(path, algo, segment_blocks=None):
    w = MslWriter(path, pid=7, encryption=MslEncryptionConfig(enc_algo=algo, raw_key=_KEY))
    w.add_memory_region(0x4000, bytes(range(256)) * 16)
    w.add_end_of_capture()
    if segment_blocks:
        w.add_extension_segment("sealer/1.0", segment_blocks)
    w.write()
    return path


def _plaintext_segment(tmp_path, algo, payload: bytes, block_type=_MANIFEST) -> bytes:
    """One extension segment with zero PrevHash: cut out of an AEAD stream."""
    path = _write(tmp_path / f"src_{payload[:4].hex()}.msl", algo,
                  [ExtensionBlock(block_type, payload)])
    with MslReader(path, key=_KEY) as r:
        (seg,) = r.scan_extension_segments()
        return r.read_bytes(seg.start, seg.end - seg.start)


def _context(path):
    with MslReader(path, key=_KEY) as r:
        assert r.tag_status is TagStatus.VALID
        return r._seal_context(), r.post_tag_offset


def _seal(path, plaintexts, *, use_memslicer=False):
    """Append sealed segments 1..n; returns their byte strings."""
    ctx, _ = _context(path)
    prev, units = ctx.primary_tag, []
    for i, pt in enumerate(plaintexts, start=1):
        if use_memslicer:
            unit = memslicer_seal_segment(ctx.cek, ctx.header, ctx.kem_ct, prev, i, pt)
        else:
            unit = seal_segment(ctx, prev, i, pt)
        units.append(unit)
        prev = unit[-_TAG:]
    with open(path, "ab") as f:
        f.write(b"".join(units))
    return units


def _base_with_segments(tmp_path, algo, n, **kw):
    path = _write(tmp_path / "base.msl", algo)
    pts = [_plaintext_segment(tmp_path, algo, bytes([0x41 + i]) * 24) for i in range(n)]
    units = _seal(path, pts, **kw)
    return path, units


def _facts(path):
    with MslReader(path, key=_KEY) as r:
        assert r.tag_status is TagStatus.VALID
        blocks = [(h.block_type, h.seal_index, p) for h, p in r.iter_extension_blocks()]
        report = verify_chain(r)
        assert report.valid, report.errors
        return {
            "sealed": [s.seal_index for s in r.sealed_segments()],
            "trailing": r.sealed_trailing_bytes,
            "blocks": blocks,
            "report": report,
            "eox": len(r.collect_end_of_extension()),
        }


# -- tests ----------------------------------------------------------------

def test_seal_header_roundtrip_and_magic_bytes():
    raw = SealHeader(3, 99, b"\x01" * 12).pack()
    assert len(raw) == SEAL_HEADER_SIZE and raw[:4] == b"\x4D\x53\x4C\x53"
    assert SealHeader.unpack(raw).seg_index == 3
    assert check_seal_header(raw, 64 + 99 + _TAG, 3) is not None
    assert check_seal_header(raw, 64 + 98 + _TAG, 3) is None   # too long
    assert check_seal_header(raw, 64 + 99 + _TAG, 2) is None   # wrong index


@pytest.mark.parametrize("n", [1, 2])
def test_sealed_segments_visible_in_order(tmp_path, algo, mode, n):
    path, _ = _base_with_segments(tmp_path, algo, n)
    facts = _facts(path)
    assert facts["sealed"] == list(range(1, n + 1))
    assert facts["trailing"] == 0
    assert [(t, s) for t, s, _ in facts["blocks"]] == [
        pair for i in range(1, n + 1) for pair in ((_MANIFEST, i), (_EOX, i))]
    payloads = [p for t, _, p in facts["blocks"] if t == _MANIFEST]
    assert payloads == [bytes([0x41 + i]) * 24 for i in range(n)]
    assert [s.seal_index for s in facts["report"].sealed_segments] == list(range(1, n + 1))
    assert facts["report"].sealed_trailing_bytes == 0 and facts["eox"] == n


def test_sealed_blocks_follow_in_stream_segment(tmp_path, algo, mode):
    path = _write(tmp_path / "base.msl", algo, [ExtensionBlock(0x1003, b"G" * 16)])
    _seal(path, [_plaintext_segment(tmp_path, algo, b"S" * 16)])
    with MslReader(path, key=_KEY) as r:
        order = [(h.block_type, h.seal_index) for h, _ in r.iter_extension_blocks()]
        assert order == [(0x1003, 0), (_EOX, 0), (_MANIFEST, 1), (_EOX, 1)]
        (sealed,) = r.sealed_segments()
        assert sealed.segment.index == 1 and sealed.segment.seal_index == 1


@pytest.mark.skipif(memslicer_seal_segment is None, reason="memslicer not importable")
def test_memslicer_sealed_segments_interop(tmp_path, mode):
    path, _ = _base_with_segments(tmp_path, EncAlgo.AES_256_GCM, 2, use_memslicer=True)
    facts = _facts(path)
    assert facts["sealed"] == [1, 2] and facts["trailing"] == 0


def test_tampered_segment_two_keeps_only_segment_one(tmp_path, algo, mode):
    path, units = _base_with_segments(tmp_path, algo, 2)
    raw = bytearray(path.read_bytes())
    raw[len(raw) - len(units[1]) + SEAL_HEADER_SIZE + 3] ^= 0x01
    path.write_bytes(bytes(raw))
    facts = _facts(path)
    assert facts["sealed"] == [1]
    assert facts["trailing"] == len(units[1])
    assert all(s == 1 for _, s, _ in facts["blocks"])


def test_reordered_segments_verify_none(tmp_path, algo, mode):
    path, units = _base_with_segments(tmp_path, algo, 2)
    raw = path.read_bytes()
    body = raw[:len(raw) - len(units[0]) - len(units[1])]
    path.write_bytes(body + units[1] + units[0])
    facts = _facts(path)
    assert facts["sealed"] == [] and facts["blocks"] == []
    assert facts["trailing"] == len(units[0]) + len(units[1])


def test_trailing_garbage_after_last_segment(tmp_path, algo, mode):
    path, _ = _base_with_segments(tmp_path, algo, 2)
    with open(path, "ab") as f:
        f.write(_GARBAGE)
    facts = _facts(path)
    assert facts["sealed"] == [1, 2] and facts["trailing"] == len(_GARBAGE)
    assert any("trailing" in w for w in facts["report"].warnings)


def test_wrong_seg_index_is_trailing(tmp_path, algo, mode):
    path = _write(tmp_path / "base.msl", algo)
    ctx, post_tag = _context(path)
    unit = seal_segment(ctx, ctx.primary_tag, 2, _plaintext_segment(tmp_path, algo, b"X" * 8))
    with open(path, "ab") as f:
        f.write(unit)
    facts = _facts(path)
    assert facts["sealed"] == [] and facts["trailing"] == len(unit)


def test_forbidden_block_type_rejected(tmp_path, algo, mode):
    path = _write(tmp_path / "base.msl", algo)
    pt = bytearray(_plaintext_segment(tmp_path, algo, b"F" * 8))
    struct.pack_into("<H", pt, 4, 0x0040)  # PROCESS_IDENTITY: evidence type
    _rehash_segment(pt, ctx_hash_algo(path))  # only the type check may fail
    units = _seal(path, [bytes(pt)])
    facts = _facts(path)
    assert facts["sealed"] == [] and facts["trailing"] == len(units[0])


def ctx_hash_algo(path) -> int:
    return _context(path)[0].hash_algo


def _rehash_segment(pt: bytearray, hash_algo: int) -> None:
    """Recompute the End-of-Extension SegmentHash of a one-block segment."""
    eox_at = struct.unpack_from("<I", pt, 8)[0]
    h = stream_hasher_factory(hash_algo)()
    h.update(bytes(pt[:eox_at]))
    pt[eox_at + 80:eox_at + 112] = h.digest()


def test_zero_cipher_len_parses_no_sealed_segments(tmp_path, algo, mode):
    path, units = _base_with_segments(tmp_path, algo, 1)
    # Strip the sealed segment, set CipherLen=0 (1.1.0 layout: tag at EOF).
    raw = bytearray(path.read_bytes()[:-len(units[0])])
    struct.pack_into("<Q", raw, CIPHER_LEN_OFFSET, 0)
    path.write_bytes(bytes(raw))
    with MslReader(path, key=_KEY) as r:
        assert r.tag_status is TagStatus.VALID
        assert r.sealed_segments() == [] and r.sealed_trailing_bytes == 0


def test_no_key_exposes_nothing(tmp_path, algo, mode):
    path, _ = _base_with_segments(tmp_path, algo, 1)
    with MslReader(path) as r:
        assert r.tag_status is TagStatus.MISSING_KEY
        assert r.sealed_segments() == [] and list(r.iter_extension_blocks()) == []
