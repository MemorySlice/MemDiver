"""Materialize of an encrypted .msl with SEALED extension segments (spec 10.8).

Every verified sealed segment of the source is folded into an ordinary
extension segment of the copy, after the in-stream ones and in SegIndex
order, keeping block types / UUIDs / ParentUUIDs / flags / payloads and the
End-of-Extension Producer and WrittenAt. The copy has no sealed segments;
unverified sealed bytes (trailing data) are never copied.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from memdiver.msl.enums import (BlockType, KdfType, RegionType, TagStatus,
                                VasNameSource)
from memdiver.msl.importer import import_dump
from memdiver.msl.integrity import verify_chain
from memdiver.msl.materialize import materialize_msl, stored_regions
from memdiver.msl.reader import MslReader
from memdiver.msl.sealed import seal_segment
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import (ExtensionBlock, MslEncryptionConfig, MslWriter,
                                 _build_vas_map_payload)

from tests.test_msl_materialize import HEAP_STACK, _writer_built_msl

RAW_KEY = bytes(range(32))
PASSPHRASE = b"pw"
_MANIFEST = 0x005A          # ModuleBuildIdManifest: permitted in a segment
_TAG = 16
SEALED_SPECS = [            # (producer, WrittenAt, payloads)
    ("enrich/1.0", 1_700_000_000_000_000_001, [b"A" * 24, b"B" * 40]),
    ("enrich/2.0", 1_700_000_000_000_000_002, [b"C" * 32]),
]


def _cases():
    return {"raw": (MslEncryptionConfig(raw_key=RAW_KEY), {"key": RAW_KEY}),
            "passphrase": (MslEncryptionConfig(kdf_type=KdfType.ARGON2ID,
                                               passphrase=PASSPHRASE),
                           {"passphrase": PASSPHRASE})}


def _segment_plaintext(tmp_path, producer, written_at, blocks) -> bytes:
    """One zero-PrevHash extension segment, cut out of an AEAD stream."""
    path = tmp_path / f"seg_{uuid4().hex}.msl"
    w = MslWriter(path, pid=1, encryption=MslEncryptionConfig(raw_key=RAW_KEY))
    w.add_memory_region(0x4000, b"\x00" * 4096)
    w.add_end_of_capture()
    w.add_extension_segment(producer, blocks, written_at_ns=written_at)
    w.write()
    with MslReader(path, key=RAW_KEY) as r:
        (seg,) = r.scan_extension_segments()
        return r.read_bytes(seg.start, seg.end - seg.start)


def _sealed_blocks(payloads):
    parent = uuid4()
    return [ExtensionBlock(_MANIFEST, p, block_uuid=uuid4(),
                           parent_uuid=parent if i else None)
            for i, p in enumerate(payloads)]


def _seal_onto(path, km, plaintexts, tamper_index=None):
    """Append sealed segments 1..n to *path*; flip a byte of one if asked."""
    with MslReader(path, **km) as r:
        assert r.tag_status is TagStatus.VALID
        ctx = r._seal_context()
    prev, units = ctx.primary_tag, []
    for i, pt in enumerate(plaintexts, start=1):
        unit = bytearray(seal_segment(ctx, prev, i, pt))
        prev = bytes(unit[-_TAG:])
        if i == tamper_index:
            unit[80] ^= 0x01  # inside the ciphertext: tag fails
        units.append(bytes(unit))
    with open(path, "ab") as f:
        f.write(b"".join(units))


def _source(tmp_path, case="raw", tamper_index=None):
    cfg, km = _cases()[case]
    src = _writer_built_msl(tmp_path, encryption=cfg)
    plaintexts = [_segment_plaintext(tmp_path, prod, at, _sealed_blocks(pl))
                  for prod, at, pl in SEALED_SPECS]
    _seal_onto(src, km, plaintexts, tamper_index)
    return src, km


def _segments(reader):
    """Per extension segment: (producer, WrittenAt, seal_index, blocks)."""
    out = []
    for seg in [*reader.scan_extension_segments(),
                *(s.segment for s in reader.sealed_segments())]:
        blocks = [(h.block_type, h.block_uuid, h.parent_uuid, h.flags,
                   reader.read_block_payload(h)) for h in seg.headers[:-1]]
        out.append((seg.producer, seg.terminator.written_at_ns,
                    seg.seal_index, blocks))
    return out


def _comparable(segments, folded_from=None):
    """(producer, WrittenAt, blocks); WrittenAt only for (folded) sealed
    segments — an in-stream segment's copy carries the writer's own."""
    folded_from = folded_from or [seal for _, _, seal, _ in segments]
    return [(p, at if seal else None, b)
            for (p, at, _, b), seal in zip(segments, folded_from)]


def _source_segments(src, km):
    with MslReader(src, **km) as r:
        assert len(r.sealed_segments()) >= 1
        segs = _segments(r)
        return _comparable(segs), [seal for _, _, seal, _ in segs]


def _assert_folded_copy(out, km, source):
    """*out* holds the *source* segments in-stream, verified, nothing sealed."""
    expected, seals = source
    with MslReader(out, **km) as r:
        segs = _segments(r)
        assert _comparable(segs, seals) == expected
        assert all(seal == 0 for _, _, seal, _ in segs)
        assert r.sealed_segments() == [] and r.sealed_trailing_bytes == 0
        report = verify_chain(r)
        assert report.valid, report.errors
        assert len(report.segments) == len(expected)
        assert all(s.verified and s.segment_hash_ok and s.block_count_ok
                   and s.chain_ok for s in report.segments)
        assert report.trailing_bytes == 0 and r.trailing_bytes == 0
        return r.tag_status, _provenance_note(r)


def _provenance_note(reader) -> str:
    from memdiver.msl.decoders import decode_import_provenance
    from memdiver.msl.enums import BlockType
    for hdr, payload in reader.iter_blocks_of_type(BlockType.IMPORT_PROVENANCE):
        return decode_import_provenance(hdr, payload, reader._byte_order).note
    return ""


def test_decrypted_copy_folds_sealed_segments_in_order(tmp_path):
    src, km = _source(tmp_path)
    expected = _source_segments(src, km)
    assert expected[1] == [0, 1, 2]  # pointer-graph segment + 2 sealed
    out = tmp_path / "plain.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True,
                         key_material=km, decrypt_output=True)
    assert result.decrypted_output
    status, note = _assert_folded_copy(out, {}, expected)
    assert status is TagStatus.NOT_ENCRYPTED
    assert "sealed_segments_folded=2" in note


@pytest.mark.parametrize("case", ["raw", "passphrase"])
def test_reencrypted_copy_folds_sealed_segments_inside_ciphertext(tmp_path, case):
    src, km = _source(tmp_path, case)
    expected = _source_segments(src, km)
    out = tmp_path / "rewrap.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True,
                         key_material=km)
    assert result.reencrypted
    status, _ = _assert_folded_copy(out, km, expected)
    assert status is TagStatus.VALID
    with MslReader(out, **km) as r:  # zero PrevHash inside the ciphertext
        heads = [h for s in r.scan_extension_segments() for h in s.headers]
        assert heads and all(h.prev_hash == b"\x00" * 32 for h in heads)


@pytest.mark.parametrize("decrypt", [True, False])
def test_tampered_second_sealed_segment_is_not_copied(tmp_path, decrypt):
    src, km = _source(tmp_path, tamper_index=2)
    expected = _source_segments(src, km)
    assert expected[1] == [0, 1]  # pointer graph + first sealed only
    out = tmp_path / "copy.msl"
    import_dump(src, out, selection=HEAP_STACK, materialize=True,
                key_material=km, decrypt_output=decrypt)
    _, note = _assert_folded_copy(out, {} if decrypt else km, expected)
    assert "sealed_segments_folded=1" in note


def test_source_without_sealed_segments_records_no_fold(tmp_path):
    cfg, km = _cases()["raw"]
    src = _writer_built_msl(tmp_path, encryption=cfg)
    expected = _source_segments_or_none(src, km)
    out = tmp_path / "plain.msl"
    import_dump(src, out, selection=HEAP_STACK, materialize=True,
                key_material=km, decrypt_output=True)
    with MslReader(out) as r:
        assert [p for p, *_ in _segments(r)] == [p for p, *_ in expected]
        assert "sealed_segments_folded" not in _provenance_note(r)


def _source_segments_or_none(src, km):
    with MslReader(src, **km) as r:
        assert r.sealed_segments() == []
        return _segments(r)


# -- sealed VAS maps (spec 5.8 + 10.8) ----------------------------------------

_SEALED_HEAP = MslVasEntry(0x10000000, 0x2000, 0x03, RegionType.HEAP,
                           "[sealed-heap]", VasNameSource.SOURCE_METADATA)


def _vas_block(entries):
    return ExtensionBlock(BlockType.VAS_MAP, _build_vas_map_payload(entries))


def _sealed_vas_source(tmp_path):
    """Sealed #1: only a VAS map; sealed #2: a manifest + the last VAS map."""
    cfg, km = _cases()["raw"]
    src = _writer_built_msl(tmp_path, encryption=cfg)
    old = _vas_block([MslVasEntry(0x10000000, 0x1000, 0x03, RegionType.HEAP,
                                  "[old]")])
    specs = [("vas/1.0", 1, [old]),
             ("vas/2.0", 2, [*_sealed_blocks([b"D" * 16]),
                             _vas_block([_SEALED_HEAP])])]
    _seal_onto(src, km, [_segment_plaintext(tmp_path, p, at, b)
                         for p, at, b in specs])
    return src, km


def test_sealed_vas_maps_are_superseded_not_folded(tmp_path):
    src, km = _sealed_vas_source(tmp_path)
    out = tmp_path / "plain.msl"
    with MslReader(src, **km) as r:
        assert len(r.sealed_segments()) == 2
        assert r.effective_vas_map().entries == [_SEALED_HEAP]
        regions = stored_regions(r, None)
        stats = materialize_msl(r, src, out, regions, [True] * len(regions),
                                "selection=all", decrypt_output=True)
    assert stats.superseded_vas_maps == 2
    assert stats.sealed_segments_folded == 1
    assert stats.dropped_extension_segments == 0
    with MslReader(out) as r:
        assert verify_chain(r).valid
        assert r.collect_extension_vas_maps() == []
        entries = r.effective_vas_map().entries
        assert _SEALED_HEAP in entries
        assert all(e.mapped_path != "[old]" for e in entries)
        producers = [s.producer for s in r.scan_extension_segments()]
        assert "vas/1.0" not in producers and producers[-1] == "vas/2.0"
        assert [h.block_type for h in r.scan_extension_segments()[-1].headers
                ] == [_MANIFEST, BlockType.END_OF_EXTENSION]
        assert "sealed_segments_folded=1" in _provenance_note(r)
