"""Tests for MslWriter streaming mode and MEMORY_REGION block splitting."""

import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from memdiver.msl.enums import BlockType, CompAlgo, PageState
from memdiver.msl.integrity import verify_chain
from memdiver.msl.key_extract import extract_key_bytes
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

PAGE = 4096


def _pattern(num_pages: int) -> bytes:
    """Distinct bytes per page so misplaced pages are detectable."""
    return b"".join(bytes([(i * 7 + 1) & 0xFF]) * PAGE for i in range(num_pages))


def _source(data: bytes):
    view = memoryview(data)
    return lambda offset, length: view[offset:offset + length]


def _region_data(reader: MslReader, region) -> bytes:
    """Captured bytes of a region block (payload past header + PageStateMap)."""
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    return reader.read_block_payload(region.block_header)[0x20 + map_bytes:]


def _region_summary(path: Path):
    with MslReader(path) as r:
        return [(reg.base_addr, reg.region_size, reg.protection, reg.region_type,
                 reg.page_size_log2, list(reg.page_states), _region_data(r, reg))
                for reg in r.collect_regions()]


def _populate(w: MslWriter, data: bytes, states, streamed: bool) -> None:
    w.add_import_provenance(source_format=1, tool_name="test", orig_file_size=0)
    if streamed:
        w.add_memory_region_source(0x10000, len(data), _source(data),
                                   protection=0x05, region_type=0x02)
        w.add_memory_region_source(0x80000, len(states) * PAGE,
                                   _source(data[:2 * PAGE]), page_states=states)
    else:
        w.add_memory_region(0x10000, data, protection=0x05, region_type=0x02)
        w.add_memory_region(0x80000, data[:2 * PAGE], page_states=states)
    w.add_end_of_capture()


STATES = [PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED,
          PageState.UNMAPPED]


def test_streaming_matches_in_memory(tmp_path):
    data = _pattern(5)
    mem, stream = tmp_path / "mem.msl", tmp_path / "stream.msl"
    w = MslWriter(mem)
    _populate(w, data, STATES, streamed=False)
    w.write()
    w = MslWriter(stream)
    _populate(w, data, STATES, streamed=True)
    w.write_streaming()
    assert _region_summary(stream) == _region_summary(mem)
    with MslReader(stream) as r:
        assert r.file_header.block_count == 4
        assert len(r.collect_end_of_capture()) == 1
        assert r.collect_end_of_capture()[0].block_count == 4
    with MslReader(mem) as r:
        assert r.collect_end_of_capture()[0].block_count == 4


def test_write_dispatches_to_streaming(tmp_path):
    out = tmp_path / "auto.msl"
    w = MslWriter(out)
    _populate(w, _pattern(2), STATES, streamed=True)
    w.write()
    assert _region_summary(out)[0][-1] == _pattern(2)


def test_streaming_integrity_and_eoc_hash(tmp_path):
    from memdiver.msl.hashing import hash_bytes
    out = tmp_path / "s.msl"
    w = MslWriter(out, region_block_cap=3 * PAGE)
    _populate(w, _pattern(7), STATES, streamed=True)
    w.write_streaming()
    with MslReader(out) as r:
        report = verify_chain(r)
        assert report.valid, report.errors
        eoc = r.collect_end_of_capture()[0]
        eoc_offset = eoc.block_header.file_offset
        assert eoc.block_count == report.block_count
    raw = out.read_bytes()
    assert eoc.file_hash == hash_bytes(raw[:eoc_offset])


def test_streaming_pointer_graph_segment_after_eoc(tmp_path):
    """write_streaming emits the pointer-graph extension segment (spec 4.6):
    chained from H(EoC), verified, and excluded from both block counts."""
    from memdiver.msl.hashing import hash_bytes
    from memdiver.msl.types import MslPointerGraphEdge, MslPointerGraphNode
    out = tmp_path / "s_pg.msl"
    w = MslWriter(out, region_block_cap=3 * PAGE)
    _populate(w, _pattern(7), STATES, streamed=True)
    w.add_pointer_graph([MslPointerGraphNode(1, 0x10040, "a")],
                        [MslPointerGraphEdge(0, 0, 1, "self")])
    w.write_streaming()
    with MslReader(out) as r:
        report = verify_chain(r)
        assert report.valid, report.errors
        capture_blocks = len(list(r._iter_raw_block_headers()))
        # import provenance + 3 chunks (7 pages / cap 3) + 2 chunks (4 pages)
        # + EoC; the segment blocks are excluded from every count
        assert report.block_count == capture_blocks == 7
        assert r.file_header.block_count == capture_blocks
        assert r.collect_end_of_capture()[0].block_count == capture_blocks
        assert report.header_block_count == report.eoc_block_count == capture_blocks
        assert report.file_hash_ok is True
        assert len(report.segments) == 1 and report.segments[0].verified
        assert report.trailing_bytes == 0
        graphs = r.collect_pointer_graphs()
        assert len(graphs) == 1 and graphs[0].nodes[0].label == "a"
        eoc_hdr = r.collect_end_of_capture()[0].block_header
        eoc_bytes = r.read_bytes(eoc_hdr.file_offset, eoc_hdr.block_length)
        assert graphs[0].block_header.prev_hash == hash_bytes(eoc_bytes)


@pytest.mark.parametrize("streamed", [False, True])
def test_split_region_into_cap_sized_blocks(tmp_path, streamed):
    data = _pattern(7)
    out = tmp_path / "split.msl"
    w = MslWriter(out, region_block_cap=3 * PAGE)
    if streamed:
        w.add_memory_region_source(0x40000, len(data), _source(data))
    else:
        w.add_memory_region(0x40000, data)
    w.write()
    with MslReader(out) as r:
        regions = r.collect_regions()
        assert [reg.base_addr for reg in regions] == [
            0x40000, 0x40000 + 3 * PAGE, 0x40000 + 6 * PAGE]
        assert [reg.region_size for reg in regions] == [3 * PAGE, 3 * PAGE, PAGE]
        assert b"".join(_region_data(r, reg) for reg in regions) == data
        assert verify_chain(r).valid


def test_split_slices_page_state_map(tmp_path):
    states = [PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED,
              PageState.UNMAPPED, PageState.CAPTURED]
    data = _pattern(3)
    out = tmp_path / "split_states.msl"
    w = MslWriter(out, region_block_cap=2 * PAGE)
    w.add_memory_region_source(0x1000, 5 * PAGE, _source(data), page_states=states)
    w.write()
    summary = _region_summary(out)
    assert [s[5] for s in summary] == [states[0:2], states[2:4], states[4:5]]
    assert [s[6] for s in summary] == [data[:PAGE], data[PAGE:2 * PAGE],
                                       data[2 * PAGE:]]


def test_key_hint_in_second_chunk_resolves(tmp_path):
    data = bytearray(_pattern(6))
    key_offset = 4 * PAGE + 0x10  # lands in chunk 2 (pages 3-5)
    data[key_offset:key_offset + 32] = b"K" * 32
    out = tmp_path / "hint.msl"
    w = MslWriter(out, region_block_cap=3 * PAGE)
    first_uuid = w.add_memory_region_source(0x200000, len(data), _source(bytes(data)))
    chunk_uuid, chunk_offset = w.region_for_va(0x200000 + key_offset)
    assert chunk_uuid != first_uuid and chunk_offset == PAGE + 0x10
    # Hint addressed against the whole region is remapped onto chunk 2.
    w.add_key_hint(first_uuid, key_offset, 32, key_type=1, protocol=1)
    w.add_key_hint(chunk_uuid, chunk_offset, 32, key_type=1, protocol=1)
    w.write()
    with MslReader(out) as r:
        hints = r.collect_key_hints()
        assert all(h.region_uuid == chunk_uuid for h in hints)
        assert all(h.region_offset == chunk_offset for h in hints)
        assert all(extract_key_bytes(r, h) == b"K" * 32 for h in hints)
    assert w.region_for_va(0x100) is None


def test_streaming_peak_memory_is_bounded(tmp_path):
    size = 64 << 20
    data = bytes(size)
    out = tmp_path / "big.msl"
    w = MslWriter(out)
    w.add_memory_region_source(0, size, _source(data))
    w.add_end_of_capture()
    tracemalloc.start()
    try:
        w.write_streaming()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < size // 8
    assert out.stat().st_size > size


def test_short_read_chunk_raises(tmp_path):
    w = MslWriter(tmp_path / "short.msl")
    w.add_memory_region_source(0, 2 * PAGE, lambda off, n: b"\x00" * (n - 1))
    with pytest.raises(ValueError, match="read_chunk returned"):
        w.write_streaming()
    assert not (tmp_path / "short.msl").exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_compression_with_streaming_raises(tmp_path):
    w = MslWriter(tmp_path / "c.msl")
    with pytest.raises(ValueError, match="compressed"):
        w.add_memory_region_source(0, PAGE, _source(bytes(PAGE)),
                                   compression=CompAlgo.ZSTD)


def test_encryption_with_streaming_supported(tmp_path):
    # Streaming encryption is supported now (incremental AEAD, same format);
    # byte-equivalence with the in-memory path: test_msl_writer_stream_encrypt.
    key = b"\x01" * 32
    w = MslWriter(tmp_path / "e.msl",
                  encryption=MslEncryptionConfig(raw_key=key))
    w.add_memory_region_source(0, PAGE, _source(_pattern(1)))
    w.write_streaming()
    with MslReader(tmp_path / "e.msl", key=key) as r:
        assert r.tag_status.name == "VALID"
        assert len(r.collect_regions()) == 1


def test_unaligned_block_cap_rejected(tmp_path):
    w = MslWriter(tmp_path / "x.msl", region_block_cap=PAGE + 1)
    with pytest.raises(ValueError, match="region_block_cap"):
        w.add_memory_region(0, bytes(PAGE))


def test_source_page_states_length_mismatch(tmp_path):
    w = MslWriter(tmp_path / "m.msl")
    with pytest.raises(ValueError, match="page_states"):
        w.add_memory_region_source(0, 2 * PAGE, _source(bytes(PAGE)),
                                   page_states=[PageState.CAPTURED])


def test_in_memory_unsplit_region_unchanged_block_count(tmp_path):
    out = tmp_path / "one.msl"
    w = MslWriter(out)
    w.add_memory_region(0x1000, _pattern(4))
    w.write()
    with MslReader(out) as r:
        assert len(r.collect_regions()) == 1
        assert r.file_header.block_count == 1
        assert all(h.block_type == BlockType.MEMORY_REGION
                   for h in r._iter_raw_block_headers())
