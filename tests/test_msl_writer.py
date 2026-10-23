"""Tests for msl/writer.py — MSL file writer."""

import struct
import sys
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from memdiver.msl.compress import is_available as _codec_is_available
from memdiver.msl.enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, FILE_MAGIC, BlockType,
                       CompAlgo, EdgeKind, NodeKind)
from memdiver.msl.reader import MslReader
from memdiver.msl.types import (MslConnArpEntry, MslConnIfaceStats, MslConnIPv4Route,
                       MslConnIPv6Route, MslConnMibCounter,
                       MslConnPacketSocket, MslConnSocketFamilyAgg,
                       MslPointerGraphEdge, MslPointerGraphNode)
from memdiver.msl.hashing import hash_bytes
from memdiver.msl.writer import ExtensionBlock, MslWriter


@pytest.fixture
def sample_data():
    # MSL Specification v1.0.0 §5.1 requires RegionSize to be a multiple
    # of PageSize. Default page_size_log2=12 → page_size=4096, so we use
    # exactly one page of mixed bytes here.
    return (b"\xAA" * 32 + b"\xBB" * 32
            + bytes(range(256)) * 15
            + b"\x00" * (4096 - 32 - 32 - 256 * 15))


def test_write_minimal(tmp_path, sample_data):
    """Write one memory region, verify file starts with FILE_MAGIC."""
    out = tmp_path / "minimal.msl"
    w = MslWriter(out)
    w.add_memory_region(0, sample_data)
    w.write()
    assert out.exists()
    raw = out.read_bytes()
    assert raw[:8] == FILE_MAGIC


def test_roundtrip_reader(tmp_path, sample_data):
    """Write MSL, read back with MslReader, verify UUID and region count."""
    out = tmp_path / "roundtrip.msl"
    w = MslWriter(out, pid=42)
    w.add_memory_region(0x1000, sample_data)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        assert reader.file_header.dump_uuid == w.dump_uuid
        regions = reader.collect_regions()
        assert len(regions) == 1


def test_memory_region_data(tmp_path):
    """Write and read back region data, verify content matches."""
    data = b"\xDE\xAD" * 2048  # 4096 bytes = 1 page
    out = tmp_path / "region_data.msl"
    w = MslWriter(out)
    w.add_memory_region(0x7FFF00000000, data)
    w.write()

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        r = regions[0]
        assert r.base_addr == 0x7FFF00000000
        assert r.region_size == len(data)
        # Read back the page data from the mmap
        region_payload_offset = r.block_header.payload_offset
        # Data starts after fixed header (0x20) + page_state_map
        num_pages = r.num_pages
        psm_bytes = ((num_pages * 2 + 7) // 8 + 7) & ~7
        data_offset = region_payload_offset + 0x20 + psm_bytes
        read_data = reader.read_bytes(data_offset, len(data))
        assert read_data == data


def test_key_hint(tmp_path):
    """Write memory region + key hint, verify roundtrip."""
    data = b"\x00" * 4096
    out = tmp_path / "keyhint.msl"
    w = MslWriter(out)
    region_uuid = w.add_memory_region(0, data)
    w.add_key_hint(
        region_uuid=region_uuid,
        offset=64,
        key_length=32,
        key_type=0x0003,
        protocol=0x0002,
        confidence=0x02,
    )
    w.write()

    with MslReader(out) as reader:
        hints = reader.collect_key_hints()
        assert len(hints) == 1
        h = hints[0]
        assert h.region_uuid == region_uuid
        assert h.key_length == 32
        assert h.key_type == 0x0003
        assert h.protocol == 0x0002
        assert h.confidence == 0x02


def test_import_provenance(tmp_path):
    """Write with import provenance, verify it parses without error."""
    data = b"\xFF" * 4096
    out = tmp_path / "provenance.msl"
    w = MslWriter(out)
    w.add_memory_region(0, data)
    w.add_import_provenance(
        source_format=0x01,
        tool_name="memdiver",
        orig_file_size=len(data),
        note="test import",
    )
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        blocks = list(reader.iter_blocks())
        types = [h.block_type for h, _ in blocks]
        assert BlockType.IMPORT_PROVENANCE in types
        prov = reader.collect_import_provenance()
        assert len(prov) == 1
        assert prov[0].tool_name == "memdiver"
        assert prov[0].orig_file_size == len(data)


def test_block_chaining(tmp_path):
    """Write 3 blocks, verify second block has non-zero prev_hash."""
    out = tmp_path / "chaining.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_memory_region(0x1000, b"\x11" * 4096)
    w.add_memory_region(0x2000, b"\x22" * 4096)
    w.write()

    with MslReader(out) as reader:
        blocks = list(reader.iter_blocks())
        assert len(blocks) == 3
        # First block chains from the file header (spec §4.4)
        from memdiver.msl.hashing import hash_bytes
        assert blocks[0][0].prev_hash == hash_bytes(out.read_bytes()[:64])
        # Second block has non-zero prev_hash
        assert blocks[1][0].prev_hash != b"\x00" * 32


def test_dump_uuid(tmp_path):
    """Writer generates unique UUIDs across instances."""
    w1 = MslWriter(tmp_path / "a.msl")
    w2 = MslWriter(tmp_path / "b.msl")
    assert w1.dump_uuid != w2.dump_uuid
    assert isinstance(w1.dump_uuid, UUID)


def test_end_of_capture(tmp_path):
    """Write with end-of-capture, verify read-back works."""
    out = tmp_path / "eoc.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        eoc = reader.collect_end_of_capture()
        assert len(eoc) == 1
        assert eoc[0].acq_end_ns > 0
        # C1: file_hash is finalized over header + preceding blocks
        assert eoc[0].file_hash != b"\x00" * 32
        assert len(eoc[0].file_hash) == 32


def test_writer_add_related_dump_with_hash(tmp_path):
    """add_related_dump computes a non-zero target_hash when given a path."""
    target = tmp_path / "target.bin"
    target.write_bytes(b"target contents for hashing")

    src = tmp_path / "source.msl"
    writer = MslWriter(src, pid=1, imported=True)
    writer.add_related_dump(
        related_uuid=uuid4(),
        related_pid=42,
        relationship=1,
        target_path=target,
    )
    writer.add_end_of_capture()
    writer.write()

    with MslReader(src) as reader:
        rels = reader.collect_related_dumps()
        assert len(rels) == 1
        assert rels[0].target_hash != b"\x00" * 32
        assert len(rels[0].target_hash) == 32
        assert rels[0].related_pid == 42


def test_writer_import_provenance_with_source_hash(tmp_path):
    """add_import_provenance computes a non-zero source_hash from source_path."""
    src_file = tmp_path / "orig.bin"
    src_file.write_bytes(b"\xDE\xAD" * 100)

    out = tmp_path / "with_prov.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_import_provenance(
        source_format=0x01,
        tool_name="memdiver",
        orig_file_size=src_file.stat().st_size,
        note="hashed import",
        source_path=src_file,
    )
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        prov = reader.collect_import_provenance()
        assert len(prov) == 1
        assert prov[0].source_hash != b"\x00" * 32
        assert len(prov[0].source_hash) == 32
        assert prov[0].tool_name == "memdiver"
        assert prov[0].note == "hashed import"


def _make_target_msl(path: Path, pid: int = 100) -> UUID:
    w = MslWriter(path, pid=pid, imported=True)
    w.add_memory_region(0x7FFF0000, b"A" * 4096)
    w.add_end_of_capture()
    w.write()
    return w.dump_uuid


def test_xref_resolver_verify_success(tmp_path):
    """resolve(verify=True) sets hash_verified=True for an unmodified target."""
    from memdiver.msl.xref_resolver import XrefResolver

    target_msl = tmp_path / "target.msl"
    target_uuid = _make_target_msl(target_msl)

    source_msl = tmp_path / "source.msl"
    source_writer = MslWriter(source_msl, pid=200, imported=True)
    source_writer.add_related_dump(
        related_uuid=target_uuid,
        related_pid=100,
        relationship=1,
        target_path=target_msl,
    )
    source_writer.add_end_of_capture()
    source_writer.write()

    resolver = XrefResolver()
    resolver.index_file(source_msl)
    resolver.index_file(target_msl)
    entries = resolver.resolve(verify=True)
    assert len(entries) == 1
    assert entries[0].target_path == target_msl
    assert entries[0].hash_verified is True


def test_xref_resolver_verify_mismatch_detected(tmp_path):
    """Mutating the target file post-pinning yields hash_verified=False."""
    from memdiver.msl.xref_resolver import XrefResolver

    target_msl = tmp_path / "target.msl"
    target_uuid = _make_target_msl(target_msl)

    source_msl = tmp_path / "source.msl"
    source_writer = MslWriter(source_msl, pid=200, imported=True)
    source_writer.add_related_dump(
        related_uuid=target_uuid,
        related_pid=100,
        relationship=1,
        target_path=target_msl,
    )
    source_writer.add_end_of_capture()
    source_writer.write()

    # Mutate the target after the source has pinned its hash
    target_msl.write_bytes(target_msl.read_bytes() + b"\x00" * 16)

    resolver = XrefResolver()
    resolver.index_file(source_msl)
    resolver.index_file(target_msl)
    entries = resolver.resolve(verify=True)
    assert len(entries) == 1
    assert entries[0].hash_verified is False


# -- Connectivity Table writer (Tier 1 A.1) --


def _sample_connectivity_rows():
    """Return one of each ConnRowType variant; matches fixture defaults so
    byte-equality against tests/fixtures/generate_msl_fixtures.py is exact."""
    return [
        MslConnIPv4Route(
            iface="eth0",
            dest=b"\x00\x00\x00\x00",
            gateway=b"\xc0\xa8\x01\x01",
            mask=b"\x00\x00\x00\x00",
            flags=0x0003, metric=100, mtu=1500,
        ),
        MslConnIPv6Route(
            iface="eth0",
            dest=b"\x00" * 16,
            dest_prefix=0,
            next_hop=bytes.fromhex("fe80000000000000000000000000fffe"),
            metric=1, flags=0,
        ),
        MslConnArpEntry(
            family=0x02, ip=b"\xc0\xa8\x01\x05",
            hw_type=0x0001, flags=0x0002,
            hw_addr=b"\xde\xad\xbe\xef\x00\x01",
            iface="eth0",
        ),
        MslConnPacketSocket(
            pid=1234, inode=98765, proto=0x0003,
            iface_index=2, user=1000, mem=4096,
        ),
        MslConnIfaceStats(
            iface="eth0",
            rx_bytes=123456789, rx_pkts=1000, rx_err=0, rx_drop=2,
            tx_bytes=987654321, tx_pkts=900, tx_err=0, tx_drop=0,
        ),
        MslConnSocketFamilyAgg(
            family=0x02, in_use=12, alloc=20, mem=81920,
        ),
        MslConnMibCounter(
            mib="ip", counter="InReceives", value=500000,
        ),
    ]


def test_connectivity_table_roundtrip(tmp_path):
    """Write all 7 ConnRowType variants, read back, verify each field."""
    out = tmp_path / "connectivity.msl"
    rows = _sample_connectivity_rows()

    w = MslWriter(out)
    w.add_connectivity_table(rows)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        tables = reader.collect_connectivity_tables()
        assert len(tables) == 1
        table = tables[0]
        assert table.row_count == len(rows)
        assert len(table.rows) == len(rows)
        # Compare each row (dataclasses are frozen, so == checks all fields)
        for original, decoded in zip(rows, table.rows):
            assert type(original) is type(decoded)
            assert original == decoded


def test_connectivity_table_byte_equality_with_fixture(tmp_path):
    """Writer payload bytes match the synthetic fixture builder exactly.

    Pins encoder/decoder symmetry: the standalone fixture in
    tests/fixtures/generate_msl_fixtures.py is the reference encoder used
    by reader tests; the writer must produce the same wire bytes for the
    same logical rows so existing fixtures and new writer output are
    interchangeable.
    """
    from memdiver.msl.writer import _build_connectivity_table_payload

    # Reference: payload portion of the fixture builder's default block
    # (skip the 80-byte block header that _build_block prepends).
    from tests.fixtures.generate_msl_fixtures import _build_connectivity_table
    fixture_block, _ = _build_connectivity_table()
    fixture_payload = fixture_block[BLOCK_HEADER_SIZE:]

    # Writer payload from the same logical rows
    writer_payload = _build_connectivity_table_payload(
        _sample_connectivity_rows()
    )

    assert writer_payload == fixture_payload, (
        f"writer payload diverges from fixture builder:\n"
        f"  writer  len={len(writer_payload)} hex={writer_payload.hex()}\n"
        f"  fixture len={len(fixture_payload)} hex={fixture_payload.hex()}"
    )


def test_connectivity_table_empty(tmp_path):
    """Empty row list still produces a parseable block (row_count=0)."""
    out = tmp_path / "connectivity_empty.msl"
    w = MslWriter(out)
    w.add_connectivity_table([])
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        tables = reader.collect_connectivity_tables()
        assert len(tables) == 1
        assert tables[0].row_count == 0
        assert tables[0].rows == ()


def test_connectivity_table_unsupported_row_raises(tmp_path):
    """Non-ConnectivityRow inputs raise ValueError before any bytes are written."""
    out = tmp_path / "connectivity_bad.msl"
    w = MslWriter(out)
    with pytest.raises(ValueError, match="Unsupported connectivity row"):
        w.add_connectivity_table([("not", "a", "dataclass")])


# -- Per-block compression writer (Tier 1 A.2) --


def test_encode_comp_flags_matches_reader_decode_rule():
    """Writer's flag-encoding rule must match the reader's bit unpacking
    (msl/types.py:85-87). Pins the contract that lets the reader decide
    whether and how to decompress on read."""
    from memdiver.msl.enums import BlockFlag
    from memdiver.msl.writer import _encode_comp_flags

    # NONE => no bits set; reader sees compressed=False
    assert _encode_comp_flags(CompAlgo.NONE) == 0

    # ZSTD => bit 0 (COMPRESSED) + algo=1 packed in bits 1-2 => 0b011
    z = _encode_comp_flags(CompAlgo.ZSTD)
    assert z & BlockFlag.COMPRESSED
    assert ((z >> 1) & 0x03) == int(CompAlgo.ZSTD)

    # LZ4 => bit 0 + algo=2 packed in bits 1-2 => 0b101
    l = _encode_comp_flags(CompAlgo.LZ4)
    assert l & BlockFlag.COMPRESSED
    assert ((l >> 1) & 0x03) == int(CompAlgo.LZ4)


@pytest.mark.parametrize("algo", [CompAlgo.ZSTD, CompAlgo.LZ4],
                         ids=["ZSTD", "LZ4"])
def test_memory_region_compressed_roundtrip(tmp_path, algo):
    """Writer compresses the payload; reader transparently decompresses."""
    if not _codec_is_available(algo):
        pytest.skip(f"{algo.name} library not installed")

    data = (b"X" * 2048 + b"Y" * 2048)  # highly compressible, 1 page
    out = tmp_path / f"compressed_{algo.name.lower()}.msl"
    w = MslWriter(out)
    w.add_memory_region(0x4000, data, compression=algo)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        r = regions[0]
        # Reader sees the block flag bits — verifies our writer-side encoding
        assert r.block_header.compressed is True
        assert r.block_header.comp_algo == algo
        # Logical metadata survives the round-trip
        assert r.base_addr == 0x4000
        assert r.region_size == len(data)
        # Compressed payload is genuinely smaller than the plaintext block
        on_disk_payload_len = r.block_header.payload_length
        plaintext_payload_len = 0x20 + 8 + len(data)  # fixed hdr + psm + data
        assert on_disk_payload_len < plaintext_payload_len


@pytest.mark.skipif(
    not _codec_is_available(CompAlgo.ZSTD),
    reason="zstandard not installed",
)
def test_compressed_block_integrity_chain(tmp_path):
    """BLAKE3 prev_hash chain validates over the on-disk (compressed) bytes."""
    from memdiver.msl.integrity import verify_chain

    out = tmp_path / "compressed_chain.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\xAA" * 4096, compression=CompAlgo.ZSTD)
    w.add_memory_region(0x1000, b"\xBB" * 4096, compression=CompAlgo.ZSTD)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        report = verify_chain(reader)
        assert report.valid, f"integrity chain failed: {report.errors}"
        assert report.broken_at is None


def test_memory_region_uncompressed_default_unchanged(tmp_path):
    """Callers that don't pass compression= emit COMPRESSED=0 and
    comp_algo=NONE, so existing readers see uncompressed blocks exactly
    as before A.2."""
    out = tmp_path / "uncompressed_default.msl"
    w = MslWriter(out)
    w.add_memory_region(0x2000, b"\xCC" * 4096)
    w.write()

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        assert regions[0].block_header.compressed is False
        assert regions[0].block_header.comp_algo is CompAlgo.NONE


@pytest.mark.skipif(
    not _codec_is_available(CompAlgo.ZSTD),
    reason="zstandard not installed",
)
def test_compress_unavailable_codec_raises(tmp_path, monkeypatch):
    """Asking for a codec whose library is missing raises a clean error
    before any bytes hit disk."""
    import builtins
    from memdiver.msl.types import MslParseError

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "zstandard":
            raise ImportError("simulated missing zstandard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    out = tmp_path / "missing_codec.msl"
    w = MslWriter(out)
    with pytest.raises(MslParseError, match="zstandard"):
        w.add_memory_region(0, b"\x00" * 4096, compression=CompAlgo.ZSTD)
    assert not out.exists()


# -- POINTER_GRAPH in an extension segment (spec 4.6) --


def _sample_pointer_graph():
    """A small graph exercising every node-kind and edge-kind, including
    a node with an empty label and an edge with empty metadata so the
    zero-length string path is tested."""
    nodes = [
        MslPointerGraphNode(
            node_kind=NodeKind.ADDRESS, value=0x7FFF1000, label="main",
        ),
        MslPointerGraphNode(
            node_kind=NodeKind.OFFSET, value=0x200, label="",
        ),
        MslPointerGraphNode(
            node_kind=NodeKind.SYMBOL, value=0xDEAD,
            label="libc.so.6:malloc",
        ),
    ]
    edges = [
        MslPointerGraphEdge(
            src_idx=0, dst_idx=1,
            edge_kind=EdgeKind.POINTER, metadata="heap",
        ),
        MslPointerGraphEdge(
            src_idx=0, dst_idx=2,
            edge_kind=EdgeKind.CALL, metadata="",
        ),
        MslPointerGraphEdge(
            src_idx=1, dst_idx=2,
            edge_kind=EdgeKind.IMPORT, metadata="weak",
        ),
    ]
    return nodes, edges


def _eoc_block_bytes(reader: MslReader) -> bytes:
    """Raw bytes of the End-of-Capture block (last capture-segment header)."""
    eoc = list(reader._iter_raw_block_headers())[-1]
    assert eoc.block_type == BlockType.END_OF_CAPTURE
    return reader.read_bytes(eoc.file_offset, eoc.block_length)


def _write_pointer_graph_file(path: Path, *, with_region: bool = True,
                              emit_integrity: bool = True, producer=None):
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(path)
    if with_region:
        w.add_memory_region(0x1000, b"\xAA" * 4096)
    pg_uuid = w.add_pointer_graph(nodes, edges, emit_integrity=emit_integrity,
                                  producer=producer)
    w.add_end_of_capture()
    w.write()
    return nodes, edges, pg_uuid


def test_pointer_graph_segment_roundtrip(tmp_path):
    """Writer emits POINTER_GRAPH in a segment after EoC; reader recovers it."""
    out = tmp_path / "with_pg.msl"
    nodes, edges, pg_uuid = _write_pointer_graph_file(out)

    with MslReader(out) as reader:
        graphs = reader.collect_pointer_graphs()
        assert len(graphs) == 1
        graph = graphs[0]
        assert graph.block_header.block_type == BlockType.POINTER_GRAPH
        assert graph.block_header.block_uuid == pg_uuid
        # Spec 4.6: the first extension block chains from H(EoC block bytes).
        assert graph.block_header.prev_hash == hash_bytes(_eoc_block_bytes(reader))
        assert tuple(graph.nodes) == tuple(nodes)
        assert tuple(graph.edges) == tuple(edges)
        # Default emit_integrity=True -> appendix_hash present and verifiable
        assert graph.appendix_hash is not None
        assert len(graph.appendix_hash) == 32


def test_pointer_graph_segment_is_verified_with_memdiver_producer(tmp_path):
    """The writer's own segment verifies and names memdiver as producer."""
    from memdiver.msl.integrity import verify_chain

    out = tmp_path / "pg_verified.msl"
    _write_pointer_graph_file(out)
    with MslReader(out) as reader:
        report = verify_chain(reader)
        assert report.valid, report.errors
        assert len(report.segments) == 1
        seg = report.segments[0]
        assert seg.verified, seg.errors
        assert seg.producer.startswith("memdiver/")
        assert seg.block_count == 2  # POINTER_GRAPH + End-of-Extension
        terminators = reader.collect_end_of_extension()
        assert len(terminators) == 1
        assert terminators[0].block_count == 2
        assert terminators[0].producer == seg.producer


def test_pointer_graph_segment_custom_producer(tmp_path):
    out = tmp_path / "pg_producer.msl"
    _write_pointer_graph_file(out, producer="acme-tool/9.9")
    with MslReader(out) as reader:
        assert reader.scan_extension_segments()[0].producer == "acme-tool/9.9"
        assert reader.collect_end_of_extension()[0].producer == "acme-tool/9.9"


def test_pointer_graph_segment_integrity_verification(tmp_path):
    """The stored BLAKE3 trailer matches a fresh hash over header+nodes+edges."""
    from memdiver.msl.decoders_ext import verify_pointer_graph_integrity

    out = tmp_path / "pg_integrity.msl"
    _write_pointer_graph_file(out, with_region=False, emit_integrity=True)

    with MslReader(out) as reader:
        graph = reader.collect_pointer_graphs()[0]
        # Re-read raw payload from disk for the verifier
        raw_payload = reader.read_block_payload(graph.block_header)
        assert verify_pointer_graph_integrity(graph, raw_payload) is True


def test_pointer_graph_segment_no_integrity_trailer(tmp_path):
    """emit_integrity=False produces no trailer; appendix_hash is None."""
    out = tmp_path / "pg_no_integrity.msl"
    nodes, _, _ = _write_pointer_graph_file(out, with_region=False,
                                            emit_integrity=False)

    with MslReader(out) as reader:
        graph = reader.collect_pointer_graphs()[0]
        assert graph.appendix_hash is None
        assert tuple(graph.nodes) == tuple(nodes)


def test_pointer_graph_segment_not_counted_in_capture(tmp_path):
    """verify_chain counts capture blocks only; the segment is verified apart."""
    from memdiver.msl.integrity import verify_chain

    out = tmp_path / "pg_chain_isolated.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_memory_region(0, b"\xBB" * 4096)
    w.add_pointer_graph(nodes, edges)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        report = verify_chain(reader)
        assert report.valid, f"chain invalid: {report.errors}"
        assert report.broken_at is None
        # MEMORY_REGION + EoC == 2 capture blocks (segment blocks NOT counted)
        assert report.block_count == 2
        assert reader.file_header.block_count == 2
        assert reader.collect_end_of_capture()[0].block_count == 2
        assert report.header_block_count == 2
        assert report.eoc_block_count == 2
        assert report.block_count_ok
        assert report.file_hash_ok is True
        assert report.segments[0].verified
        assert report.trailing_bytes == 0


def test_pointer_graph_segment_absent(tmp_path):
    """Files without a segment yield an empty pointer-graph list."""
    out = tmp_path / "no_pg.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        assert reader.collect_pointer_graphs() == []
        assert reader.scan_extension_segments() == []


def test_pointer_graph_iter_blocks_stops_at_eoc(tmp_path):
    """iter_blocks should not return the segment — the capture ends at EoC.

    Pins backward compatibility: existing collectors (regions, key hints,
    etc.) that iterate via iter_blocks must NOT see the POINTER_GRAPH
    bytes, so any reader code written before the extension landed is
    unaffected.
    """
    out = tmp_path / "iter_test.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_memory_region(0, b"\xCC" * 4096)
    w.add_pointer_graph(nodes, edges)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        block_types = [h.block_type for h, _ in reader.iter_blocks()]
        assert BlockType.POINTER_GRAPH not in block_types
        assert BlockType.MEMORY_REGION in block_types
        assert BlockType.END_OF_CAPTURE in block_types
        ext_types = [h.block_type for h, _ in reader.iter_extension_blocks()]
        assert ext_types == [BlockType.POINTER_GRAPH, BlockType.END_OF_EXTENSION]


def test_pointer_graph_replacing_call_overwrites(tmp_path):
    """Calling add_pointer_graph twice keeps only the latest registration
    and still emits a single segment."""
    out = tmp_path / "pg_replace.msl"
    nodes_a, edges_a = _sample_pointer_graph()
    nodes_b = [MslPointerGraphNode(
        node_kind=NodeKind.ADDRESS, value=0xCAFE, label="overridden",
    )]
    edges_b = []

    w = MslWriter(out)
    w.add_pointer_graph(nodes_a, edges_a)
    w.add_pointer_graph(nodes_b, edges_b)
    assert w.extension_segment_count == 1
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        assert len(reader.scan_extension_segments()) == 1
        graphs = reader.collect_pointer_graphs()
        assert len(graphs) == 1
        assert tuple(graphs[0].nodes) == tuple(nodes_b)
        assert graphs[0].edges == ()


def test_pointer_graph_tampered_trailer_detected(tmp_path):
    """Flipping a byte of the graph payload breaks the segment: verify_chain
    marks it unverified, the collector hides it, the unverified walk still
    yields it and the self-integrity trailer no longer matches."""
    from memdiver.msl.decoders_ext import (decode_pointer_graph,
                                           verify_pointer_graph_integrity)
    from memdiver.msl.integrity import verify_chain

    out = tmp_path / "pg_tampered.msl"
    _write_pointer_graph_file(out, with_region=False, emit_integrity=True)

    with MslReader(out) as reader:
        pg_hdr = reader.scan_extension_segments()[0].headers[0]
        assert pg_hdr.block_type == BlockType.POINTER_GRAPH
        # Last byte of the trailer (32-byte BLAKE3 at the end of the payload).
        tamper_at = pg_hdr.payload_offset + pg_hdr.payload_length - 1

    data = bytearray(out.read_bytes())
    data[tamper_at] ^= 0xFF
    out.write_bytes(bytes(data))

    with MslReader(out) as reader:
        report = verify_chain(reader)
        assert report.capture_ok
        assert not report.valid
        assert not report.segments[0].verified
        assert not report.segments[0].segment_hash_ok
        assert any("segment 0" in e for e in report.errors)
        assert reader.collect_pointer_graphs() == []
        unverified = [(h, p) for h, p in reader.iter_extension_blocks(include_unverified=True)
                      if h.block_type == BlockType.POINTER_GRAPH]
        assert len(unverified) == 1
        hdr, raw_payload = unverified[0]
        graph = decode_pointer_graph(hdr, raw_payload, reader._byte_order)
        assert verify_pointer_graph_integrity(graph, raw_payload) is False


# -- add_extension_segment (spec 4.6) --


def test_add_extension_segment_rejects_forbidden_type(tmp_path):
    w = MslWriter(tmp_path / "x.msl")
    with pytest.raises(ValueError, match="0x0001"):
        w.add_extension_segment("t", [ExtensionBlock(0x0001, b"\x00" * 8)])
    with pytest.raises(ValueError, match="0x0FFF"):
        w.add_extension_segment("t", [ExtensionBlock(BlockType.END_OF_CAPTURE, b"")])
    with pytest.raises(ValueError, match="0x0FFE"):
        w.add_extension_segment("t", [ExtensionBlock(BlockType.END_OF_EXTENSION, b"")])
    assert w.extension_segment_count == 0


def test_add_extension_segment_rejects_empty_block_list(tmp_path):
    w = MslWriter(tmp_path / "x.msl")
    with pytest.raises(ValueError, match="at least one block"):
        w.add_extension_segment("t", [])
    assert w.extension_segment_count == 0


def test_extension_segment_without_eoc_fails_at_write(tmp_path):
    out = tmp_path / "no_eoc.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_extension_segment("t", [ExtensionBlock(0x1100, b"\x01" * 8)])
    with pytest.raises(ValueError, match="End-of-Capture"):
        w.write()
    assert not out.exists()


def test_two_extension_segments_chained_in_order(tmp_path):
    """Pointer graph + a custom 0x1100 segment both verify, in file order,
    with the PrevHash chain running EoC -> seg0 -> seg1."""
    from memdiver.msl.integrity import verify_chain

    out = tmp_path / "two_segments.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_memory_region(0, b"\x11" * 4096)
    w.add_pointer_graph(nodes, edges)
    custom_uuid = uuid4()
    idx = w.add_extension_segment(
        "custom-tool/1.0",
        [ExtensionBlock(0x1100, b"\x42" * 16, block_uuid=custom_uuid)])
    assert idx == 1 and w.extension_segment_count == 2
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        report = verify_chain(reader)
        assert report.valid, report.errors
        assert report.block_count == 2
        assert [s.verified for s in report.segments] == [True, True]
        assert [s.producer for s in report.segments][1] == "custom-tool/1.0"
        assert report.segments[0].producer.startswith("memdiver/")
        assert report.trailing_bytes == 0
        segments = reader.scan_extension_segments()
        assert segments[0].end == segments[1].start
        types = [h.block_type for h, _ in reader.iter_extension_blocks()]
        assert types == [BlockType.POINTER_GRAPH, BlockType.END_OF_EXTENSION,
                         0x1100, BlockType.END_OF_EXTENSION]
        # Chain continuity across the segment boundary.
        prev = hash_bytes(_eoc_block_bytes(reader))
        for seg in segments:
            for hdr in seg.headers:
                assert hdr.prev_hash == prev
                prev = hash_bytes(reader.read_bytes(hdr.file_offset, hdr.block_length))
        assert segments[1].headers[0].block_uuid == custom_uuid
        assert len(reader.collect_pointer_graphs()) == 1


def test_add_raw_appendix_removed(tmp_path):
    w = MslWriter(tmp_path / "x.msl")
    with pytest.raises(NotImplementedError, match="add_extension_segment"):
        w.add_raw_appendix(b"\x00" * 80)


def test_extension_bytes_identical_across_writes(tmp_path):
    """Writing the same writer twice (fixed timestamp) yields identical
    extension bytes: WrittenAt and the terminator UUID are fixed per writer."""
    out = tmp_path / "twice.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out, timestamp_ns=1_700_000_000_000_000_000)
    w.add_memory_region(0, b"\x22" * 4096)
    w.add_pointer_graph(nodes, edges)
    w.add_extension_segment("t", [ExtensionBlock(0x1100, b"\x07" * 8)])
    w.add_end_of_capture(acq_end_ns=5)

    def _extension_bytes() -> bytes:
        w.write()
        with MslReader(out) as reader:
            start = reader._extension_start()
            assert start is not None
            return reader.read_bytes(start, reader.buffer_length - start)

    first = _extension_bytes()
    second = _extension_bytes()
    assert first and first == second


# --- atomic write (temp + os.replace) ---

def test_atomic_output_preserves_existing_file_on_failure(tmp_path):
    """A mid-write failure must not corrupt/truncate the destination or clobber
    a previously-good file, and must leave no stray temp behind."""
    from memdiver.msl.writer import MslWriter

    dest = tmp_path / "out.msl"
    dest.write_bytes(b"GOOD-EXISTING")
    w = MslWriter(dest)

    with pytest.raises(RuntimeError, match="boom"):
        with w._atomic_output() as f:
            f.write(b"PARTIAL")
            raise RuntimeError("boom")

    assert dest.read_bytes() == b"GOOD-EXISTING"  # untouched
    assert list(tmp_path.glob("*.tmp")) == []  # temp cleaned up


def test_atomic_output_commits_on_success(tmp_path):
    """A clean write atomically replaces the destination and leaves no temp."""
    from memdiver.msl.writer import MslWriter

    dest = tmp_path / "out.msl"
    w = MslWriter(dest)
    with w._atomic_output() as f:
        f.write(b"NEW-CONTENT")

    assert dest.read_bytes() == b"NEW-CONTENT"
    assert list(tmp_path.glob("*.tmp")) == []
