"""Tests for msl/writer.py — MSL file writer."""

import struct
import sys
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from msl.compress import is_available as _codec_is_available
from msl.enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, FILE_MAGIC, BlockType,
                       CompAlgo, EdgeKind, NodeKind)
from msl.reader import MslReader
from msl.types import (MslConnArpEntry, MslConnIfaceStats, MslConnIPv4Route,
                       MslConnIPv6Route, MslConnMibCounter,
                       MslConnPacketSocket, MslConnSocketFamilyAgg,
                       MslPointerGraphEdge, MslPointerGraphNode)
from msl.writer import MslWriter


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
        # First block has zero prev_hash
        assert blocks[0][0].prev_hash == b"\x00" * 32
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
    from msl.xref_resolver import XrefResolver

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
    from msl.xref_resolver import XrefResolver

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
    from msl.writer import _build_connectivity_table_payload

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
    from msl.enums import BlockFlag
    from msl.writer import _encode_comp_flags

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
    from msl.integrity import verify_chain

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
    from msl.types import MslParseError

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "zstandard":
            raise ImportError("simulated missing zstandard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    out = tmp_path / "missing_codec.msl"
    w = MslWriter(out)
    with pytest.raises(MslParseError, match="zstandard not installed"):
        w.add_memory_region(0, b"\x00" * 4096, compression=CompAlgo.ZSTD)
    assert not out.exists()


# -- POINTER_GRAPH appendix (Tier 1 Phase B) --


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


def test_pointer_graph_appendix_roundtrip(tmp_path):
    """Writer emits POINTER_GRAPH after EoC; reader recovers exact data."""
    out = tmp_path / "with_pg.msl"
    nodes, edges = _sample_pointer_graph()

    w = MslWriter(out)
    w.add_memory_region(0x1000, b"\xAA" * 4096)
    pg_uuid = w.add_pointer_graph(nodes, edges)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        graphs = reader.collect_pointer_graphs()
        assert len(graphs) == 1
        graph = graphs[0]
        assert graph.block_header.block_type == BlockType.POINTER_GRAPH
        assert graph.block_header.block_uuid == pg_uuid
        # Appendix lives outside the chain — prev_hash MUST be zero
        assert graph.block_header.prev_hash == b"\x00" * 32
        assert tuple(graph.nodes) == tuple(nodes)
        assert tuple(graph.edges) == tuple(edges)
        # Default emit_integrity=True → appendix_hash present and verifiable
        assert graph.appendix_hash is not None
        assert len(graph.appendix_hash) == 32


def test_pointer_graph_appendix_integrity_verification(tmp_path):
    """The stored BLAKE3 trailer matches a fresh hash over header+nodes+edges."""
    from msl.decoders_ext import verify_pointer_graph_integrity

    out = tmp_path / "pg_integrity.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_pointer_graph(nodes, edges, emit_integrity=True)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        graph = reader.collect_pointer_graphs()[0]
        # Re-read raw payload from disk for the verifier
        raw_payload = reader.read_block_payload(graph.block_header)
        assert verify_pointer_graph_integrity(graph, raw_payload) is True


def test_pointer_graph_appendix_no_integrity_trailer(tmp_path):
    """emit_integrity=False produces no trailer; appendix_hash is None."""
    out = tmp_path / "pg_no_integrity.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_pointer_graph(nodes, edges, emit_integrity=False)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        graph = reader.collect_pointer_graphs()[0]
        assert graph.appendix_hash is None
        assert tuple(graph.nodes) == tuple(nodes)


def test_pointer_graph_appendix_outside_chain(tmp_path):
    """verify_chain stops at EoC; appendix doesn't poison integrity."""
    from msl.integrity import verify_chain

    out = tmp_path / "pg_chain_isolated.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_memory_region(0, b"\xBB" * 4096)
    w.add_pointer_graph(nodes, edges)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        report = verify_chain(reader)
        # Chain valid for in-chain blocks; appendix is excluded
        assert report.valid, f"chain invalid: {report.errors}"
        assert report.broken_at is None
        # MEMORY_REGION + EoC == 2 in-chain blocks (the appendix is NOT counted)
        assert report.block_count == 2


def test_pointer_graph_appendix_absent(tmp_path):
    """Files without an appendix yield an empty pointer-graph list."""
    out = tmp_path / "no_pg.msl"
    w = MslWriter(out)
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        assert reader.collect_pointer_graphs() == []


def test_pointer_graph_iter_blocks_stops_at_eoc(tmp_path):
    """iter_blocks should not return the appendix — chain ends at EoC.

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


def test_pointer_graph_replacing_call_overwrites(tmp_path):
    """Calling add_pointer_graph twice keeps only the latest registration."""
    out = tmp_path / "pg_replace.msl"
    nodes_a, edges_a = _sample_pointer_graph()
    nodes_b = [MslPointerGraphNode(
        node_kind=NodeKind.ADDRESS, value=0xCAFE, label="overridden",
    )]
    edges_b = []

    w = MslWriter(out)
    w.add_pointer_graph(nodes_a, edges_a)
    w.add_pointer_graph(nodes_b, edges_b)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as reader:
        graphs = reader.collect_pointer_graphs()
        assert len(graphs) == 1
        assert tuple(graphs[0].nodes) == tuple(nodes_b)
        assert graphs[0].edges == ()


def test_pointer_graph_tampered_trailer_detected(tmp_path):
    """Flipping a byte in the appendix trailer makes verifier return False."""
    from msl.decoders_ext import verify_pointer_graph_integrity

    out = tmp_path / "pg_tampered.msl"
    nodes, edges = _sample_pointer_graph()
    w = MslWriter(out)
    w.add_pointer_graph(nodes, edges, emit_integrity=True)
    w.add_end_of_capture()
    w.write()

    # Corrupt one byte of the appendix payload AFTER write
    data = bytearray(out.read_bytes())
    data[-1] ^= 0xFF
    out.write_bytes(bytes(data))

    with MslReader(out) as reader:
        graph = reader.collect_pointer_graphs()[0]
        raw_payload = reader.read_block_payload(graph.block_header)
        assert verify_pointer_graph_integrity(graph, raw_payload) is False
