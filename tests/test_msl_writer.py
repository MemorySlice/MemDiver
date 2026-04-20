"""Tests for msl/writer.py — MSL file writer."""

import struct
import sys
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from msl.enums import BLOCK_HEADER_SIZE, BLOCK_MAGIC, FILE_MAGIC, BlockType
from msl.reader import MslReader
from msl.writer import MslWriter


@pytest.fixture
def sample_data():
    return b"\xAA" * 32 + b"\xBB" * 32 + bytes(range(256)) * 15


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
