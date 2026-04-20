"""Tests for msl/reader.py — MSL file parser."""

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from msl.enums import BlockType, Endianness, FILE_MAGIC
from msl.reader import MslReader
from msl.types import MslEncryptedError, MslParseError
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def msl_path(tmp_path):
    """Write a synthetic MSL file and return its path."""
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


def test_read_file_header(msl_path):
    with MslReader(msl_path) as reader:
        hdr = reader.file_header
        assert hdr.endianness == Endianness.LITTLE
        assert hdr.version_major == 1
        assert hdr.version_minor == 1
        assert hdr.header_size == 64
        assert hdr.pid == 1234
        assert hdr.os_type == 1  # Linux
        assert hdr.arch_type == 1  # x86_64
        assert not hdr.encrypted
        assert not hdr.imported


def test_iter_blocks(msl_path):
    with MslReader(msl_path) as reader:
        blocks = list(reader.iter_blocks())
        # 7 original blocks + 11 new (MSL-Decoders-02: 4 spec-defined table
        # blocks + Connectivity Table (0x0055) + 6 ext decoder blocks with
        # speculative layouts)
        assert len(blocks) == 18
        types = [h.block_type for h, _ in blocks]
        # Original 7
        assert BlockType.PROCESS_IDENTITY in types
        assert BlockType.MEMORY_REGION in types
        assert BlockType.MODULE_ENTRY in types
        assert BlockType.KEY_HINT in types
        assert BlockType.RELATED_DUMP in types
        assert BlockType.VAS_MAP in types
        assert BlockType.END_OF_CAPTURE in types
        # New spec-defined table blocks
        assert BlockType.MODULE_LIST_INDEX in types
        assert BlockType.PROCESS_TABLE in types
        assert BlockType.CONNECTION_TABLE in types
        assert BlockType.HANDLE_TABLE in types
        # New ext blocks (speculative layouts)
        assert BlockType.THREAD_CONTEXT in types
        assert BlockType.FILE_DESCRIPTOR in types
        assert BlockType.NETWORK_CONNECTION in types
        assert BlockType.ENVIRONMENT_BLOCK in types
        assert BlockType.SECURITY_TOKEN in types
        assert BlockType.SYSTEM_CONTEXT in types


def test_collect_regions(msl_path):
    with MslReader(msl_path) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        r = regions[0]
        assert r.base_addr == 0x7FFF00000000
        assert r.region_size == 4096
        assert r.page_size == 4096
        assert r.num_pages == 1


def test_collect_key_hints(msl_path):
    with MslReader(msl_path) as reader:
        hints = reader.collect_key_hints()
        assert len(hints) == 1
        h = hints[0]
        assert h.key_length == 32
        assert h.key_type == 3  # SESSION_KEY
        assert h.protocol == 2  # TLS_13
        assert h.confidence == 2  # CONFIRMED
        assert h.key_state == 1  # ACTIVE
        assert h.note == "test_key"


def test_collect_modules(msl_path):
    with MslReader(msl_path) as reader:
        modules = reader.collect_modules()
        assert len(modules) == 1
        assert modules[0].path == "/usr/lib/libssl.so"


def test_block_uuids_unique(msl_path):
    with MslReader(msl_path) as reader:
        blocks = list(reader.iter_blocks())
        uuids = [h.block_uuid for h, _ in blocks]
        assert len(set(uuids)) == len(uuids)


def test_bad_magic_raises(tmp_path):
    p = tmp_path / "bad.msl"
    p.write_bytes(b"NOTMAGIC" + b"\x00" * 56)
    with pytest.raises(MslParseError, match="Bad magic"):
        MslReader(p).open()


def test_encrypted_raises(tmp_path):
    data = bytearray(generate_msl_file())
    # Set Encrypted flag (bit 2) in Flags at offset 0x0C
    flags = struct.unpack_from("<I", data, 0x0C)[0]
    flags |= 0x04  # ENCRYPTED
    struct.pack_into("<I", data, 0x0C, flags)
    # Set HeaderSize to 128
    data[9] = 128
    p = tmp_path / "encrypted.msl"
    p.write_bytes(bytes(data))
    with pytest.raises(MslEncryptedError, match="Encrypted"):
        MslReader(p).open()


def test_too_small_raises(tmp_path):
    p = tmp_path / "tiny.msl"
    p.write_bytes(b"\x00" * 10)
    with pytest.raises(MslParseError, match="too small"):
        MslReader(p).open()


def test_key_hint_references_region(msl_path):
    """Key Hint's region_uuid should match the Memory Region's block_uuid."""
    with MslReader(msl_path) as reader:
        regions = reader.collect_regions()
        hints = reader.collect_key_hints()
        region_uuid = regions[0].block_header.block_uuid
        assert hints[0].region_uuid == region_uuid


# -- Compressed block tests --

try:
    import zstandard  # noqa: F401
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import lz4.frame  # noqa: F401
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


@pytest.mark.skipif(not HAS_ZSTD, reason="zstandard not installed")
def test_iter_blocks_compressed_zstd(tmp_path):
    """Compressed zstd block is transparently decompressed."""
    from tests.fixtures.generate_msl_fixtures import write_compressed_msl_fixture
    msl_path = tmp_path / "compressed_zstd.msl"
    write_compressed_msl_fixture(msl_path, algo="zstd")
    with MslReader(msl_path) as reader:
        regions = reader.collect_regions()
        assert len(regions) >= 1
        region = regions[0]
        assert region.base_addr > 0
        assert region.region_size > 0


@pytest.mark.skipif(not HAS_LZ4, reason="lz4 not installed")
def test_iter_blocks_compressed_lz4(tmp_path):
    """Compressed lz4 block is transparently decompressed."""
    from tests.fixtures.generate_msl_fixtures import write_compressed_msl_fixture
    msl_path = tmp_path / "compressed_lz4.msl"
    write_compressed_msl_fixture(msl_path, algo="lz4")
    with MslReader(msl_path) as reader:
        regions = reader.collect_regions()
        assert len(regions) >= 1
        region = regions[0]
        assert region.base_addr > 0
