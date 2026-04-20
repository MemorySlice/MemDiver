"""Tests for msl/types.py — MSL dataclasses."""

import sys
from pathlib import Path
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.enums import BlockType, Endianness, HeaderFlag, PageState
from msl.types import (
    MslBlockHeader,
    MslEncryptedError,
    MslFileHeader,
    MslKeyHint,
    MslMemoryRegion,
    MslParseError,
)


def _make_file_header(**overrides):
    defaults = dict(
        endianness=Endianness.LITTLE, header_size=64,
        version_major=1, version_minor=1, flags=0,
        cap_bitmap=0, dump_uuid=uuid4(), timestamp_ns=0,
        os_type=1, arch_type=1, pid=1234, clock_source=0,
    )
    defaults.update(overrides)
    return MslFileHeader(**defaults)


def _make_block_header(**overrides):
    defaults = dict(
        block_type=BlockType.MEMORY_REGION, flags=0,
        block_length=160, payload_version=1,
        block_uuid=uuid4(), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32, file_offset=64, payload_offset=144,
    )
    defaults.update(overrides)
    return MslBlockHeader(**defaults)


def test_file_header_properties():
    hdr = _make_file_header(flags=0)
    assert not hdr.imported
    assert not hdr.investigation
    assert not hdr.encrypted


def test_file_header_imported():
    hdr = _make_file_header(flags=HeaderFlag.IMPORTED)
    assert hdr.imported
    assert not hdr.investigation


def test_file_header_encrypted():
    hdr = _make_file_header(flags=HeaderFlag.ENCRYPTED)
    assert hdr.encrypted


def test_file_header_frozen():
    hdr = _make_file_header()
    try:
        hdr.pid = 999
        assert False, "Should raise"
    except AttributeError:
        pass  # frozen dataclass


def test_block_header_payload_length():
    hdr = _make_block_header(block_length=160)
    assert hdr.payload_length == 80  # 160 - 80


def test_block_header_not_compressed():
    hdr = _make_block_header(flags=0)
    assert not hdr.compressed


def test_memory_region_page_size():
    bh = _make_block_header()
    region = MslMemoryRegion(
        block_header=bh, base_addr=0x1000, region_size=8192,
        protection=7, region_type=1, page_size_log2=12,
        timestamp_ns=0, page_states=[PageState.CAPTURED, PageState.CAPTURED],
    )
    assert region.page_size == 4096
    assert region.num_pages == 2


def test_key_hint_defaults():
    bh = _make_block_header(block_type=BlockType.KEY_HINT)
    hint = MslKeyHint(
        block_header=bh, region_uuid=uuid4(),
        region_offset=0, key_length=32,
        key_type=3, protocol=2, confidence=2, key_state=1,
    )
    assert hint.note == ""
    assert hint.key_length == 32


def test_exceptions():
    assert issubclass(MslEncryptedError, ValueError)
    assert issubclass(MslParseError, ValueError)
