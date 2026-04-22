"""Tests for the hand-rolled MSL Kaitai parser (``core.binary_formats.kaitai_compiled.msl``)."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.binary_formats.kaitai_registry import (
    get_kaitai_registry,
    kaitai_available,
)


pytestmark = pytest.mark.skipif(
    not kaitai_available(),
    reason="kaitaistruct runtime not installed",
)


def _build_file_header(flags: int = 0) -> bytes:
    """Build a synthetic 64-byte MSL file header."""
    version = (1 << 8) | 1  # v1.1
    cap_bitmap = 0
    dump_uuid = b"\x11" * 16
    timestamp_ns = 0
    os_type = 0x0001
    arch_type = 0x0001
    pid = 1234
    clock_source = 0
    hdr = struct.pack(
        "<8sBBHIQ16sQHHIB7x",
        b"MEMSLICE", 0x01, 64, version, flags,
        cap_bitmap, dump_uuid, timestamp_ns,
        os_type, arch_type, pid, clock_source,
    )
    assert len(hdr) == 64
    return hdr


def _build_block(block_type: int = 0x0001, payload: bytes = b"") -> bytes:
    """Build a synthetic 80-byte MSLC block header + payload."""
    block_length = 80 + len(payload)
    block_uuid = b"\x22" * 16
    parent_uuid = b"\x00" * 16
    prev_hash = b"\x00" * 32
    hdr = struct.pack(
        "<4sHHIH2x16s16s32s",
        b"MSLC", block_type, 0, block_length, 1,
        block_uuid, parent_uuid, prev_hash,
    )
    assert len(hdr) == 80
    return hdr + payload


def test_parses_synthetic_msl():
    buf = _build_file_header() + _build_block(0x0001, b"")
    registry = get_kaitai_registry()
    parsed = registry.parse("msl", buf)
    assert parsed is not None
    assert parsed.file_header.magic == b"MEMSLICE"
    assert len(parsed.blocks) == 1
    assert parsed.blocks[0].magic == b"MSLC"
    assert int(parsed.blocks[0].block_length) == 80


def test_rejects_encrypted():
    # flags bit 2 = ENCRYPTED
    buf = _build_file_header(flags=1 << 2) + _build_block()
    registry = get_kaitai_registry()
    parsed = registry.parse("msl", buf)
    # kaitai_registry swallows exceptions → returns None on failure
    assert parsed is None


def test_truncated_block_graceful():
    # block_length claims 80, but we only supply 40 payload/header bytes
    truncated_block_header = struct.pack(
        "<4sHHIH2x16s16s",
        b"MSLC", 0x0001, 0, 80, 1,
        b"\x22" * 16, b"\x00" * 16,
    )
    buf = _build_file_header() + truncated_block_header  # missing prev_hash + no payload
    registry = get_kaitai_registry()
    # Should not crash; parser may return a partial object or None.
    parsed = registry.parse("msl", buf)
    assert parsed is None or parsed.file_header.magic == b"MEMSLICE"


def test_two_blocks_parsed_sequentially():
    buf = (
        _build_file_header()
        + _build_block(0x0001, b"")
        + _build_block(0x0002, b"\x00" * 8)
    )
    registry = get_kaitai_registry()
    parsed = registry.parse("msl", buf)
    assert parsed is not None
    assert len(parsed.blocks) == 2
    assert int(parsed.blocks[1].block_length) == 88
