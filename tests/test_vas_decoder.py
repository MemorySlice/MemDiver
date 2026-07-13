"""Tests for VAS Map decoder and reader integration."""

import struct
import sys
from pathlib import Path
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.decoders import decode_vas_map
from msl.types import MslBlockHeader, MslVasEntry, MslVasMap
from tests.fixtures.generate_msl_fixtures import (
    _build_vas_map,
    _det_uuid,
    _pack_padded_str,
    ensure_msl_fixtures,
    generate_msl_file,
)

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "dataset"


def _make_block_header():
    """Create a dummy block header for decoder tests."""
    return MslBlockHeader(
        block_type=0x1001, flags=0, block_length=80,
        payload_version=1,
        block_uuid=UUID(int=1), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32, file_offset=0, payload_offset=80,
    )


def _build_raw_vas_payload(entries):
    """Build raw VAS_MAP payload bytes for decoder tests."""
    payload = struct.pack("<II", len(entries), 0)
    for base, size, prot, rtype, path in entries:
        path_raw_len = (len(path.encode("utf-8")) + 1) if path else 0
        payload += struct.pack("<QQBBH4x", base, size, prot, rtype,
                               path_raw_len)
        if path:
            raw = path.encode("utf-8") + b"\x00"
            padded = raw.ljust((len(raw) + 7) & ~7, b"\x00")
            payload += padded
    return payload


def test_decode_vas_map_basic():
    """Round-trip decode of a single-entry VAS_MAP."""
    entries = [(0x7FFF00000000, 0x21000, 0x07, 0x01, "")]
    payload = _build_raw_vas_payload(entries)
    hdr = _make_block_header()
    result = decode_vas_map(hdr, payload, "<")
    assert isinstance(result, MslVasMap)
    assert result.entry_count == 1
    assert len(result.entries) == 1
    assert result.entries[0].base_addr == 0x7FFF00000000
    assert result.entries[0].region_size == 0x21000


def test_decode_vas_map_empty():
    """Zero entries produces empty list."""
    payload = struct.pack("<II", 0, 0)
    hdr = _make_block_header()
    result = decode_vas_map(hdr, payload, "<")
    assert result.entry_count == 0
    assert result.entries == []


def test_decode_vas_map_multiple_entries():
    """Multiple entries with different types decode correctly."""
    entries = [
        (0x00400000, 0x10000, 0x05, 0x03, "/usr/lib/libssl.so"),
        (0x7FFF00000000, 0x21000, 0x07, 0x01, ""),
        (0x7FFFFFFDE000, 0x22000, 0x03, 0x02, "[stack]"),
    ]
    payload = _build_raw_vas_payload(entries)
    hdr = _make_block_header()
    result = decode_vas_map(hdr, payload, "<")
    assert result.entry_count == 3
    assert result.entries[0].region_type == 0x03  # IMAGE
    assert result.entries[1].region_type == 0x01  # HEAP
    assert result.entries[2].mapped_path == "[stack]"


def test_vas_entry_fields():
    """Verify all fields of a VAS entry decode correctly."""
    entries = [(0xDEADBEEF, 0x1000, 0x07, 0x04, "/tmp/mapped.dat")]
    payload = _build_raw_vas_payload(entries)
    hdr = _make_block_header()
    result = decode_vas_map(hdr, payload, "<")
    e = result.entries[0]
    assert e.base_addr == 0xDEADBEEF
    assert e.region_size == 0x1000
    assert e.protection == 0x07
    assert e.region_type == 0x04
    assert e.mapped_path == "/tmp/mapped.dat"


def test_collect_vas_map():
    """Reader collect_vas_map returns cached VAS_MAP blocks."""
    from msl.reader import MslReader

    ensure_msl_fixtures(FIXTURES_ROOT)
    msl_path = FIXTURES_ROOT / "msl" / "test_capture.msl"
    with MslReader(msl_path) as reader:
        maps = reader.collect_vas_map()
        assert len(maps) >= 1
        assert isinstance(maps[0], MslVasMap)
        assert maps[0].entry_count == 3
        # Verify caching
        assert reader.collect_vas_map() is maps


def test_vas_map_no_block():
    """Reader returns empty list when no VAS_MAP blocks exist."""
    from msl.reader import MslReader

    # Build a minimal MSL with no VAS_MAP block
    from tests.fixtures.generate_msl_fixtures import (
        _build_file_header,
        _build_end_of_capture,
        _RNG,
    )
    import random
    import tempfile

    rng = random.Random(42)
    dump_uuid = bytes(rng.getrandbits(8) for _ in range(16))
    blob = _build_file_header(dump_uuid, 1_700_000_000_000_000_000)
    eoc, _ = _build_end_of_capture(1_700_000_001_000_000_000)
    blob += eoc

    with tempfile.NamedTemporaryFile(suffix=".msl", delete=False) as f:
        f.write(blob)
        tmp_path = Path(f.name)

    try:
        with MslReader(tmp_path) as reader:
            maps = reader.collect_vas_map()
            assert maps == []
    finally:
        tmp_path.unlink()


# -- adversarial / bounds-guard regression tests --

from msl.decoders import decode_memory_region
from msl.types import MslParseError


def test_decode_vas_map_truncated_entry_raises():
    """A truncated entry head raises MslParseError, not struct.error."""
    # Header advertises one entry but the payload stops mid-entry.
    payload = struct.pack("<II", 1, 0) + b"\x00" * 4  # only 4 of 0x18 bytes
    hdr = _make_block_header()
    with pytest.raises(MslParseError):
        decode_vas_map(hdr, payload, "<")


def test_decode_vas_map_bogus_huge_count_raises():
    """A bogus huge entry_count cannot drive billions of iterations.

    The per-entry guard raises MslParseError on the very first short entry
    instead of looping ``entry_count`` times.
    """
    payload = struct.pack("<II", 0xFFFFFFFF, 0)  # header only, no entries
    hdr = _make_block_header()
    with pytest.raises(MslParseError):
        decode_vas_map(hdr, payload, "<")


def test_decode_vas_map_truncated_path_raises():
    """An entry whose path_len runs past the payload raises MslParseError."""
    # One entry header claiming a 0x20-byte path but no path bytes follow.
    payload = struct.pack("<II", 1, 0) + struct.pack(
        "<QQBBH4x", 0x1000, 0x1000, 0x07, 0x01, 0x20
    )
    hdr = _make_block_header()
    with pytest.raises(MslParseError):
        decode_vas_map(hdr, payload, "<")


def test_decode_memory_region_short_payload_raises():
    """A payload shorter than the fixed 0x20 header raises MslParseError."""
    hdr = _make_block_header()
    # Only 0x10 bytes — the protection/page_size_log2 reads would overrun.
    payload = b"\x00" * 0x10
    with pytest.raises(MslParseError):
        decode_memory_region(hdr, payload, "<")
