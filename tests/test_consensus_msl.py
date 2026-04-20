"""Tests for ASLR-aware consensus building with MSL dumps."""

import logging
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dump_source import MslDumpSource, RawDumpSource, open_dump
from core.variance import ByteClass
from engine.consensus import ConsensusVector, STRUCTURAL_MAX, POINTER_MAX, _is_native_msl
from tests.fixtures.generate_msl_fixtures import (
    generate_msl_file, _build_file_header, _build_memory_region, _det_uuid,
    FILE_MAGIC, PAGE_SIZE,
)


def _write_raw_dump(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _write_msl_with_flags(path: Path, blob: bytes, flags: int) -> Path:
    """Write an MSL blob with the flags field overridden at offset 0x0C."""
    buf = bytearray(blob)
    struct.pack_into("<I", buf, 0x0C, flags)
    path.write_bytes(bytes(buf))
    return path


def _make_native_msl(path: Path, base_addr: int, page_data: bytes) -> Path:
    """Build a minimal native MSL file (flags=0) with one memory region."""
    import random
    rng = random.Random(42)

    dump_uuid = bytes(rng.getrandbits(8) for _ in range(16))
    ts = 1_700_000_000_000_000_000
    hdr = _build_file_header(dump_uuid, ts)
    region_block, _ = _build_memory_region(
        base_addr=base_addr, num_pages=1, page_data=page_data,
    )
    blob = hdr + region_block
    path.write_bytes(blob)
    return path


# --- Tests ---


def test_threshold_structural_200():
    assert STRUCTURAL_MAX == 200.0
    assert POINTER_MAX == 3000.0


def test_raw_fallback(tmp_path):
    data = bytes(range(256))
    p1 = _write_raw_dump(tmp_path / "a.dump", data)
    p2 = _write_raw_dump(tmp_path / "b.dump", data)

    s1 = RawDumpSource(p1)
    s2 = RawDumpSource(p2)
    s1.open()
    s2.open()
    try:
        cm = ConsensusVector()
        cm.build_from_sources([s1, s2])
        assert cm.size == 256
        assert all(c == ByteClass.INVARIANT for c in cm.classifications)
        assert cm.region_results == {}
    finally:
        s1.close()
        s2.close()


def test_mixed_sources_fallback(tmp_path):
    raw_data = b"\x42" * 128
    p_raw = _write_raw_dump(tmp_path / "a.dump", raw_data)

    msl_blob = generate_msl_file()
    p_msl = tmp_path / "b.msl"
    p_msl.write_bytes(msl_blob)

    s_raw = RawDumpSource(p_raw)
    s_msl = MslDumpSource(p_msl)
    s_raw.open()
    s_msl.open()
    try:
        cm = ConsensusVector()
        cm.build_from_sources([s_raw, s_msl])
        assert cm.size > 0
    finally:
        s_raw.close()
        s_msl.close()


def test_imported_msl_uses_flat_fallback(tmp_path):
    blob = generate_msl_file()

    from msl.enums import HeaderFlag
    p1 = _write_msl_with_flags(tmp_path / "a.msl", blob, HeaderFlag.IMPORTED)
    p2 = _write_msl_with_flags(tmp_path / "b.msl", blob, HeaderFlag.IMPORTED)

    s1 = MslDumpSource(p1)
    s2 = MslDumpSource(p2)
    s1.open()
    s2.open()
    try:
        assert not _is_native_msl(s1)
        assert not _is_native_msl(s2)

        cm = ConsensusVector()
        cm.build_from_sources([s1, s2])
        assert cm.size > 0
        assert all(c == ByteClass.INVARIANT for c in cm.classifications)
    finally:
        s1.close()
        s2.close()


def test_region_results_initialized():
    cm = ConsensusVector()
    assert cm.region_results == {}


def test_build_from_sources_single_dump_warns(tmp_path, caplog):
    data = b"\x00" * 64
    p = _write_raw_dump(tmp_path / "only.dump", data)
    s = RawDumpSource(p)
    s.open()
    try:
        cm = ConsensusVector()
        with caplog.at_level(logging.WARNING, logger="memdiver.engine.consensus"):
            cm.build_from_sources([s])
        assert cm.size == 0
        assert "Need >= 2" in caplog.text
    finally:
        s.close()


def test_consensus_aslr_alignment_inline(tmp_path):
    page_data = b"\xDE\xAD" * (PAGE_SIZE // 2)

    p1 = _make_native_msl(tmp_path / "dump1.msl", 0x7FFF00000000, page_data)
    p2 = _make_native_msl(tmp_path / "dump2.msl", 0x7FFF10000000, page_data)

    s1 = MslDumpSource(p1)
    s2 = MslDumpSource(p2)
    s1.open()
    s2.open()
    try:
        assert _is_native_msl(s1)
        assert _is_native_msl(s2)

        cm = ConsensusVector()
        cm.build_from_sources([s1, s2])
        assert cm.size > 0
    finally:
        s1.close()
        s2.close()
