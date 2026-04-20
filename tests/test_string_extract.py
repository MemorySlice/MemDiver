"""Tests for msl.string_extract -- MSL string extraction."""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List
from unittest.mock import MagicMock
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.strings import StringMatch
from msl.string_extract import (
    MslStringReport,
    extract_region_strings,
    extract_strings_from_msl,
    extract_strings_from_path,
    extract_structured_strings,
)
from msl.enums import PageState
from msl.types import MslBlockHeader, MslMemoryRegion, MslModuleEntry, MslProcessIdentity


# -- Helpers --

_NEXT_OFFSET = 0

def _fake_block_header(**kwargs):
    global _NEXT_OFFSET
    defaults = dict(
        block_type=0x0001, flags=0, block_length=200,
        payload_version=1, block_uuid=UUID(int=1),
        parent_uuid=UUID(int=0), prev_hash=b"\x00" * 32,
        file_offset=_NEXT_OFFSET, payload_offset=_NEXT_OFFSET + 80,
    )
    _NEXT_OFFSET += 0x10000  # ensure unique offsets per block
    defaults.update(kwargs)
    return MslBlockHeader(**defaults)


def _make_region(base_addr, page_data, page_size_log2=12):
    """Create a fake MslMemoryRegion with captured page data."""
    page_size = 1 << page_size_log2
    num_pages = max(1, len(page_data) // page_size)
    region_size = num_pages * page_size
    return MslMemoryRegion(
        block_header=_fake_block_header(),
        base_addr=base_addr,
        region_size=region_size,
        protection=0x07,
        region_type=0x01,
        page_size_log2=page_size_log2,
        timestamp_ns=0,
        page_states=[PageState.CAPTURED] * num_pages,
    ), page_data[:region_size]


def _build_payload(region, page_data):
    """Build a full block payload for a region (header + page map + page data)."""
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    payload = bytearray(0x20 + map_bytes + len(page_data))
    payload[0x20 + map_bytes:] = page_data
    return bytes(payload)


def _mock_reader(regions=None, payload_map=None, modules=None, process=None):
    """Build a mock MslReader returning controlled data."""
    reader = MagicMock()
    reader.collect_regions.return_value = regions or []
    reader.collect_modules.return_value = modules or []
    reader.collect_process_identity.return_value = process or []

    if payload_map:
        def fake_read_block_payload(hdr):
            return payload_map.get(hdr.file_offset, b"")
        reader.read_block_payload.side_effect = fake_read_block_payload
    else:
        reader.read_block_payload.return_value = b""
    return reader


def _region_with_strings(base_addr, strings, page_size=4096):
    """Build a region whose page data contains known strings at known offsets."""
    data = bytearray(page_size)
    offsets = []
    pos = 0
    for s in strings:
        encoded = s.encode("ascii") + b"\x00"
        data[pos:pos + len(encoded)] = encoded
        offsets.append(pos)
        pos += len(encoded) + 4  # gap between strings
    region, pdata = _make_region(base_addr, bytes(data))
    payload = _build_payload(region, pdata)
    return region, pdata, payload, offsets


# -- Tests --

class TestMslStringReport:
    def test_total_count(self):
        report = MslStringReport(
            region_strings=[StringMatch(0, "hello", "ascii", 5)],
            module_strings=["mod1", "mod2"],
            process_strings=["proc1"],
        )
        assert report.total_count == 4

    def test_empty(self):
        report = MslStringReport()
        assert report.total_count == 0


class TestExtractRegionStrings:
    def test_basic(self):
        region, pdata, payload, _ = _region_with_strings(
            0x1000, ["hello_world", "test_string"],
        )
        reader = _mock_reader(
            regions=[region],
            payload_map={region.block_header.file_offset: payload},
        )
        results = extract_region_strings(reader, min_length=4)
        values = [m.value for m in results]
        assert "hello_world" in values
        assert "test_string" in values

    def test_min_length(self):
        region, pdata, payload, _ = _region_with_strings(
            0x2000, ["ab", "abcdef"],
        )
        reader = _mock_reader(
            regions=[region],
            payload_map={region.block_header.file_offset: payload},
        )
        results = extract_region_strings(reader, min_length=4)
        values = [m.value for m in results]
        assert "ab" not in values
        assert "abcdef" in values

    def test_max_regions(self):
        r1, p1, pl1, _ = _region_with_strings(0x1000, ["region_one"])
        r2, p2, pl2, _ = _region_with_strings(0x2000, ["region_two"])
        reader = _mock_reader(
            regions=[r1, r2],
            payload_map={r1.block_header.file_offset: pl1, r2.block_header.file_offset: pl2},
        )
        results = extract_region_strings(reader, min_length=4, max_regions=1)
        values = [m.value for m in results]
        assert "region_one" in values
        assert "region_two" not in values

    def test_offset_adjusted(self):
        base = 0x7FFF00000000
        region, pdata, payload, raw_offsets = _region_with_strings(
            base, ["offset_check"],
        )
        reader = _mock_reader(
            regions=[region],
            payload_map={region.block_header.file_offset: payload},
        )
        results = extract_region_strings(reader, min_length=4)
        match = next(m for m in results if m.value == "offset_check")
        # Offset should be base_addr + raw position in page data
        assert match.offset == base + raw_offsets[0]

    def test_dedup(self):
        """Same string at same absolute offset is deduplicated."""
        region, pdata, payload, _ = _region_with_strings(
            0x1000, ["duplicate"],
        )
        # Two identical regions with same base_addr -> same absolute offsets
        reader = _mock_reader(
            regions=[region, region],
            payload_map={region.block_header.file_offset: payload},
        )
        results = extract_region_strings(reader, min_length=4)
        dup_matches = [m for m in results if m.value == "duplicate"]
        assert len(dup_matches) == 1


class TestExtractStructuredStrings:
    def test_modules(self):
        m1 = MslModuleEntry(
            block_header=_fake_block_header(), base_addr=0,
            module_size=0, path="/usr/lib/libssl.so",
            version="1.1.1", disk_hash=b"\x00" * 32,
        )
        m2 = MslModuleEntry(
            block_header=_fake_block_header(), base_addr=0,
            module_size=0, path="/usr/lib/libcrypto.so",
            version="", disk_hash=b"\x00" * 32,
        )
        reader = _mock_reader(modules=[m1, m2])
        mod_strs, proc_strs = extract_structured_strings(reader)
        assert "/usr/lib/libssl.so" in mod_strs
        assert "1.1.1" in mod_strs
        assert "/usr/lib/libcrypto.so" in mod_strs
        # Empty version should not be included
        assert "" not in mod_strs
        assert proc_strs == []

    def test_process(self):
        p1 = MslProcessIdentity(
            block_header=_fake_block_header(), ppid=100,
            session_id=1, start_time_ns=0,
            exe_path="/usr/bin/openssl", cmd_line="openssl s_client",
        )
        reader = _mock_reader(process=[p1])
        mod_strs, proc_strs = extract_structured_strings(reader)
        assert mod_strs == []
        assert "/usr/bin/openssl" in proc_strs
        assert "openssl s_client" in proc_strs

    def test_empty(self):
        reader = _mock_reader()
        mod_strs, proc_strs = extract_structured_strings(reader)
        assert mod_strs == []
        assert proc_strs == []


class TestExtractStringsFromMsl:
    def test_combined(self):
        region, pdata, payload, _ = _region_with_strings(
            0x1000, ["memory_string"],
        )
        module = MslModuleEntry(
            block_header=_fake_block_header(), base_addr=0,
            module_size=0, path="/lib/test.so",
            version="2.0", disk_hash=b"\x00" * 32,
        )
        proc = MslProcessIdentity(
            block_header=_fake_block_header(), ppid=1,
            session_id=1, start_time_ns=0,
            exe_path="/bin/app", cmd_line="app run",
        )
        reader = _mock_reader(
            regions=[region],
            payload_map={region.block_header.file_offset: payload},
            modules=[module],
            process=[proc],
        )
        report = extract_strings_from_msl(reader, min_length=4)
        assert any(m.value == "memory_string" for m in report.region_strings)
        assert "/lib/test.so" in report.module_strings
        assert "/bin/app" in report.process_strings
        assert report.total_count > 0


class TestExtractStringsFromPath:
    def test_end_to_end(self, tmp_path):
        """End-to-end test using a real MSL fixture file."""
        from tests.fixtures.generate_msl_fixtures import write_msl_fixture

        msl_path = tmp_path / "test.msl"
        write_msl_fixture(msl_path)
        report = extract_strings_from_path(msl_path, min_length=4)
        # The fixture has a process identity with exe_path="/usr/bin/test"
        assert "/usr/bin/test" in report.process_strings
        assert "test --flag" in report.process_strings
        # total_count should include at least the process strings
        assert report.total_count >= 2
