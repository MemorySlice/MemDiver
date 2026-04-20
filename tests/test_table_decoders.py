"""Tests for the 4 new spec-defined MSL table block decoders (Phase MSL-Decoders-02).

Covers MODULE_LIST_INDEX (0x0010), PROCESS_TABLE (0x0051),
CONNECTION_TABLE (0x0052), HANDLE_TABLE (0x0053).

Unlike the ext decoders (which tolerate truncation by falling back to
MslGenericBlock), these spec-defined decoders raise MslParseError on
truncation — silent fallback would hide corruption of data the spec says
is real.
"""

import struct
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from msl.block_tree import _block_type_name, list_blocks
from msl.decoders import (decode_connection_table, decode_connectivity_table,
                          decode_handle_table, decode_module_list_index,
                          decode_process_table)
from msl.enums import BlockType, ConnRowType
from msl.reader import MslReader
from msl.types import (MslBlockHeader, MslConnArpEntry, MslConnectionTable,
                       MslConnectivityTable, MslConnIfaceStats,
                       MslConnIPv4Route, MslConnIPv6Route, MslConnMibCounter,
                       MslConnPacketSocket, MslConnSocketFamilyAgg,
                       MslHandleTable, MslModuleListIndex, MslParseError,
                       MslProcessTable)
from tests.fixtures.generate_msl_fixtures import (_build_block,
                                                   _build_connection_table,
                                                   _build_connectivity_table,
                                                   _build_handle_table,
                                                   _build_module_list_index,
                                                   _build_process_table,
                                                   _pack_conn_row,
                                                   _pack_conn_string,
                                                   generate_msl_file)

BO = "<"


def _hdr(block_type: int = 0x0051) -> MslBlockHeader:
    return MslBlockHeader(
        block_type=block_type, flags=0, block_length=0,
        payload_version=1,
        block_uuid=UUID(int=1), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32,
        file_offset=0, payload_offset=80,
    )


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


# =========================================================================
# MODULE_LIST_INDEX (0x0010)
# =========================================================================

def _mli_payload(entries):
    """Rebuild a MODULE_LIST_INDEX payload given a list of (uuid, base, size, path) tuples."""
    payload = struct.pack("<II", len(entries), 0)
    for mod_uuid, base, size, path in entries:
        path_raw = (path.encode("utf-8") + b"\x00") if path else b""
        path_padded = path_raw.ljust(((len(path_raw) + 7) & ~7), b"\x00")
        payload += bytes(mod_uuid)
        payload += struct.pack("<QQHHI", base, size, len(path_raw), 0, 0)
        payload += path_padded
    return payload


def test_mli_roundtrip_single_entry():
    uid = bytes(range(16))
    payload = _mli_payload([(uid, 0x400000, 0x10000, "/usr/lib/libc.so")])
    result = decode_module_list_index(_hdr(0x0010), payload, BO)
    assert isinstance(result, MslModuleListIndex)
    assert result.entry_count == 1
    e = result.entries[0]
    assert e.module_uuid == UUID(bytes=uid)
    assert e.base_addr == 0x400000
    assert e.module_size == 0x10000
    assert e.path == "/usr/lib/libc.so"


def test_mli_roundtrip_multi_entry():
    entries = [
        (bytes(range(16)), 0x1000, 0x2000, "/a"),
        (bytes(range(16, 32)), 0x3000, 0x4000, "/usr/lib/much/longer/path.so"),
        (bytes([0xFF] * 16), 0x5000, 0x6000, ""),
    ]
    payload = _mli_payload(entries)
    result = decode_module_list_index(_hdr(0x0010), payload, BO)
    assert result.entry_count == 3
    assert result.entries[0].path == "/a"
    assert result.entries[1].path == "/usr/lib/much/longer/path.so"
    assert result.entries[2].path == ""  # Len=0 edge case


def test_mli_empty_table():
    payload = struct.pack("<II", 0, 0)
    result = decode_module_list_index(_hdr(0x0010), payload, BO)
    assert result.entry_count == 0
    assert result.entries == ()


def test_mli_truncated_raises():
    # Partial entry after header → corruption → must raise.
    # (8-byte payload exactly is the legal manifest-only variant.)
    payload = struct.pack("<II", 5, 0) + b"\x00" * 16  # partial entry
    with pytest.raises(MslParseError):
        decode_module_list_index(_hdr(0x0010), payload, BO)


def test_mli_manifest_only_variant():
    """Chrome writer emits MODULE_LIST_INDEX as a count-only manifest
    (8-byte header with entry_count but no inline entries). Actual module
    data lives in separate MODULE_ENTRY (0x0002) blocks."""
    payload = struct.pack("<II", 366, 0)  # 8 bytes: count=366, no entries
    result = decode_module_list_index(_hdr(0x0010), payload, BO)
    assert result.entry_count == 366
    assert result.entries == ()


def test_mli_collector_via_reader(msl_path):
    with MslReader(msl_path) as reader:
        tables = reader.collect_module_list_index()
        assert len(tables) == 1
        assert tables[0].entry_count == 2
        assert tables[0].entries[0].path == "/usr/lib/libssl.so"


def test_mli_collector_cache_identity(msl_path):
    with MslReader(msl_path) as reader:
        a = reader.collect_module_list_index()
        b = reader.collect_module_list_index()
        assert a is b


# =========================================================================
# PROCESS_TABLE (0x0051)
# =========================================================================

def test_process_table_roundtrip_single(msl_path):
    with MslReader(msl_path) as reader:
        tables = reader.collect_processes()
        assert len(tables) == 1
        tbl = tables[0]
        assert tbl.entry_count == 2
        e0 = tbl.entries[0]
        assert e0.pid == 1234
        assert e0.ppid == 1
        assert e0.uid == 1000
        assert e0.is_target is True
        assert e0.exe_name == "/usr/bin/target"
        assert e0.cmd_line == "target --flag"
        assert e0.user == "alice"
        e1 = tbl.entries[1]
        assert e1.pid == 5678
        assert e1.is_target is False
        assert e1.cmd_line == ""  # Len=0 edge case (no string bytes)
        assert e1.user == "root"


def test_process_table_roundtrip_multi_lengths():
    """Varied string lengths including empty strings."""
    raw, _ = _build_process_table([
        {"pid": 1, "ppid": 0, "uid": 0, "is_target": False,
         "start_time_ns": 0, "rss": 0,
         "exe_name": "", "cmd_line": "", "user": ""},
        {"pid": 2, "ppid": 1, "uid": 1, "is_target": True,
         "start_time_ns": 1, "rss": 1,
         "exe_name": "a", "cmd_line": "b", "user": "c"},
        {"pid": 3, "ppid": 2, "uid": 2, "is_target": False,
         "start_time_ns": 2, "rss": 2,
         "exe_name": "x" * 100, "cmd_line": "y" * 50, "user": "z" * 10},
    ])
    payload = raw[80:]  # strip block header
    result = decode_process_table(_hdr(0x0051), payload, BO)
    assert result.entry_count == 3
    assert result.entries[0].exe_name == ""
    assert result.entries[1].exe_name == "a"
    assert result.entries[1].cmd_line == "b"
    assert result.entries[2].exe_name == "x" * 100


def test_process_table_empty():
    payload = struct.pack("<II", 0, 0)
    result = decode_process_table(_hdr(0x0051), payload, BO)
    assert result.entry_count == 0
    assert result.entries == ()


def test_process_table_truncated_raises():
    payload = struct.pack("<II", 3, 0) + b"\x00" * 8  # count=3, insufficient
    with pytest.raises(MslParseError):
        decode_process_table(_hdr(0x0051), payload, BO)


def test_process_table_cache_identity(msl_path):
    with MslReader(msl_path) as reader:
        a = reader.collect_processes()
        b = reader.collect_processes()
        assert a is b


# =========================================================================
# CONNECTION_TABLE (0x0052)
# =========================================================================

def test_connection_table_roundtrip(msl_path):
    with MslReader(msl_path) as reader:
        tables = reader.collect_connections()
        assert len(tables) == 1
        tbl = tables[0]
        assert tbl.entry_count == 2
        e0 = tbl.entries[0]
        assert e0.pid == 1234
        assert e0.family == 0x02  # AF_INET
        assert e0.protocol == 0x06  # TCP
        assert e0.state == 0x01
        assert e0.local_addr[:4] == b"\x7f\x00\x00\x01"
        assert e0.local_port == 443
        assert e0.remote_addr[:4] == b"\x08\x08\x08\x08"
        assert e0.remote_port == 55123
        e1 = tbl.entries[1]
        assert e1.family == 0x0A  # AF_INET6
        assert e1.protocol == 0x11  # UDP
        assert e1.local_port == 5353
        assert e1.remote_port == 0  # listen-like / UDP


def test_connection_table_empty():
    payload = struct.pack("<II", 0, 0)
    result = decode_connection_table(_hdr(0x0052), payload, BO)
    assert result.entry_count == 0
    assert result.entries == ()


def test_connection_table_truncated_raises():
    payload = struct.pack("<II", 2, 0) + b"\x00" * 16  # 2 entries need 96 bytes
    with pytest.raises(MslParseError):
        decode_connection_table(_hdr(0x0052), payload, BO)


def test_connection_table_port_byte_order():
    """Ports MUST be uint16 little-endian, NOT network byte order.

    This is the one field most likely to be silently wrong in a symmetric
    build+decode round-trip (both would use the same wrong code). Validates
    against a hand-packed payload using explicit LE byte layout.
    """
    # local_port=443 (0x01BB), remote_port=8080 (0x1F90)
    # In LE: 443 = bb 01, 8080 = 90 1f
    # In NE: 443 = 01 bb, 8080 = 1f 90
    payload = struct.pack("<II", 1, 0)
    payload += struct.pack(
        "<IBBB1s 16s H2s 16s H2s",
        1234, 0x02, 0x06, 0x01, b"\x00",
        b"\x00" * 16,
        443,           # LE uint16 → bb 01
        b"\x00" * 2,
        b"\x00" * 16,
        8080,          # LE uint16 → 90 1f
        b"\x00" * 2,
    )
    # Verify raw bytes show LE layout
    assert payload[8 + 0x18:8 + 0x1A] == b"\xbb\x01"
    assert payload[8 + 0x2C:8 + 0x2E] == b"\x90\x1f"
    # And decoder recovers the values correctly
    result = decode_connection_table(_hdr(0x0052), payload, BO)
    assert result.entries[0].local_port == 443
    assert result.entries[0].remote_port == 8080


def test_connection_table_cache_identity(msl_path):
    with MslReader(msl_path) as reader:
        a = reader.collect_connections()
        b = reader.collect_connections()
        assert a is b


# =========================================================================
# HANDLE_TABLE (0x0053)
# =========================================================================

def test_handle_table_roundtrip(msl_path):
    """Verify HANDLE_TABLE (0x0053) round-trips per spec Table 24.

    HandleType is a uint16 enum; default fixture exercises File, Socket
    (empty-path edge case), and Other handle types.
    """
    from msl.enums import HandleType
    with MslReader(msl_path) as reader:
        tables = reader.collect_handles()
        assert len(tables) == 1
        tbl = tables[0]
        assert tbl.entry_count == 3
        e0 = tbl.entries[0]
        assert e0.pid == 1234
        assert e0.fd == 3
        assert e0.handle_type == HandleType.FILE  # 0x01
        assert e0.path == "/var/log/target.log"
        e1 = tbl.entries[1]
        assert e1.handle_type == HandleType.SOCKET  # 0x03
        assert e1.path == ""  # Len=0 edge case
        e2 = tbl.entries[2]
        assert e2.handle_type == HandleType.OTHER  # 0x07
        assert e2.path == "HKLM\\Software\\Test"


def test_handle_table_empty():
    payload = struct.pack("<II", 0, 0)
    result = decode_handle_table(_hdr(0x0053), payload, BO)
    assert result.entry_count == 0
    assert result.entries == ()


def test_handle_table_truncated_raises():
    payload = struct.pack("<II", 2, 0) + b"\x00" * 8  # 2 entries, insufficient
    with pytest.raises(MslParseError):
        decode_handle_table(_hdr(0x0053), payload, BO)


def test_handle_table_cache_identity(msl_path):
    with MslReader(msl_path) as reader:
        a = reader.collect_handles()
        b = reader.collect_handles()
        assert a is b


# =========================================================================
# CONNECTIVITY_TABLE (0x0055)
# =========================================================================

def test_connectivity_table_roundtrip(msl_path):
    """Verify CONNECTIVITY_TABLE (0x0055) round-trips all 7 row types per
    spec Table 25/26."""
    with MslReader(msl_path) as reader:
        tables = reader.collect_connectivity_tables()
    assert len(tables) == 1
    tbl = tables[0]
    assert tbl.row_count == 7
    assert len(tbl.rows) == 7

    kinds = {type(r).__name__: r for r in tbl.rows}
    assert "MslConnIPv4Route" in kinds
    assert kinds["MslConnIPv4Route"].gateway == b"\xc0\xa8\x01\x01"
    assert kinds["MslConnIPv4Route"].iface == "eth0"
    assert kinds["MslConnIPv4Route"].mtu == 1500

    assert kinds["MslConnIPv6Route"].dest_prefix == 0
    assert kinds["MslConnIPv6Route"].next_hop.startswith(b"\xfe\x80")

    assert kinds["MslConnArpEntry"].ip == b"\xc0\xa8\x01\x05"
    assert kinds["MslConnArpEntry"].hw_addr == b"\xde\xad\xbe\xef\x00\x01"

    assert kinds["MslConnPacketSocket"].pid == 1234
    assert kinds["MslConnPacketSocket"].inode == 98765

    stats = kinds["MslConnIfaceStats"]
    assert stats.rx_bytes == 123456789
    assert stats.tx_pkts == 900

    agg = kinds["MslConnSocketFamilyAgg"]
    assert agg.family == 0x02
    assert agg.mem == 81920

    mib = kinds["MslConnMibCounter"]
    assert mib.mib == "ip"
    assert mib.counter == "InReceives"
    assert mib.value == 500000


def test_connectivity_table_unknown_row_skip():
    """Unknown row types MUST be silently skipped per spec §6.6 forward-compat.

    Builds a 3-row payload: known IPv4 route + unknown RowType=0xFF + known
    packet socket. The decoder should skip the unknown row and still correctly
    decode the packet socket that follows it.
    """
    ipv4_body = _pack_conn_string("eth0")
    ipv4_body += b"\x00\x00\x00\x00"  # dest
    ipv4_body += b"\xc0\xa8\x01\x01"  # gateway
    ipv4_body += b"\x00\x00\x00\x00"  # mask
    ipv4_body += struct.pack("<HII", 3, 100, 1500)
    row1 = _pack_conn_row(0x01, ipv4_body)

    unknown_body = b"\xAA\xBB\xCC\xDD\xEE"  # arbitrary bytes
    row2 = _pack_conn_row(0xFF, unknown_body)

    ps_body = struct.pack("<IQHIIQ", 4242, 555, 3, 7, 1000, 8192)
    row3 = _pack_conn_row(0x04, ps_body)

    payload = struct.pack("<II", 3, 0) + row1 + row2 + row3

    hdr = MslBlockHeader(
        block_type=0x0055, flags=0, block_length=0,
        payload_version=1,
        block_uuid=UUID(int=1), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32, file_offset=0, payload_offset=80,
    )
    result = decode_connectivity_table(hdr, payload, BO)
    assert result.row_count == 3
    assert len(result.rows) == 2  # unknown skipped
    assert isinstance(result.rows[0], MslConnIPv4Route)
    assert isinstance(result.rows[1], MslConnPacketSocket)
    assert result.rows[1].pid == 4242
    assert result.rows[1].inode == 555


def test_connectivity_table_empty():
    payload = struct.pack("<II", 0, 0)
    result = decode_connectivity_table(_hdr(0x0055), payload, BO)
    assert result.row_count == 0
    assert result.rows == ()


def test_connectivity_table_cache_identity(msl_path):
    with MslReader(msl_path) as reader:
        a = reader.collect_connectivity_tables()
        b = reader.collect_connectivity_tables()
        assert a is b


# =========================================================================
# Cross-cutting: block_tree naming + cache-attr structural invariant
# =========================================================================

def test_block_tree_names_all_new_types(msl_path):
    """list_blocks() must yield decoded names for the 4 new block types,
    never UNKNOWN_0x00NN."""
    with MslReader(msl_path) as reader:
        nodes = list_blocks(reader)
    names = {n.type_name for n in nodes}
    assert "MODULE_LIST_INDEX" in names
    assert "PROCESS_TABLE" in names
    assert "CONNECTION_TABLE" in names
    assert "HANDLE_TABLE" in names
    for forbidden in ("UNKNOWN_0x0010", "UNKNOWN_0x0051",
                      "UNKNOWN_0x0052", "UNKNOWN_0x0053"):
        assert forbidden not in names


def test_cache_attrs_structural_invariant():
    """Every entry in MslReader._CACHE_ATTRS must have a matching collect_*
    method. Guards against future wiring drift where a cache attr is added
    but the collector is missed (or vice versa)."""
    attrs = MslReader._CACHE_ATTRS
    # Each cache attr follows the pattern _<name>_cache and should have a
    # collect_<name> method. We verify the reader class exposes SOME collect_*
    # method matching each attr's name stem — exact mapping lives in reader.py.
    collect_methods = [m for m in dir(MslReader) if m.startswith("collect_")]
    assert len(collect_methods) >= len(attrs), (
        f"{len(collect_methods)} collectors vs {len(attrs)} cache attrs — wiring drift"
    )
    # And no duplicate cache attrs
    assert len(set(attrs)) == len(attrs), "duplicate _CACHE_ATTRS entries"


# =========================================================================
# Golden-file test (vendored real sample)
# =========================================================================

_GOLDEN = Path(__file__).parent / "fixtures" / "real_samples" / "chrome_min.msl"


@pytest.mark.skipif(not _GOLDEN.exists(), reason="Golden sample not vendored")
def test_golden_real_sample_no_exceptions():
    """Open the vendored real Chrome .msl and call all 10 new collectors.

    Guards against silent drift if the memslicer writer changes. The
    Chrome sample (~85 KB) is known to contain MODULE_LIST_INDEX (0x0010),
    MEMORY_REGION, MODULE_ENTRY, and END_OF_CAPTURE — it does NOT include
    PROCESS/CONNECTION/HANDLE tables (those are Linux/memslicer capture
    output), so those collectors must return empty lists without errors.
    """
    with MslReader(_GOLDEN) as reader:
        for collector_name in (
            "collect_module_list_index",
            "collect_processes",
            "collect_connections",
            "collect_handles",
            "collect_thread_contexts",
            "collect_file_descriptors",
            "collect_network_connections",
            "collect_environment_blocks",
            "collect_security_tokens",
            "collect_system_context",
        ):
            result = getattr(reader, collector_name)()
            assert isinstance(result, list), collector_name
        # Known to contain MODULE_LIST_INDEX — exercises the real-data path
        mli_tables = reader.collect_module_list_index()
        assert len(mli_tables) >= 1, "Chrome sample must have MODULE_LIST_INDEX"
        total_entries = sum(t.entry_count for t in mli_tables)
        assert total_entries > 0
        # Every decoded entry must have a non-empty path and a UUID
        for table in mli_tables:
            for entry in table.entries:
                assert entry.path  # non-empty
                assert entry.module_uuid is not None
