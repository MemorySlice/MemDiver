"""Synthetic MSL fixture generator for testing.

Builds valid MSL binary blobs using struct.pack with deterministic
UUIDs (seeded random) so round-trip tests are reproducible.
"""

import random
import struct
import uuid
from pathlib import Path

_RNG = random.Random(42)

FILE_MAGIC = b"MEMSLICE"
BLOCK_MAGIC = b"MSLC"
FILE_HEADER_SIZE = 64
BLOCK_HEADER_SIZE = 80
PAGE_SIZE = 4096
PAGE_SIZE_LOG2 = 12


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _det_uuid() -> bytes:
    """Generate a deterministic 16-byte UUID from seeded RNG."""
    return bytes(_RNG.getrandbits(8) for _ in range(16))


def _pack_padded_str(s: str) -> bytes:
    """Null-terminate and pad string to 8-byte alignment."""
    raw = s.encode("utf-8") + b"\x00"
    return raw.ljust(_pad8(len(raw)), b"\x00")


def _build_block(block_type, payload, block_uuid=None, parent_uuid=None):
    """Build a complete block: 80-byte header + payload."""
    if block_uuid is None:
        block_uuid = _det_uuid()
    if parent_uuid is None:
        parent_uuid = b"\x00" * 16
    block_length = BLOCK_HEADER_SIZE + len(payload)
    header = struct.pack(
        "<4sHHIH2x16s16s32s",
        BLOCK_MAGIC, block_type, 0, block_length, 1,
        bytes(block_uuid), bytes(parent_uuid), b"\x00" * 32,
    )
    assert len(header) == BLOCK_HEADER_SIZE
    return header + payload, block_uuid


def _build_file_header(dump_uuid, timestamp_ns, pid=1234):
    """Build the 64-byte MSL file header."""
    version = (1 << 8) | 1  # v1.1
    cap_bitmap = 1 << 0     # MemoryRegions bit
    hdr = struct.pack(
        "<8sBBHIQ16sQHHIB7x",
        FILE_MAGIC, 0x01, FILE_HEADER_SIZE, version, 0,
        cap_bitmap, dump_uuid, timestamp_ns,
        0x0001, 0x0001, pid, 0,  # Linux, x86_64, pid, clock_source
    )
    assert len(hdr) == FILE_HEADER_SIZE
    return hdr


def _build_process_identity(ppid=1000, session_id=1,
                            exe_path="/usr/bin/test",
                            cmd_line="test --flag"):
    """Build Process Identity payload (type 0x0040)."""
    exe_bytes = _pack_padded_str(exe_path)
    cmd_bytes = _pack_padded_str(cmd_line)
    exe_raw_len = len(exe_path.encode("utf-8")) + 1
    cmd_raw_len = len(cmd_line.encode("utf-8")) + 1
    payload = struct.pack("<IIQHH4x", ppid, session_id, 0, exe_raw_len, cmd_raw_len)
    payload += exe_bytes + cmd_bytes
    return _build_block(0x0040, payload)


def _build_memory_region(base_addr=0x7FFF00000000, num_pages=1,
                         page_data=None):
    """Build Memory Region payload (type 0x0001) with page data."""
    region_size = num_pages * PAGE_SIZE
    bitmap_padded = _pad8(((num_pages * 2) + 7) // 8)
    page_map = b"\x00" * bitmap_padded  # all CAPTURED
    payload = struct.pack(
        "<QQBBB5xQ",
        base_addr, region_size,
        0x07, 0x01, PAGE_SIZE_LOG2, 0,  # RWX, HEAP, log2, timestamp
    )
    payload += page_map
    if page_data is not None:
        payload += page_data
    return _build_block(0x0001, payload)


def _build_key_hint(region_uuid, offset=0, key_length=32,
                    key_type=0x0003, protocol=0x0002,
                    confidence=0x02, key_state=0x01, note="test_key"):
    """Build Key Hint payload (type 0x0020)."""
    note_bytes = _pack_padded_str(note)
    note_raw_len = len(note.encode("utf-8")) + 1
    payload = struct.pack(
        "<16sQIHHBB2xI4x",
        bytes(region_uuid), offset, key_length,
        key_type, protocol, confidence, key_state, note_raw_len,
    )
    payload += note_bytes
    return _build_block(0x0020, payload)


def _build_module_entry(base_addr=0x00400000, module_size=0x10000,
                        path="/usr/lib/libssl.so", version="1.1.1"):
    """Build Module Entry payload (type 0x0002)."""
    path_bytes = _pack_padded_str(path)
    ver_bytes = _pack_padded_str(version)
    path_raw_len = len(path.encode("utf-8")) + 1
    ver_raw_len = len(version.encode("utf-8")) + 1
    payload = struct.pack("<QQHH4x", base_addr, module_size,
                          path_raw_len, ver_raw_len)
    payload += path_bytes + ver_bytes + b"\x00" * 32  # disk_hash
    return _build_block(0x0002, payload)


def _build_related_dump(related_uuid=None, related_pid=5678, relationship=1,
                        target_hash=None):
    """Build Related Dump payload (type 0x0041).

    Post-C1 layout: 24-byte fixed prefix + 32-byte target_hash = 56 bytes.
    `target_hash` defaults to a deterministic non-zero pattern so
    round-trip tests can assert it survives the writer/reader cycle.
    """
    if related_uuid is None:
        related_uuid = _det_uuid()
    if target_hash is None:
        target_hash = bytes(range(32))  # deterministic, non-zero
    payload = struct.pack("<16sIH2x", bytes(related_uuid),
                          related_pid, relationship)
    payload += target_hash
    return _build_block(0x0041, payload)


def _build_vas_map(entries=None):
    """Build VAS Map payload (type 0x1001).

    Each entry: uint64 base, uint64 size, uint8 prot, uint8 rtype,
    uint16 path_len, 4 pad, then path string.
    """
    if entries is None:
        entries = [
            (0x00400000, 0x10000, 0x05, 0x03, "/usr/lib/libssl.so"),
            (0x7FFF00000000, 0x21000, 0x07, 0x01, ""),
            (0x7FFFFFFDE000, 0x22000, 0x03, 0x02, "[stack]"),
        ]
    entry_size = 0  # variable length
    payload = struct.pack("<II", len(entries), entry_size)
    for base, size, prot, rtype, path in entries:
        path_bytes = _pack_padded_str(path) if path else b""
        path_raw_len = (len(path.encode("utf-8")) + 1) if path else 0
        payload += struct.pack("<QQBBH4x", base, size, prot, rtype,
                               path_raw_len)
        payload += path_bytes
    return _build_block(0x1001, payload)


def _build_module_list_index(entries=None):
    """Build Module List Index payload (type 0x0010, spec Table 15)."""
    if entries is None:
        entries = [
            (_det_uuid(), 0x00400000, 0x10000, "/usr/lib/libssl.so"),
            (_det_uuid(), 0x00500000, 0x08000, "/usr/lib/libcrypto.so"),
        ]
    payload = struct.pack("<II", len(entries), 0)
    for module_uuid, base_addr, module_size, path in entries:
        path_bytes = _pack_padded_str(path) if path else b""
        path_raw_len = (len(path.encode("utf-8")) + 1) if path else 0
        payload += bytes(module_uuid)
        payload += struct.pack("<QQHHI",
                               base_addr, module_size,
                               path_raw_len, 0, 0)
        payload += path_bytes
    return _build_block(0x0010, payload)


def _build_process_table(entries=None):
    """Build Process Table payload (type 0x0051, spec Table 21)."""
    if entries is None:
        entries = [
            {
                "pid": 1234, "ppid": 1, "uid": 1000, "is_target": True,
                "start_time_ns": 1_700_000_000_000_000_000, "rss": 0x1000000,
                "exe_name": "/usr/bin/target", "cmd_line": "target --flag",
                "user": "alice",
            },
            {
                "pid": 5678, "ppid": 1234, "uid": 0, "is_target": False,
                "start_time_ns": 1_700_000_001_000_000_000, "rss": 0x200000,
                "exe_name": "/sbin/helper", "cmd_line": "",
                "user": "root",
            },
        ]
    payload = struct.pack("<II", len(entries), 0)
    for e in entries:
        exe_raw = (e["exe_name"].encode("utf-8") + b"\x00") if e["exe_name"] else b""
        cmd_raw = (e["cmd_line"].encode("utf-8") + b"\x00") if e["cmd_line"] else b""
        user_raw = (e["user"].encode("utf-8") + b"\x00") if e["user"] else b""
        payload += struct.pack(
            "<III B3s QQ HHH2s",
            e["pid"], e["ppid"], e["uid"],
            0x01 if e["is_target"] else 0x00,
            b"\x00" * 3,
            e["start_time_ns"], e["rss"],
            len(exe_raw), len(cmd_raw), len(user_raw),
            b"\x00" * 2,
        )
        if exe_raw:
            payload += exe_raw.ljust(_pad8(len(exe_raw)), b"\x00")
        if cmd_raw:
            payload += cmd_raw.ljust(_pad8(len(cmd_raw)), b"\x00")
        if user_raw:
            payload += user_raw.ljust(_pad8(len(user_raw)), b"\x00")
    return _build_block(0x0051, payload)


def _build_connection_table(entries=None):
    """Build Connection Table payload (type 0x0052, spec Table 22).

    Fixed 48-byte entries. Ports are packed as uint16 LE (NOT network order).
    """
    if entries is None:
        entries = [
            {
                "pid": 1234, "family": 0x02, "protocol": 0x06, "state": 0x01,
                "local_addr": b"\x7f\x00\x00\x01" + b"\x00" * 12,
                "local_port": 443,
                "remote_addr": b"\x08\x08\x08\x08" + b"\x00" * 12,
                "remote_port": 55123,
            },
            {
                "pid": 5678, "family": 0x0A, "protocol": 0x11, "state": 0x00,
                "local_addr": bytes.fromhex("20010db8000000000000000000000001"),
                "local_port": 5353,
                "remote_addr": b"\x00" * 16,
                "remote_port": 0,
            },
        ]
    payload = struct.pack("<II", len(entries), 0)
    for e in entries:
        local_addr = e["local_addr"].ljust(16, b"\x00")[:16]
        remote_addr = e["remote_addr"].ljust(16, b"\x00")[:16]
        payload += struct.pack(
            "<IBBB1s 16s H2s 16s H2s",
            e["pid"], e["family"], e["protocol"], e["state"],
            b"\x00",
            local_addr,
            e["local_port"],
            b"\x00" * 2,
            remote_addr,
            e["remote_port"],
            b"\x00" * 2,
        )
    return _build_block(0x0052, payload)


def _build_handle_table(entries=None):
    """Build Handle Table payload (type 0x0053, spec Table 24).

    Per-entry layout: PID(4) + FD(4) + HandleType(2) + PathLen(2) +
    Reserved(4) + Path(var UTF-8 padded). Default entries exercise File,
    Socket (empty-path edge case), and Other handle types.
    """
    if entries is None:
        entries = [
            {"pid": 1234, "fd": 3, "handle_type": 0x01, "path": "/var/log/target.log"},
            {"pid": 1234, "fd": 4, "handle_type": 0x03, "path": ""},
            {"pid": 5678, "fd": 0xFF, "handle_type": 0x07, "path": "HKLM\\Software\\Test"},
        ]
    payload = struct.pack("<II", len(entries), 0)
    for e in entries:
        path_raw = (e["path"].encode("utf-8") + b"\x00") if e["path"] else b""
        payload += struct.pack(
            "<IIHH4s",
            e["pid"], e["fd"], e["handle_type"],
            len(path_raw),
            b"\x00" * 4,
        )
        if path_raw:
            payload += path_raw.ljust(_pad8(len(path_raw)), b"\x00")
    return _build_block(0x0053, payload)


def _pack_conn_string(s: str) -> bytes:
    """Pack a uint16 length-prefixed UTF-8 string for a Connectivity row.

    Unlike Table 20 SYSTEM_CONTEXT strings, these are NOT 8-byte padded:
    they pack tight because the row's RowLen gives the explicit extent.
    Empty string => len=0, no body bytes.
    """
    if not s:
        return struct.pack("<H", 0)
    raw = s.encode("utf-8") + b"\x00"
    return struct.pack("<H", len(raw)) + raw


def _pack_conn_row(row_type: int, body: bytes) -> bytes:
    """Wrap a row body with its 3-byte tag header (RowType + RowLen)."""
    return struct.pack("<BH", row_type, len(body)) + body


def _build_connectivity_table(entries=None):
    """Build Connectivity Table payload (type 0x0055, spec Table 25).

    Default entries exercise all 7 row types (one of each).
    """
    if entries is None:
        entries = [
            # IPv4 route
            ("ipv4_route", {
                "iface": "eth0",
                "dest": b"\x00\x00\x00\x00",
                "gateway": b"\xc0\xa8\x01\x01",
                "mask": b"\x00\x00\x00\x00",
                "flags": 0x0003,
                "metric": 100,
                "mtu": 1500,
            }),
            # IPv6 route
            ("ipv6_route", {
                "iface": "eth0",
                "dest": b"\x00" * 16,
                "dest_prefix": 0,
                "next_hop": bytes.fromhex("fe80000000000000000000000000fffe"),
                "metric": 1,
                "flags": 0,
            }),
            # ARP entry
            ("arp_entry", {
                "family": 0x02,
                "ip": b"\xc0\xa8\x01\x05",
                "hw_type": 0x0001,
                "flags": 0x0002,
                "hw_addr": b"\xde\xad\xbe\xef\x00\x01",
                "iface": "eth0",
            }),
            # Packet socket
            ("packet_socket", {
                "pid": 1234,
                "inode": 98765,
                "proto": 0x0003,
                "iface_index": 2,
                "user": 1000,
                "mem": 4096,
            }),
            # Interface stats
            ("iface_stats", {
                "iface": "eth0",
                "rx_bytes": 123456789, "rx_pkts": 1000,
                "rx_err": 0, "rx_drop": 2,
                "tx_bytes": 987654321, "tx_pkts": 900,
                "tx_err": 0, "tx_drop": 0,
            }),
            # Socket-family aggregate
            ("socket_family_agg", {
                "family": 0x02,
                "in_use": 12, "alloc": 20, "mem": 81920,
            }),
            # MIB counter
            ("mib_counter", {
                "mib": "ip", "counter": "InReceives", "value": 500000,
            }),
        ]

    rows_blob = b""
    for kind, e in entries:
        if kind == "ipv4_route":
            body = _pack_conn_string(e["iface"])
            body += e["dest"] + e["gateway"] + e["mask"]
            body += struct.pack("<HII", e["flags"], e["metric"], e["mtu"])
            rows_blob += _pack_conn_row(0x01, body)
        elif kind == "ipv6_route":
            body = _pack_conn_string(e["iface"])
            body += e["dest"]
            body += struct.pack("<B", e["dest_prefix"])
            body += e["next_hop"]
            body += struct.pack("<II", e["metric"], e["flags"])
            rows_blob += _pack_conn_row(0x02, body)
        elif kind == "arp_entry":
            body = struct.pack("<B", e["family"])
            body += e["ip"]
            body += struct.pack("<HH", e["hw_type"], e["flags"])
            body += e["hw_addr"]
            body += _pack_conn_string(e["iface"])
            rows_blob += _pack_conn_row(0x03, body)
        elif kind == "packet_socket":
            body = struct.pack(
                "<IQHIIQ",
                e["pid"], e["inode"], e["proto"],
                e["iface_index"], e["user"], e["mem"],
            )
            rows_blob += _pack_conn_row(0x04, body)
        elif kind == "iface_stats":
            body = _pack_conn_string(e["iface"])
            body += struct.pack(
                "<8Q",
                e["rx_bytes"], e["rx_pkts"], e["rx_err"], e["rx_drop"],
                e["tx_bytes"], e["tx_pkts"], e["tx_err"], e["tx_drop"],
            )
            rows_blob += _pack_conn_row(0x05, body)
        elif kind == "socket_family_agg":
            body = struct.pack(
                "<BIIQ",
                e["family"], e["in_use"], e["alloc"], e["mem"],
            )
            rows_blob += _pack_conn_row(0x06, body)
        elif kind == "mib_counter":
            body = _pack_conn_string(e["mib"])
            body += _pack_conn_string(e["counter"])
            body += struct.pack("<Q", e["value"])
            rows_blob += _pack_conn_row(0x07, body)
        else:
            raise ValueError(f"Unknown connectivity row kind: {kind}")

    payload = struct.pack("<II", len(entries), 0) + rows_blob
    return _build_block(0x0055, payload)


# -- Ext decoder fixture builders (speculative layouts mirroring decoders_ext.py) --

def _build_thread_context(thread_id=0xDEAD, register_data=b"\xAA\xBB\xCC\xDD"):
    """Build Thread Context payload (type 0x0011) — speculative layout."""
    payload = struct.pack("<Q", thread_id) + register_data
    return _build_block(0x0011, payload)


def _build_file_descriptor(fd=7, path="/dev/null"):
    """Build File Descriptor payload (type 0x0012) — speculative layout."""
    path_raw = path.encode("utf-8") + b"\x00"
    path_padded = path_raw.ljust(_pad8(len(path_raw)), b"\x00")
    payload = struct.pack("<IH2x", fd, len(path_raw)) + path_padded
    return _build_block(0x0012, payload)


def _build_network_connection(local_port=443, remote_port=8080, protocol=0x06,
                              addresses=b"\x7f\x00\x00\x01"):
    """Build Network Connection payload (type 0x0013) — speculative layout."""
    payload = struct.pack("<HHH2x", local_port, remote_port, protocol) + addresses
    return _build_block(0x0013, payload)


def _build_environment_block(entries=None):
    """Build Environment Block payload (type 0x0014) — speculative layout."""
    if entries is None:
        entries = [("HOME", "/root"), ("PATH", "/usr/bin")]
    payload = struct.pack("<I", len(entries))
    for key, val in entries:
        key_raw = key.encode("utf-8")
        val_raw = val.encode("utf-8")
        payload += struct.pack("<HH", len(key_raw), len(val_raw))
        payload += key_raw.ljust(_pad8(len(key_raw)), b"\x00")
        payload += val_raw.ljust(_pad8(len(val_raw)), b"\x00")
    return _build_block(0x0014, payload)


def _build_security_token(token_type=3, token_data=b"\xCA\xFE\xBA\xBE"):
    """Build Security Token payload (type 0x0015) — speculative layout."""
    payload = struct.pack("<H2x", token_type) + token_data
    return _build_block(0x0015, payload)


def _build_system_context(
    boot_time_ns: int = 1_600_000_000_000_000_000,
    target_count: int = 1,
    table_bitmap: int = 0b111,  # ProcessTable | ConnectionTable | HandleTable
    acq_user: str = "examiner01",
    hostname: str = "server01",
    domain: str = "",
    os_detail: str = "Linux 6.1.0-18-amd64 #1 SMP Debian",
    case_ref: str = "",
    uptime_ns: int = 123456789,
    os_version: str = "Linux 6.1",
):
    """Build System Context payload (type 0x0050) per spec §6.2 Table 20.

    Emits the full Table 20 header + variable string tail, followed by the
    memdiver-local deviation tail (uptime_ns, os_version).
    """
    def _raw(s: str) -> bytes:
        return (s.encode("utf-8") + b"\x00") if s else b""

    acq_user_raw = _raw(acq_user)
    hostname_raw = _raw(hostname)
    domain_raw = _raw(domain)
    os_detail_raw = _raw(os_detail)
    case_ref_raw = _raw(case_ref)
    os_version_raw = _raw(os_version)

    # Fixed 32-byte header per Table 20
    payload = struct.pack(
        "<QIIHHHHH6x",
        boot_time_ns, target_count, table_bitmap,
        len(acq_user_raw), len(hostname_raw), len(domain_raw),
        len(os_detail_raw), len(case_ref_raw),
    )

    # Variable spec tail — omit Domain/CaseRef when length is 0
    if acq_user_raw:
        payload += acq_user_raw.ljust(_pad8(len(acq_user_raw)), b"\x00")
    if hostname_raw:
        payload += hostname_raw.ljust(_pad8(len(hostname_raw)), b"\x00")
    if domain_raw:
        payload += domain_raw.ljust(_pad8(len(domain_raw)), b"\x00")
    if os_detail_raw:
        payload += os_detail_raw.ljust(_pad8(len(os_detail_raw)), b"\x00")
    if case_ref_raw:
        payload += case_ref_raw.ljust(_pad8(len(case_ref_raw)), b"\x00")

    # Local deviation tail (memdiver-specific)
    payload += struct.pack("<QH6x", uptime_ns, len(os_version_raw))
    if os_version_raw:
        payload += os_version_raw.ljust(_pad8(len(os_version_raw)), b"\x00")

    return _build_block(0x0050, payload)


def _build_end_of_capture(acq_end_ns):
    """Build End-of-Capture payload (type 0x0FFF).

    The 32-byte file_hash slot is intentionally left as zeros for the
    raw struct.pack fixture path: these fixtures don't exercise the
    file-hash finalization performed by MslWriter.write(), so a zero
    digest is acceptable here. Tests that need a real file_hash should
    construct fixtures via MslWriter directly.
    """
    payload = struct.pack("<32sQ", b"\x00" * 32, acq_end_ns)
    return _build_block(0x0FFF, payload)


def generate_msl_file() -> bytes:
    """Build a complete valid MSL binary blob with test data.

    Contains: file header, process identity block, memory region block
    (1 page of deterministic data), key hint block, end-of-capture block.
    """
    global _RNG
    _RNG = random.Random(42)

    timestamp_ns = 1_700_000_000_000_000_000  # ~2023-11-14
    dump_uuid = _det_uuid()
    blob = _build_file_header(dump_uuid, timestamp_ns)

    # Block 0: Process Identity
    proc_block, _ = _build_process_identity()
    blob += proc_block

    # Block 1: Memory Region with deterministic page data
    rng_fill = random.Random(99)
    page_data = (
        b"\xAA" * 32 + b"\xBB" * 32
        + bytes(rng_fill.getrandbits(8) for _ in range(PAGE_SIZE - 64))
    )
    region_block, region_uuid = _build_memory_region(page_data=page_data)
    blob += region_block

    # Block 2: Module Entry
    mod_block, _ = _build_module_entry()
    blob += mod_block

    # Block 3: Key Hint referencing the memory region
    hint_block, _ = _build_key_hint(region_uuid)
    blob += hint_block

    # Block 4: Related Dump
    rel_block, _ = _build_related_dump()
    blob += rel_block

    # Block 5: VAS Map
    vas_block, _ = _build_vas_map()
    blob += vas_block

    # Block 6-9: New spec-defined table decoders (MSL-Decoders-02)
    mli_block, _ = _build_module_list_index()
    blob += mli_block

    proc_tbl_block, _ = _build_process_table()
    blob += proc_tbl_block

    conn_tbl_block, _ = _build_connection_table()
    blob += conn_tbl_block

    hnd_tbl_block, _ = _build_handle_table()
    blob += hnd_tbl_block

    # Connectivity Table (0x0055) — spec §6.6 Tables 25, 26
    conn_block, _ = _build_connectivity_table()
    blob += conn_block

    # Block 10-15: Ext decoder blocks (speculative layouts; see decoders_ext.py).
    # Real producers MUST NOT emit 0x0011-0x0015 per spec §4.3 — these exist
    # only for round-trip testing of memdiver's guess decoders.
    tc_block, _ = _build_thread_context()
    blob += tc_block

    fd_block, _ = _build_file_descriptor()
    blob += fd_block

    nc_block, _ = _build_network_connection()
    blob += nc_block

    env_block, _ = _build_environment_block()
    blob += env_block

    st_block, _ = _build_security_token()
    blob += st_block

    sc_block, _ = _build_system_context()
    blob += sc_block

    # Final block: End-of-Capture
    eoc_block, _ = _build_end_of_capture(timestamp_ns + 1_000_000_000)
    blob += eoc_block

    return blob


def write_msl_fixture(path: Path) -> Path:
    """Write the generated MSL blob to a file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(generate_msl_file())
    return path


def ensure_msl_fixtures(root: Path) -> Path:
    """Create MSL fixtures under root if they don't exist. Idempotent."""
    root = Path(root)
    fixture_path = root / "msl" / "test_capture.msl"
    if fixture_path.exists():
        return root
    write_msl_fixture(fixture_path)
    return root


def _build_compressed_block(block_type, payload, algo="zstd"):
    """Build an MSL block with compressed payload.

    algo: 'zstd' or 'lz4'. Returns None if compression lib unavailable.
    """
    if algo == "zstd":
        try:
            import zstandard
            compressed = zstandard.ZstdCompressor().compress(payload)
            flags = 0x01 | 0x02  # COMPRESSED | COMP_ZSTD
        except ImportError:
            return None
    elif algo == "lz4":
        try:
            import lz4.frame
            compressed = lz4.frame.compress(payload)
            flags = 0x01 | 0x04  # COMPRESSED | COMP_LZ4
        except ImportError:
            return None
    else:
        return None

    block_length = BLOCK_HEADER_SIZE + len(compressed)
    header = bytearray(BLOCK_HEADER_SIZE)
    header[0:4] = BLOCK_MAGIC
    struct.pack_into("<H", header, 4, block_type)
    struct.pack_into("<H", header, 6, flags)
    struct.pack_into("<I", header, 8, block_length)
    struct.pack_into("<H", header, 0x0C, 1)  # payload_version
    header[0x10:0x20] = uuid.UUID(int=99).bytes
    header[0x20:0x30] = uuid.UUID(int=0).bytes
    header[0x30:0x50] = b"\x00" * 32
    return bytes(header) + compressed


def write_compressed_msl_fixture(path, algo="zstd"):
    """Write an MSL file with one compressed MEMORY_REGION block.

    Returns the path on success, or None if the compression lib is
    unavailable.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build the memory region payload (uncompressed form)
    base_addr = 0x7FFF00000000
    num_pages = 1
    region_size = num_pages * PAGE_SIZE
    bitmap_padded = _pad8(((num_pages * 2) + 7) // 8)
    page_map = b"\x00" * bitmap_padded  # all CAPTURED

    rng_fill = random.Random(77)
    page_data = (
        b"\xCC" * 32 + b"\xDD" * 32
        + bytes(rng_fill.getrandbits(8) for _ in range(PAGE_SIZE - 64))
    )

    region_payload = struct.pack(
        "<QQBBB5xQ",
        base_addr, region_size,
        0x07, 0x01, PAGE_SIZE_LOG2, 0,
    )
    region_payload += page_map + page_data

    compressed_block = _build_compressed_block(
        0x0001, region_payload, algo=algo,
    )
    if compressed_block is None:
        return None

    # Assemble: file header + compressed block
    global _RNG
    _RNG = random.Random(42)
    dump_uuid = _det_uuid()
    timestamp_ns = 1_700_000_000_000_000_000
    blob = _build_file_header(dump_uuid, timestamp_ns)
    blob += compressed_block

    path.write_bytes(blob)
    return path


def write_aslr_fixture(
    path: Path,
    *,
    region_base: int,
    key_offset: int = 0x200,
    key_bytes: bytes = b"\x00" * 32,
    filler_byte: int = 0x42,
) -> Path:
    """Write a minimal native MSL fixture with a key at a fixed region offset.

    The fixture contains only a file header (flags=0 → native) and a single
    1-page memory region whose virtual base is `region_base`. The page is
    `filler_byte` everywhere except `key_bytes` at `key_offset`.

    Used by the ASLR regression test: writing multiple fixtures with
    *different* `region_base` values but different `key_bytes` simulates an
    ASLR-shifted capture where the key lives at the same region-relative
    offset across runs. UUIDs and timestamps are held constant (RNG reseeded)
    so that ONLY `region_base` and `key_bytes` vary between fixtures — this
    keeps the flat-bytes baseline deterministic for comparison.
    """
    global _RNG
    _RNG = random.Random(42)  # deterministic UUIDs across every call

    if len(key_bytes) == 0:
        raise ValueError("key_bytes must be non-empty")
    if key_offset < 0 or key_offset + len(key_bytes) > PAGE_SIZE:
        raise ValueError(
            f"key at offset {key_offset} length {len(key_bytes)} does not fit in page"
        )

    timestamp_ns = 1_700_000_000_000_000_000
    dump_uuid = _det_uuid()

    page = bytearray([filler_byte & 0xFF]) * PAGE_SIZE
    page[key_offset:key_offset + len(key_bytes)] = key_bytes

    blob = _build_file_header(dump_uuid, timestamp_ns)
    region_block, _ = _build_memory_region(
        base_addr=region_base, num_pages=1, page_data=bytes(page),
    )
    blob += region_block

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


if __name__ == "__main__":
    out = write_msl_fixture(Path(__file__).parent / "dataset" / "msl" / "test_capture.msl")
    print(f"MSL fixture written to: {out} ({out.stat().st_size} bytes)")
