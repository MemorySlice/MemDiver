"""Block payload decoders for MSL block types.

Stateless functions that parse raw payload bytes into typed dataclasses.
Separated from reader.py to keep each file under 200 lines.
"""

import struct
from typing import Callable, Dict, Optional
from uuid import UUID

from .enums import BlockType, ConnRowType
from .page_map import decode_page_intervals, decode_page_state_map
from .types import (
    MslBlockHeader,
    MslConnArpEntry,
    MslConnectionEntry,
    MslConnectionTable,
    MslConnectivityTable,
    MslConnIfaceStats,
    MslConnIPv4Route,
    MslConnIPv6Route,
    MslConnMibCounter,
    MslConnPacketSocket,
    MslConnSocketFamilyAgg,
    MslEndOfCapture,
    MslHandleEntry,
    MslHandleTable,
    MslImportProvenance,
    MslKeyHint,
    MslMemoryRegion,
    MslModuleEntry,
    MslModuleIndexEntry,
    MslModuleListIndex,
    MslParseError,
    MslProcessEntry,
    MslProcessIdentity,
    MslProcessTable,
    MslRelatedDump,
    MslVasEntry,
    MslVasMap,
)


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _read_padded_str(buf: bytes, offset: int, length: int) -> str:
    if length <= 0:
        return ""
    raw = buf[offset:offset + length]
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def decode_memory_region(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslMemoryRegion:
    """Decode Memory Region payload (type 0x0001, spec Table 11)."""
    bo = byte_order
    base_addr = struct.unpack_from(f"{bo}Q", payload, 0)[0]
    region_size = struct.unpack_from(f"{bo}Q", payload, 8)[0]
    protection = payload[0x10]
    region_type = payload[0x11]
    page_size_log2 = payload[0x12]
    timestamp_ns = struct.unpack_from(f"{bo}Q", payload, 0x18)[0]
    page_size = 1 << page_size_log2
    num_pages = region_size // page_size if page_size > 0 else 0
    map_bytes = _pad8((num_pages + 3) // 4)
    map_data = payload[0x20:0x20 + map_bytes]
    intervals = decode_page_intervals(map_data, num_pages)
    page_states = decode_page_state_map(map_data, num_pages)
    return MslMemoryRegion(
        block_header=hdr, base_addr=base_addr,
        region_size=region_size, protection=protection,
        region_type=region_type, page_size_log2=page_size_log2,
        timestamp_ns=timestamp_ns,
        page_intervals=intervals, page_states=page_states,
    )


def decode_key_hint(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslKeyHint:
    """Decode Key Hint payload (type 0x0020, spec Table 16)."""
    bo = byte_order
    region_uuid = UUID(bytes=payload[0:16])
    region_offset = struct.unpack_from(f"{bo}Q", payload, 0x10)[0]
    key_length = struct.unpack_from(f"{bo}I", payload, 0x18)[0]
    key_type = struct.unpack_from(f"{bo}H", payload, 0x1C)[0]
    protocol = struct.unpack_from(f"{bo}H", payload, 0x1E)[0]
    confidence = payload[0x20]
    key_state = payload[0x21]
    note_len = struct.unpack_from(f"{bo}I", payload, 0x24)[0]
    note = _read_padded_str(payload, 0x2C, note_len) if note_len > 0 else ""
    return MslKeyHint(
        block_header=hdr, region_uuid=region_uuid,
        region_offset=region_offset, key_length=key_length,
        key_type=key_type, protocol=protocol,
        confidence=confidence, key_state=key_state, note=note,
    )


def decode_process_identity(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslProcessIdentity:
    """Decode Process Identity payload (type 0x0040, spec Table 14)."""
    bo = byte_order
    ppid = struct.unpack_from(f"{bo}I", payload, 0)[0]
    session_id = struct.unpack_from(f"{bo}I", payload, 4)[0]
    start_time = struct.unpack_from(f"{bo}Q", payload, 8)[0]
    exe_path_len = struct.unpack_from(f"{bo}H", payload, 0x10)[0]
    cmd_line_len = struct.unpack_from(f"{bo}H", payload, 0x12)[0]
    offset = 0x18
    exe_path = _read_padded_str(payload, offset, exe_path_len)
    offset += _pad8(exe_path_len)
    cmd_line = _read_padded_str(payload, offset, cmd_line_len)
    return MslProcessIdentity(
        block_header=hdr, ppid=ppid, session_id=session_id,
        start_time_ns=start_time, exe_path=exe_path, cmd_line=cmd_line,
    )


def decode_end_of_capture(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslEndOfCapture:
    """Decode End-of-Capture payload (type 0x0FFF, spec Table 10)."""
    bo = byte_order
    file_hash = payload[0:32]
    acq_end = struct.unpack_from(f"{bo}Q", payload, 0x20)[0]
    return MslEndOfCapture(
        block_header=hdr, file_hash=bytes(file_hash), acq_end_ns=acq_end,
    )


def decode_module_entry(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslModuleEntry:
    """Decode Module Entry payload (type 0x0002, spec Table 12)."""
    bo = byte_order
    base_addr = struct.unpack_from(f"{bo}Q", payload, 0)[0]
    module_size = struct.unpack_from(f"{bo}Q", payload, 8)[0]
    path_len = struct.unpack_from(f"{bo}H", payload, 0x10)[0]
    version_len = struct.unpack_from(f"{bo}H", payload, 0x12)[0]
    offset = 0x18
    path = _read_padded_str(payload, offset, path_len)
    offset += _pad8(path_len)
    version = _read_padded_str(payload, offset, version_len)
    offset += _pad8(version_len)
    disk_hash = bytes(payload[offset:offset + 32])
    return MslModuleEntry(
        block_header=hdr, base_addr=base_addr,
        module_size=module_size, path=path,
        version=version, disk_hash=disk_hash,
    )


def decode_related_dump(hdr: MslBlockHeader, payload: bytes, byte_order: str) -> MslRelatedDump:
    """Decode Related Dump payload (type 0x0041, spec Table 15).

    Layout (56 bytes):
        0x00 uuid[16]   related_dump_uuid
        0x10 uint32     related_pid
        0x14 uint16     relationship
        0x16 uint16     reserved
        0x18 bytes[32]  target_hash  (BLAKE3 digest of target file)

    Pre-C1 fixtures (24-byte payload without target_hash) are accepted:
    target_hash defaults to 32 zero bytes.
    """
    bo = byte_order
    related_uuid = UUID(bytes=payload[0:16])
    related_pid = struct.unpack_from(f"{bo}I", payload, 0x10)[0]
    relationship = struct.unpack_from(f"{bo}H", payload, 0x14)[0]
    if len(payload) >= 0x18 + 32:
        target_hash = bytes(payload[0x18:0x18 + 32])
    else:
        target_hash = b"\x00" * 32
    return MslRelatedDump(
        block_header=hdr, related_dump_uuid=related_uuid,
        related_pid=related_pid, relationship=relationship,
        target_hash=target_hash,
    )


def decode_vas_map(hdr: MslBlockHeader, payload: bytes, byte_order: str) -> MslVasMap:
    """Decode VAS Map payload (type 0x1001)."""
    bo = byte_order
    entry_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    entry_size = struct.unpack_from(f"{bo}I", payload, 4)[0]
    entries = []
    offset = 8
    for _ in range(entry_count):
        base_addr = struct.unpack_from(f"{bo}Q", payload, offset)[0]
        region_size = struct.unpack_from(f"{bo}Q", payload, offset + 8)[0]
        protection = payload[offset + 0x10]
        region_type = payload[offset + 0x11]
        path_len = struct.unpack_from(f"{bo}H", payload, offset + 0x12)[0]
        # 4 bytes padding at offset+0x14
        path = _read_padded_str(payload, offset + 0x18, path_len)
        entries.append(MslVasEntry(
            base_addr=base_addr, region_size=region_size,
            protection=protection, region_type=region_type,
            mapped_path=path,
        ))
        if entry_size > 0:
            offset += entry_size
        else:
            offset += 0x18 + _pad8(path_len)
    return MslVasMap(
        block_header=hdr, entry_count=entry_count, entries=entries,
    )


def _advance_str(raw_len: int) -> int:
    """How many bytes a string field of raw length *raw_len* consumes.

    Writer pads each string independently: Len=0 → 0 bytes follow, Len≥1 → pad8.
    """
    return 0 if raw_len == 0 else _pad8(raw_len)


def _require(payload: bytes, end: int, ctx: str) -> None:
    if end > len(payload):
        raise MslParseError(
            f"Truncated {ctx}: needs {end} bytes, payload has {len(payload)}"
        )


def decode_module_list_index(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslModuleListIndex:
    """Decode Module List Index payload (type 0x0010, spec Table 15).

    Two real-world variants exist:
    - Inline: 8-byte header followed by `entry_count` inline entries. This is
      the memslicer reference writer's layout (spec Table 15).
    - Manifest-only: just the 8-byte header. `entry_count` advertises how
      many MODULE_ENTRY (0x0002) blocks exist separately in the file. Chrome
      memslicer uses this variant.

    We handle both: if the payload is exactly 8 bytes we treat it as manifest
    mode and return an empty entries tuple. Corruption (partial entries after
    the 8-byte header) still raises MslParseError.
    """
    bo = byte_order
    _require(payload, 8, "MODULE_LIST_INDEX header")
    entry_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    # reserved u32 at offset 4
    if len(payload) == 8:
        # Manifest-only variant (Chrome-style): no inline entries.
        return MslModuleListIndex(
            block_header=hdr, entry_count=entry_count, entries=(),
        )
    offset = 8
    entries = []
    for idx in range(entry_count):
        _require(payload, offset + 0x28, f"MODULE_LIST_INDEX entry {idx}")
        module_uuid = UUID(bytes=bytes(payload[offset:offset + 16]))
        base_addr = struct.unpack_from(f"{bo}Q", payload, offset + 0x10)[0]
        module_size = struct.unpack_from(f"{bo}Q", payload, offset + 0x18)[0]
        path_len = struct.unpack_from(f"{bo}H", payload, offset + 0x20)[0]
        # +0x22 reserved u16, +0x24 reserved u32
        str_offset = offset + 0x28
        _require(payload, str_offset + _advance_str(path_len), f"MODULE_LIST_INDEX entry {idx} path")
        path = _read_padded_str(payload, str_offset, path_len)
        entries.append(MslModuleIndexEntry(
            module_uuid=module_uuid, base_addr=base_addr,
            module_size=module_size, path=path,
        ))
        offset = str_offset + _advance_str(path_len)
    return MslModuleListIndex(
        block_header=hdr, entry_count=entry_count, entries=tuple(entries),
    )


def decode_process_table(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslProcessTable:
    """Decode Process Table payload (type 0x0051, spec Table 21)."""
    bo = byte_order
    _require(payload, 8, "PROCESS_TABLE header")
    entry_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    offset = 8
    entries = []
    for idx in range(entry_count):
        _require(payload, offset + 0x28, f"PROCESS_TABLE entry {idx}")
        pid = struct.unpack_from(f"{bo}I", payload, offset + 0x00)[0]
        ppid = struct.unpack_from(f"{bo}I", payload, offset + 0x04)[0]
        uid = struct.unpack_from(f"{bo}I", payload, offset + 0x08)[0]
        is_target = payload[offset + 0x0C] == 0x01
        # +0x0D reserved 3 bytes
        start_time_ns = struct.unpack_from(f"{bo}Q", payload, offset + 0x10)[0]
        rss = struct.unpack_from(f"{bo}Q", payload, offset + 0x18)[0]
        exe_len = struct.unpack_from(f"{bo}H", payload, offset + 0x20)[0]
        cmd_len = struct.unpack_from(f"{bo}H", payload, offset + 0x22)[0]
        user_len = struct.unpack_from(f"{bo}H", payload, offset + 0x24)[0]
        # +0x26 reserved u16
        str_offset = offset + 0x28
        exe_adv = _advance_str(exe_len)
        cmd_adv = _advance_str(cmd_len)
        user_adv = _advance_str(user_len)
        _require(
            payload,
            str_offset + exe_adv + cmd_adv + user_adv,
            f"PROCESS_TABLE entry {idx} strings",
        )
        exe_name = _read_padded_str(payload, str_offset, exe_len)
        cmd_off = str_offset + exe_adv
        cmd_line = _read_padded_str(payload, cmd_off, cmd_len)
        user_off = cmd_off + cmd_adv
        user = _read_padded_str(payload, user_off, user_len)
        entries.append(MslProcessEntry(
            pid=pid, ppid=ppid, uid=uid, is_target=is_target,
            start_time_ns=start_time_ns, rss=rss,
            exe_name=exe_name, cmd_line=cmd_line, user=user,
        ))
        offset = user_off + user_adv
    return MslProcessTable(
        block_header=hdr, entry_count=entry_count, entries=tuple(entries),
    )


def decode_connection_table(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslConnectionTable:
    """Decode Connection Table payload (type 0x0052, spec Table 22).

    Fixed 48-byte entries. Ports are uint16 little-endian (NOT network order).
    """
    bo = byte_order
    _require(payload, 8, "CONNECTION_TABLE header")
    entry_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    offset = 8
    entries = []
    entry_size = 48
    for idx in range(entry_count):
        _require(payload, offset + entry_size, f"CONNECTION_TABLE entry {idx}")
        pid = struct.unpack_from(f"{bo}I", payload, offset + 0x00)[0]
        family = payload[offset + 0x04]
        protocol = payload[offset + 0x05]
        state = payload[offset + 0x06]
        # +0x07 reserved u8
        local_addr = bytes(payload[offset + 0x08:offset + 0x18])
        local_port = struct.unpack_from(f"{bo}H", payload, offset + 0x18)[0]
        # +0x1A reserved u16
        remote_addr = bytes(payload[offset + 0x1C:offset + 0x2C])
        remote_port = struct.unpack_from(f"{bo}H", payload, offset + 0x2C)[0]
        # +0x2E reserved u16
        entries.append(MslConnectionEntry(
            pid=pid, family=family, protocol=protocol, state=state,
            local_addr=local_addr, local_port=local_port,
            remote_addr=remote_addr, remote_port=remote_port,
        ))
        offset += entry_size
    return MslConnectionTable(
        block_header=hdr, entry_count=entry_count, entries=tuple(entries),
    )


def decode_handle_table(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslHandleTable:
    """Decode Handle Table payload (type 0x0053, spec Table 24).

    Per-entry layout: PID(4) + FD(4) + HandleType(2) + PathLen(2) +
    Reserved(4) + Path(var, UTF-8 padded). HandleType is a uint16 enum
    (0x00=Unknown, 0x01=File, 0x02=Dir, 0x03=Socket, 0x04=Pipe,
    0x05=Mutex, 0x06=Timer, 0x07=Other).
    """
    bo = byte_order
    _require(payload, 8, "HANDLE_TABLE header")
    entry_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    offset = 8
    entries = []
    for idx in range(entry_count):
        _require(payload, offset + 0x10, f"HANDLE_TABLE entry {idx}")
        pid = struct.unpack_from(f"{bo}I", payload, offset + 0x00)[0]
        fd = struct.unpack_from(f"{bo}I", payload, offset + 0x04)[0]
        handle_type = struct.unpack_from(f"{bo}H", payload, offset + 0x08)[0]
        path_len = struct.unpack_from(f"{bo}H", payload, offset + 0x0A)[0]
        # +0x0C reserved u32
        str_offset = offset + 0x10
        path_adv = _advance_str(path_len)
        _require(payload, str_offset + path_adv, f"HANDLE_TABLE entry {idx} path")
        path = _read_padded_str(payload, str_offset, path_len)
        entries.append(MslHandleEntry(
            pid=pid, fd=fd, handle_type=handle_type, path=path,
        ))
        offset = str_offset + path_adv
    return MslHandleTable(
        block_header=hdr, entry_count=entry_count, entries=tuple(entries),
    )


def _read_conn_str(payload: bytes, offset: int, ctx: str) -> tuple:
    """Read a uint16 length-prefixed UTF-8 string inside a Connectivity row.

    Unlike spec Table 20 strings, these are NOT 8-byte aligned — the row's
    RowLen gives the explicit extent, so strings pack tight. Returns
    (decoded_str, next_offset).
    """
    _require(payload, offset + 2, f"{ctx} str length")
    raw_len = struct.unpack_from("<H", payload, offset)[0]
    start = offset + 2
    end = start + raw_len
    _require(payload, end, f"{ctx} str body")
    return _read_padded_str(payload, start, raw_len), end


def _check_row_fits(cur: int, row_end: int, row_name: str) -> None:
    """Assert the row-decoder cursor did not advance past the declared RowLen."""
    if cur > row_end:
        raise MslParseError(f"{row_name} overruns RowLen")


def _decode_conn_ipv4_route(payload, offset, row_len, bo) -> MslConnIPv4Route:
    end = offset + row_len
    iface, cur = _read_conn_str(payload, offset, "IPV4_ROUTE iface")
    _require(payload, cur + 4 + 4 + 4 + 2 + 4 + 4, "IPV4_ROUTE body")
    dest = bytes(payload[cur:cur + 4]); cur += 4
    gateway = bytes(payload[cur:cur + 4]); cur += 4
    mask = bytes(payload[cur:cur + 4]); cur += 4
    flags = struct.unpack_from(f"{bo}H", payload, cur)[0]; cur += 2
    metric = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    mtu = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    _check_row_fits(cur, end, "IPV4_ROUTE")
    return MslConnIPv4Route(
        iface=iface, dest=dest, gateway=gateway, mask=mask,
        flags=flags, metric=metric, mtu=mtu,
    )


def _decode_conn_ipv6_route(payload, offset, row_len, bo) -> MslConnIPv6Route:
    end = offset + row_len
    iface, cur = _read_conn_str(payload, offset, "IPV6_ROUTE iface")
    _require(payload, cur + 16 + 1 + 16 + 4 + 4, "IPV6_ROUTE body")
    dest = bytes(payload[cur:cur + 16]); cur += 16
    dest_prefix = payload[cur]; cur += 1
    next_hop = bytes(payload[cur:cur + 16]); cur += 16
    metric = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    flags = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    _check_row_fits(cur, end, "IPV6_ROUTE")
    return MslConnIPv6Route(
        iface=iface, dest=dest, dest_prefix=dest_prefix,
        next_hop=next_hop, metric=metric, flags=flags,
    )


def _decode_conn_arp_entry(payload, offset, row_len, bo) -> MslConnArpEntry:
    end = offset + row_len
    _require(payload, offset + 1 + 4 + 2 + 2 + 6, "ARP_ENTRY fixed")
    family = payload[offset]
    cur = offset + 1
    ip = bytes(payload[cur:cur + 4]); cur += 4
    hw_type = struct.unpack_from(f"{bo}H", payload, cur)[0]; cur += 2
    flags = struct.unpack_from(f"{bo}H", payload, cur)[0]; cur += 2
    hw_addr = bytes(payload[cur:cur + 6]); cur += 6
    iface, cur = _read_conn_str(payload, cur, "ARP_ENTRY iface")
    _check_row_fits(cur, end, "ARP_ENTRY")
    return MslConnArpEntry(
        family=family, ip=ip, hw_type=hw_type, flags=flags,
        hw_addr=hw_addr, iface=iface,
    )


def _decode_conn_packet_socket(payload, offset, row_len, bo) -> MslConnPacketSocket:
    end = offset + row_len
    _require(payload, offset + 4 + 8 + 2 + 4 + 4 + 8, "PACKET_SOCKET body")
    cur = offset
    pid = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    inode = struct.unpack_from(f"{bo}Q", payload, cur)[0]; cur += 8
    proto = struct.unpack_from(f"{bo}H", payload, cur)[0]; cur += 2
    iface_index = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    user = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    mem = struct.unpack_from(f"{bo}Q", payload, cur)[0]; cur += 8
    _check_row_fits(cur, end, "PACKET_SOCKET")
    return MslConnPacketSocket(
        pid=pid, inode=inode, proto=proto,
        iface_index=iface_index, user=user, mem=mem,
    )


def _decode_conn_iface_stats(payload, offset, row_len, bo) -> MslConnIfaceStats:
    end = offset + row_len
    iface, cur = _read_conn_str(payload, offset, "IFACE_STATS iface")
    _require(payload, cur + 8 * 8, "IFACE_STATS counters")
    vals = struct.unpack_from(f"{bo}8Q", payload, cur)
    cur += 8 * 8
    _check_row_fits(cur, end, "IFACE_STATS")
    return MslConnIfaceStats(
        iface=iface,
        rx_bytes=vals[0], rx_pkts=vals[1], rx_err=vals[2], rx_drop=vals[3],
        tx_bytes=vals[4], tx_pkts=vals[5], tx_err=vals[6], tx_drop=vals[7],
    )


def _decode_conn_socket_family_agg(payload, offset, row_len, bo) -> MslConnSocketFamilyAgg:
    end = offset + row_len
    _require(payload, offset + 1 + 4 + 4 + 8, "SOCKET_FAMILY_AGG body")
    cur = offset
    family = payload[cur]; cur += 1
    in_use = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    alloc = struct.unpack_from(f"{bo}I", payload, cur)[0]; cur += 4
    mem = struct.unpack_from(f"{bo}Q", payload, cur)[0]; cur += 8
    _check_row_fits(cur, end, "SOCKET_FAMILY_AGG")
    return MslConnSocketFamilyAgg(
        family=family, in_use=in_use, alloc=alloc, mem=mem,
    )


def _decode_conn_mib_counter(payload, offset, row_len, bo) -> MslConnMibCounter:
    end = offset + row_len
    mib, cur = _read_conn_str(payload, offset, "MIB_COUNTER mib")
    counter, cur = _read_conn_str(payload, cur, "MIB_COUNTER counter")
    _require(payload, cur + 8, "MIB_COUNTER value")
    value = struct.unpack_from(f"{bo}Q", payload, cur)[0]
    cur += 8
    _check_row_fits(cur, end, "MIB_COUNTER")
    return MslConnMibCounter(mib=mib, counter=counter, value=value)


_CONN_ROW_DISPATCH: Dict[int, Callable] = {
    ConnRowType.IPV4_ROUTE: _decode_conn_ipv4_route,
    ConnRowType.IPV6_ROUTE: _decode_conn_ipv6_route,
    ConnRowType.ARP_ENTRY: _decode_conn_arp_entry,
    ConnRowType.PACKET_SOCKET: _decode_conn_packet_socket,
    ConnRowType.IFACE_STATS: _decode_conn_iface_stats,
    ConnRowType.SOCKET_FAMILY_AGG: _decode_conn_socket_family_agg,
    ConnRowType.MIB_COUNTER: _decode_conn_mib_counter,
}


def decode_connectivity_table(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslConnectivityTable:
    """Decode Connectivity Table payload (type 0x0055, spec Table 25).

    Heterogeneous tagged-row format. Each row starts with
    ``RowType(B) + RowLen(H)`` followed by RowLen body bytes. Unknown row
    types are silently skipped per the forward-compat rule in spec §6.6
    — the cursor advances by ``3 + row_len`` regardless.
    """
    bo = byte_order
    _require(payload, 8, "CONNECTIVITY_TABLE header")
    row_count = struct.unpack_from(f"{bo}I", payload, 0)[0]
    # +0x04 Reserved u32
    offset = 8
    rows = []
    for idx in range(row_count):
        _require(payload, offset + 3, f"CONNECTIVITY_TABLE row {idx} tag")
        row_type = payload[offset]
        row_len = struct.unpack_from(f"{bo}H", payload, offset + 1)[0]
        body_start = offset + 3
        _require(payload, body_start + row_len, f"CONNECTIVITY_TABLE row {idx} body")
        decoder = _CONN_ROW_DISPATCH.get(row_type)
        if decoder is not None:
            rows.append(decoder(payload, body_start, row_len, bo))
        # Unknown row types: silently skip — forward-compat rule §6.6
        offset = body_start + row_len
    return MslConnectivityTable(
        block_header=hdr, row_count=row_count, rows=tuple(rows),
    )


def decode_import_provenance(
    hdr: MslBlockHeader, payload: bytes, byte_order: str
) -> MslImportProvenance:
    """Decode Import Provenance payload (type 0x0030, spec Table 26)."""
    bo = byte_order
    source_format = struct.unpack_from(f"{bo}H", payload, 0)[0]
    tool_name_len = struct.unpack_from(f"{bo}I", payload, 4)[0]
    import_time = struct.unpack_from(f"{bo}Q", payload, 8)[0]
    orig_size = struct.unpack_from(f"{bo}Q", payload, 0x10)[0]
    note_len = struct.unpack_from(f"{bo}I", payload, 0x18)[0]
    offset = 0x20
    tool_name = _read_padded_str(payload, offset, tool_name_len)
    offset += _pad8(tool_name_len)
    note = _read_padded_str(payload, offset, note_len) if note_len > 0 else ""
    # source_hash sits 8-byte-aligned past the note; for note_len==0 there
    # are no bytes for the note string, so the hash starts at `offset`.
    hash_offset = offset + (_pad8(note_len) if note_len > 0 else 0)
    if len(payload) >= hash_offset + 32:
        source_hash = bytes(payload[hash_offset:hash_offset + 32])
    else:
        source_hash = b"\x00" * 32
    return MslImportProvenance(
        block_header=hdr, source_format=source_format,
        tool_name=tool_name, import_time_ns=import_time,
        orig_file_size=orig_size, note=note, source_hash=source_hash,
    )
