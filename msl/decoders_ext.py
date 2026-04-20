"""Extended block decoders for additional MSL block types.

WARNING — SPECULATIVE LAYOUTS
-----------------------------
The decoders for block types 0x0011 (THREAD_CONTEXT), 0x0012 (FILE_DESCRIPTOR),
0x0013 (NETWORK_CONNECTION), 0x0014 (ENVIRONMENT_BLOCK), and 0x0015
(SECURITY_TOKEN) use GUESSED layouts — the MSL v1.1 specification (§4.3, Table 9)
RESERVES these type codes and explicitly states that producers MUST NOT emit
them until their payloads are defined in a future spec version. Conformant MSL
files therefore never contain them, and the layouts below have not been
validated against any authoritative reference.

If/when spec ≥ v1.2 defines these block types, re-verify every decoder in this
file against the new spec tables and update both the layouts and any tests.
Until then, these decoders are latent: `MslReader.collect_*()` methods will
return empty lists on real captures, and any non-empty result must be treated
as speculative. The SYSTEM_CONTEXT (0x0050) decoder implements the full spec
§6.2 Table 20 layout (BootTime, TargetCount, TableBitmap, AcqUser, Hostname,
Domain, OSDetail, CaseRef). Two memdiver-local deviation fields (`uptime_ns`,
`os_version`) are appended at the payload tail for clock-skew insurance and
short OS label retention; pure-spec readers stop at block_header.length
after CaseRef and ignore the deviation tail.

All decoders here wrap the layout logic in try/except and fall back to
MslGenericBlock on any failure. This is the correct strategy for guessed
layouts, because the alternative (hard failure) would reject any conformant
real-world data that uses a future layout we haven't seen yet.
"""

import logging
import struct
from dataclasses import dataclass
from typing import List

from .enums import BlockType
from .types import MslBlockHeader, MslGenericBlock

logger = logging.getLogger("memdiver.msl.decoders_ext")


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _read_padded_str(buf: bytes, offset: int, length: int) -> str:
    if length <= 0:
        return ""
    return buf[offset:offset + length].split(b"\x00", 1)[0].decode("utf-8", errors="replace")

# -- Extended dataclasses --

@dataclass(frozen=True)
class MslThreadContext:
    block_header: MslBlockHeader
    thread_id: int
    register_data: bytes  # raw register snapshot


@dataclass(frozen=True)
class MslFileDescriptor:
    block_header: MslBlockHeader
    fd: int
    path: str


@dataclass(frozen=True)
class MslNetworkConnection:
    block_header: MslBlockHeader
    local_port: int
    remote_port: int
    protocol: int
    addresses: bytes  # raw addr data


@dataclass(frozen=True)
class MslEnvironmentBlock:
    block_header: MslBlockHeader
    entries: dict  # key -> value


@dataclass(frozen=True)
class MslSecurityToken:
    block_header: MslBlockHeader
    token_type: int
    token_data: bytes


@dataclass(frozen=True)
class MslSystemContext:
    """SYSTEM_CONTEXT block (0x0050) — spec §6.2 Table 20 + memdiver deviation tail.

    Spec fields: boot_time_ns, target_count, table_bitmap, acq_user, hostname,
    domain, os_detail, case_ref.
    Local deviation fields (non-spec): uptime_ns, os_version.
    """
    block_header: MslBlockHeader
    # Spec Table 20 fields
    boot_time_ns: int
    target_count: int
    table_bitmap: int
    acq_user: str
    hostname: str
    domain: str
    os_detail: str
    case_ref: str
    # Local deviation tail (memdiver-specific, not in spec)
    uptime_ns: int
    os_version: str


# -- Decoders --

def decode_generic(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> MslGenericBlock:
    """Capture raw payload as a generic block."""
    return MslGenericBlock(block_header=hdr, payload=bytes(payload))


def decode_thread_context(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslThreadContext | MslGenericBlock":
    """Decode Thread Context payload (type 0x0011)."""
    try:
        bo = byte_order
        thread_id = struct.unpack_from(f"{bo}Q", payload, 0)[0]
        register_data = bytes(payload[8:])
        return MslThreadContext(
            block_header=hdr, thread_id=thread_id,
            register_data=register_data,
        )
    except Exception:
        return decode_generic(hdr, payload, byte_order)


def decode_file_descriptor(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslFileDescriptor | MslGenericBlock":
    """Decode File Descriptor payload (type 0x0012)."""
    try:
        bo = byte_order
        fd = struct.unpack_from(f"{bo}I", payload, 0)[0]
        path_len = struct.unpack_from(f"{bo}H", payload, 4)[0]
        path = _read_padded_str(payload, 8, path_len)
        return MslFileDescriptor(block_header=hdr, fd=fd, path=path)
    except Exception:
        return decode_generic(hdr, payload, byte_order)


def decode_network_connection(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslNetworkConnection | MslGenericBlock":
    """Decode Network Connection payload (type 0x0013)."""
    try:
        bo = byte_order
        local_port = struct.unpack_from(f"{bo}H", payload, 0)[0]
        remote_port = struct.unpack_from(f"{bo}H", payload, 2)[0]
        protocol = struct.unpack_from(f"{bo}H", payload, 4)[0]
        addresses = bytes(payload[8:])
        return MslNetworkConnection(
            block_header=hdr, local_port=local_port,
            remote_port=remote_port, protocol=protocol,
            addresses=addresses,
        )
    except Exception:
        return decode_generic(hdr, payload, byte_order)


def decode_environment_block(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslEnvironmentBlock | MslGenericBlock":
    """Decode Environment Block payload (type 0x0014)."""
    try:
        bo = byte_order
        count = struct.unpack_from(f"{bo}I", payload, 0)[0]
        entries: dict = {}
        offset = 4
        for _ in range(count):
            key_len = struct.unpack_from(f"{bo}H", payload, offset)[0]
            offset += 2
            val_len = struct.unpack_from(f"{bo}H", payload, offset)[0]
            offset += 2
            key = _read_padded_str(payload, offset, key_len)
            offset += _pad8(key_len)
            val = _read_padded_str(payload, offset, val_len)
            offset += _pad8(val_len)
            entries[key] = val
        return MslEnvironmentBlock(block_header=hdr, entries=entries)
    except Exception:
        return decode_generic(hdr, payload, byte_order)


def decode_security_token(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslSecurityToken | MslGenericBlock":
    """Decode Security Token payload (type 0x0015)."""
    try:
        bo = byte_order
        token_type = struct.unpack_from(f"{bo}H", payload, 0)[0]
        token_data = bytes(payload[4:])
        return MslSecurityToken(
            block_header=hdr, token_type=token_type,
            token_data=token_data,
        )
    except Exception:
        return decode_generic(hdr, payload, byte_order)


def decode_system_context(
    hdr: MslBlockHeader, payload: bytes, byte_order: str,
) -> "MslSystemContext | MslGenericBlock":
    """Decode System Context payload (type 0x0050) per spec §6.2 Table 20.

    Parses the fixed 32-byte header, the variable-length spec tail (AcqUser /
    Hostname / optional Domain / OSDetail / optional CaseRef), then the
    memdiver-local deviation tail (uptime_ns + os_version). A pure-spec reader
    can ignore the deviation tail by stopping at block_header.block_length.
    """
    try:
        bo = byte_order
        (boot_time_ns, target_count, table_bitmap,
         acq_user_len, hostname_len, domain_len,
         os_detail_len, case_ref_len) = struct.unpack_from(
            f"{bo}QIIHHHHH", payload, 0,
        )
        offset = 0x20  # after 32-byte fixed header

        acq_user = _read_padded_str(payload, offset, acq_user_len)
        offset += _pad8(acq_user_len)

        hostname = _read_padded_str(payload, offset, hostname_len)
        offset += _pad8(hostname_len)

        if domain_len > 0:
            domain = _read_padded_str(payload, offset, domain_len)
            offset += _pad8(domain_len)
        else:
            domain = ""

        os_detail = _read_padded_str(payload, offset, os_detail_len)
        offset += _pad8(os_detail_len)

        if case_ref_len > 0:
            case_ref = _read_padded_str(payload, offset, case_ref_len)
            offset += _pad8(case_ref_len)
        else:
            case_ref = ""

        # Local deviation tail — optional; absent on pure-spec producers
        uptime_ns = 0
        os_version = ""
        if offset + 16 <= len(payload):
            uptime_ns, os_version_len = struct.unpack_from(
                f"{bo}QH6x", payload, offset,
            )
            offset += 16
            if os_version_len > 0 and offset + os_version_len <= len(payload):
                os_version = _read_padded_str(payload, offset, os_version_len)

        return MslSystemContext(
            block_header=hdr,
            boot_time_ns=boot_time_ns,
            target_count=target_count,
            table_bitmap=table_bitmap,
            acq_user=acq_user,
            hostname=hostname,
            domain=domain,
            os_detail=os_detail,
            case_ref=case_ref,
            uptime_ns=uptime_ns,
            os_version=os_version,
        )
    except Exception:
        return decode_generic(hdr, payload, byte_order)

# -- Collection helper --

def collect_generic_blocks(
    reader: object, block_type: int,
) -> List[MslGenericBlock]:
    """Collect blocks of any type as generic containers."""
    bo = reader._byte_order  # type: ignore[attr-defined]
    return [
        decode_generic(h, p, bo)
        for h, p in reader.iter_blocks()
        if h.block_type == block_type
    ]
