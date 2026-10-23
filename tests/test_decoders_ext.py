"""Tests for msl.decoders_ext — extended block decoders."""

import struct
from uuid import UUID

import pytest

from memdiver.msl.enums import (
    REG_ROLE_FLAGS,
    REG_ROLE_PC,
    REG_ROLE_SP,
    TC_FLAG_CURRENT,
    TC_FLAG_SUSPENDED,
    ThreadState,
)
from memdiver.msl.types import (
    MslBlockHeader,
    MslGenericBlock,
    MslThreadContext,
    MslThreadRegister,
)
from memdiver.msl.decoders_ext import (
    MslEnvironmentBlock,
    MslFileDescriptor,
    MslNetworkConnection,
    MslSecurityToken,
    MslSystemContext,
    decode_environment_block,
    decode_file_descriptor,
    decode_generic,
    decode_network_connection,
    decode_security_token,
    decode_system_context,
    decode_thread_context,
)

BO = "<"  # little-endian


def _hdr(block_type: int = 0x0011) -> MslBlockHeader:
    return MslBlockHeader(
        block_type=block_type, flags=0, block_length=200,
        payload_version=1,
        block_uuid=UUID(int=1), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32,
        file_offset=0, payload_offset=80,
    )


def test_decode_generic_captures_payload():
    payload = b"\xDE\xAD\xBE\xEF"
    result = decode_generic(_hdr(), payload, BO)
    assert isinstance(result, MslGenericBlock)
    assert result.payload == payload
    assert result.block_header.block_type == 0x0011


# -- Thread Context (spec Tables 19a/19b), packed by hand with struct only --

# ThreadID(8) StartTime(8) Flags(2) ThreadState(1) Arch(1) RegCount(4)
# NameLen(2) Reserved(6); ThreadName (pad8) follows, omitted when NameLen 0.
_TC_HEAD = "<QQHBBIH6x"
# NameLen(1) Width(1) Flags(2) Reserved(4); Name (pad8) + Value (pad8) follow.
_TC_REG_HEAD = "<BBH4x"


def _pad8(raw: bytes) -> bytes:
    return raw.ljust((len(raw) + 7) & ~7, b"\x00")


def _pack_register(name: str, width: int, flags: int, value: bytes) -> bytes:
    raw_name = name.encode("utf-8") + b"\x00"
    head = struct.pack(_TC_REG_HEAD, len(raw_name), width, flags)
    return head + _pad8(raw_name) + _pad8(value)


def _pack_thread_context(tid, start_ns, flags, state, arch, name, registers):
    raw_name = name.encode("utf-8") + b"\x00" if name else b""
    payload = struct.pack(_TC_HEAD, tid, start_ns, flags, state, arch,
                          len(registers), len(raw_name))
    if raw_name:
        payload += _pad8(raw_name)
    for reg in registers:
        payload += _pack_register(*reg)
    return payload


_PC_VALUE = (0x00007FFF_DEAD_BEEF).to_bytes(8, "little")
_SP_VALUE = (0x00007FFF_FFFF_E000).to_bytes(8, "little")
_VEC_VALUE = bytes(range(16))
_REGISTERS = (
    ("rip", 8, REG_ROLE_PC, _PC_VALUE),
    ("rsp", 8, REG_ROLE_SP, _SP_VALUE),
    ("eflags", 4, REG_ROLE_FLAGS, b"\x46\x02\x00\x00"),  # 4 bytes -> pad8
    ("xmm0", 16, 0, _VEC_VALUE),
)


def test_decode_thread_context_spec_layout():
    payload = _pack_thread_context(
        0xDEAD, 1_700_000_000_123_456_789, TC_FLAG_CURRENT,
        ThreadState.RUNNING, 0, "main", _REGISTERS,
    )
    # head(32) + "main\0" pad8 (8) + 4 register entries
    assert len(payload) == 32 + 8 + (8 + 8 + 8) + (8 + 8 + 8) + (8 + 8 + 8) + (8 + 8 + 16)
    result = decode_thread_context(_hdr(), payload, BO)
    assert isinstance(result, MslThreadContext)
    assert result.block_header is not None
    assert result.thread_id == 0xDEAD
    assert result.start_time_ns == 1_700_000_000_123_456_789
    assert result.flags == TC_FLAG_CURRENT
    assert result.current and not result.crashed
    assert not result.suspended and not result.partial
    assert result.state == ThreadState.RUNNING
    assert result.arch == 0
    assert result.name == "main"
    assert [(r.name, r.width, r.flags, r.value) for r in result.registers] == list(_REGISTERS)
    assert all(isinstance(r, MslThreadRegister) for r in result.registers)


def test_decode_thread_context_register_roles_and_vector_width():
    payload = _pack_thread_context(7, 0, 0, ThreadState.UNKNOWN, 0, "t", _REGISTERS)
    result = decode_thread_context(_hdr(), payload, BO)
    assert isinstance(result, MslThreadContext)
    pc = result.register("rip")
    assert pc is not None and pc.is_pc and not pc.is_sp
    assert pc.value == _PC_VALUE
    sp = result.register("RSP")  # lookup is case-insensitive on the query
    assert sp is not None and sp.is_sp and not sp.is_pc
    flags = result.register("eflags")
    assert flags.width == 4 and flags.value == b"\x46\x02\x00\x00"
    assert len(flags.value) == 4  # pad bytes are not part of the value
    vec = result.register("xmm0")
    assert vec.width == 16 and vec.value == _VEC_VALUE and vec.flags == 0
    assert result.register("nope") is None


def test_decode_thread_context_nameless_thread():
    payload = _pack_thread_context(
        0x1002, 0, TC_FLAG_SUSPENDED, ThreadState.SLEEPING, 2, "",
        [("pc", 8, REG_ROLE_PC, _PC_VALUE)],
    )
    assert len(payload) == 32 + (8 + 8 + 8)  # no ThreadName bytes at all
    result = decode_thread_context(_hdr(), payload, BO)
    assert isinstance(result, MslThreadContext)
    assert result.name == ""
    assert result.thread_id == 0x1002
    assert result.suspended and not result.current
    assert result.state == ThreadState.SLEEPING
    assert result.arch == 2
    assert len(result.registers) == 1
    assert result.registers[0].name == "pc" and result.registers[0].is_pc


def test_decode_thread_context_no_registers():
    payload = _pack_thread_context(1, 0, 0, ThreadState.ZOMBIE, 0, "idle", [])
    result = decode_thread_context(_hdr(), payload, BO)
    assert isinstance(result, MslThreadContext)
    assert result.name == "idle"
    assert result.registers == ()


def test_decode_thread_context_truncated_register_falls_back():
    full = _pack_thread_context(1, 0, 0, ThreadState.RUNNING, 0, "main", _REGISTERS)
    # Cut inside the last register's 16-byte value and inside a register head.
    for cut in (len(full) - 1, len(full) - 20, 32 + 8 + 4):
        truncated = full[:cut]
        result = decode_thread_context(_hdr(), truncated, BO)
        assert isinstance(result, MslGenericBlock), f"cut at {cut}"
        assert result.payload == truncated


def test_decode_thread_context_truncated_name_falls_back():
    head = struct.pack(_TC_HEAD, 1, 0, 0, 0, 0, 0, 5)  # NameLen 5, no name bytes
    result = decode_thread_context(_hdr(), head, BO)
    assert isinstance(result, MslGenericBlock)


def test_decode_file_descriptor_basic():
    fd = 7
    path = b"/dev/null\x00"
    path_padded = path + b"\x00" * (8 - len(path) % 8) if len(path) % 8 else path
    payload = struct.pack("<I", fd) + struct.pack("<H", len(path)) + b"\x00\x00" + path_padded
    result = decode_file_descriptor(_hdr(0x0012), payload, BO)
    assert isinstance(result, MslFileDescriptor)
    assert result.fd == 7
    assert result.path == "/dev/null"


def test_decode_network_connection_basic():
    payload = struct.pack("<HHH", 443, 8080, 6) + b"\x00\x00" + b"\x7f\x00\x00\x01"
    result = decode_network_connection(_hdr(0x0013), payload, BO)
    assert isinstance(result, MslNetworkConnection)
    assert result.local_port == 443
    assert result.remote_port == 8080
    assert result.protocol == 6


def test_decode_environment_block_basic():
    key = b"HOME\x00\x00\x00\x00"   # 8 bytes padded
    val = b"/root\x00\x00\x00"       # 8 bytes padded
    payload = struct.pack("<I", 1)    # count=1
    payload += struct.pack("<HH", 4, 5)  # key_len=4, val_len=5
    payload += key + val
    result = decode_environment_block(_hdr(0x0014), payload, BO)
    assert isinstance(result, MslEnvironmentBlock)
    assert result.entries["HOME"] == "/root"


def test_decode_security_token_basic():
    token_data = b"\xCA\xFE\xBA\xBE"
    payload = struct.pack("<H", 3) + b"\x00\x00" + token_data
    result = decode_security_token(_hdr(0x0015), payload, BO)
    assert isinstance(result, MslSecurityToken)
    assert result.token_type == 3
    assert result.token_data == token_data


def test_decode_system_context_basic():
    """Decode a full spec §6.2 Table 20 payload built via the fixture helper."""
    from tests.fixtures.generate_msl_fixtures import _build_system_context
    from memdiver.msl.enums import BLOCK_HEADER_SIZE

    sc_block, _ = _build_system_context()
    # Strip the 80-byte block header to get the raw payload
    payload = sc_block[BLOCK_HEADER_SIZE:]
    result = decode_system_context(_hdr(0x0050), payload, BO)
    assert isinstance(result, MslSystemContext)
    # Spec Table 20 fields
    assert result.boot_time_ns == 1_600_000_000_000_000_000
    assert result.target_count == 1
    assert result.table_bitmap == 0b111
    assert result.acq_user == "examiner01"
    assert result.hostname == "server01"
    assert result.domain == ""
    assert result.os_detail == "Linux 6.1.0-18-amd64 #1 SMP Debian"
    assert result.case_ref == ""
    # Local deviation tail
    assert result.uptime_ns == 123456789
    assert result.os_version == "Linux 6.1"


def test_fallback_to_generic_on_truncated():
    tiny = b"\xAB"
    for decoder in (
        decode_thread_context, decode_file_descriptor,
        decode_network_connection, decode_environment_block,
        decode_security_token, decode_system_context,
    ):
        result = decoder(_hdr(), tiny, BO)
        assert isinstance(result, MslGenericBlock), (
            f"{decoder.__name__} did not fall back to MslGenericBlock"
        )
        assert result.payload == tiny
