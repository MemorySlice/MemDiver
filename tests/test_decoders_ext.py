"""Tests for msl.decoders_ext — extended block decoders."""

import struct
from uuid import UUID

import pytest

from msl.types import MslBlockHeader, MslGenericBlock
from msl.decoders_ext import (
    MslEnvironmentBlock,
    MslFileDescriptor,
    MslNetworkConnection,
    MslSecurityToken,
    MslSystemContext,
    MslThreadContext,
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


def test_decode_thread_context_basic():
    tid = 42
    regs = b"\x01\x02\x03\x04"
    payload = struct.pack("<Q", tid) + regs
    result = decode_thread_context(_hdr(), payload, BO)
    assert isinstance(result, MslThreadContext)
    assert result.thread_id == 42
    assert result.register_data == regs


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
    from msl.enums import BLOCK_HEADER_SIZE

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
