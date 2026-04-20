"""Tests for msl/enums.py — MSL format constants and enumerations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from msl.enums import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    FILE_HEADER_SIZE,
    FILE_MAGIC,
    ArchType,
    BlockType,
    CompAlgo,
    Confidence,
    Endianness,
    HeaderFlag,
    KeyState,
    MslKeyType,
    MslProtocol,
    OSType,
    PageState,
    Protection,
    RegionType,
)


def test_magic_bytes():
    assert FILE_MAGIC == b"MEMSLICE"
    assert BLOCK_MAGIC == b"MSLC"


def test_header_sizes():
    assert FILE_HEADER_SIZE == 64
    assert BLOCK_HEADER_SIZE == 80


def test_endianness_values():
    assert Endianness.LITTLE == 0x01
    assert Endianness.BIG == 0x02


def test_block_types_spec_values():
    assert BlockType.MEMORY_REGION == 0x0001
    assert BlockType.MODULE_ENTRY == 0x0002
    assert BlockType.MODULE_LIST_INDEX == 0x0010
    assert BlockType.KEY_HINT == 0x0020
    assert BlockType.PROCESS_IDENTITY == 0x0040
    assert BlockType.SYSTEM_CONTEXT == 0x0050
    assert BlockType.END_OF_CAPTURE == 0x0FFF
    assert BlockType.VAS_MAP == 0x1001


def test_page_state_two_bit():
    assert PageState.CAPTURED == 0b00
    assert PageState.FAILED == 0b01
    assert PageState.UNMAPPED == 0b10
    assert PageState.RESERVED == 0b11


def test_protection_flags():
    rwx = Protection.READ | Protection.WRITE | Protection.EXECUTE
    assert rwx & Protection.READ
    assert rwx & Protection.WRITE
    assert rwx & Protection.EXECUTE
    assert not (rwx & Protection.GUARD)


def test_region_types():
    assert RegionType.HEAP == 0x01
    assert RegionType.STACK == 0x02
    assert RegionType.IMAGE == 0x03


def test_key_type_protocol_codes():
    assert MslKeyType.SESSION_KEY == 0x0003
    assert MslProtocol.TLS_13 == 0x0002
    assert MslProtocol.SSH == 0x0007


def test_confidence_levels():
    assert Confidence.SPECULATIVE == 0x00
    assert Confidence.HEURISTIC == 0x01
    assert Confidence.CONFIRMED == 0x02


def test_header_flags():
    flags = HeaderFlag.IMPORTED | HeaderFlag.INVESTIGATION
    assert flags & HeaderFlag.IMPORTED
    assert flags & HeaderFlag.INVESTIGATION
    assert not (flags & HeaderFlag.ENCRYPTED)


def test_os_arch_types():
    assert OSType.LINUX == 0x0001
    assert ArchType.X86_64 == 0x0001
