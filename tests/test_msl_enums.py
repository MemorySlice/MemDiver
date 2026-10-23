"""Tests for msl/enums.py — MSL format constants and enumerations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.msl.enums import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    EXTENSION_FORBIDDEN_TYPES,
    FILE_HEADER_SIZE,
    FILE_MAGIC,
    REG_ROLE_FLAGS,
    REG_ROLE_FP,
    REG_ROLE_LR,
    REG_ROLE_PC,
    REG_ROLE_SP,
    REG_ROLE_TLS,
    TC_FLAG_CRASHED,
    TC_FLAG_CURRENT,
    TC_FLAG_PARTIAL,
    TC_FLAG_SUSPENDED,
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
    ThreadState,
    VasNameSource,
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
    assert PageState.NOT_RESIDENT == 0b11
    assert PageState.RESERVED == 0b11  # backwards-compatible alias


def test_page_state_not_resident():
    assert PageState.NOT_RESIDENT == 3
    assert PageState.RESERVED is PageState.NOT_RESIDENT
    assert PageState(3).name == "NOT_RESIDENT"
    assert PageState(3) is PageState.NOT_RESIDENT


def test_thread_state_values():
    assert ThreadState.UNKNOWN == 0
    assert ThreadState.RUNNING == 1
    assert ThreadState.SLEEPING == 2
    assert ThreadState.STOPPED == 3
    assert ThreadState.WAITING == 4
    assert ThreadState.UNINTERRUPTIBLE == 5
    assert ThreadState.HALTED == 6
    assert ThreadState.ZOMBIE == 7
    assert len(ThreadState) == 8


def test_thread_context_flag_constants():
    assert TC_FLAG_CURRENT == 1
    assert TC_FLAG_CRASHED == 2
    assert TC_FLAG_SUSPENDED == 4
    assert TC_FLAG_PARTIAL == 8
    assert REG_ROLE_PC == 1
    assert REG_ROLE_SP == 2
    assert REG_ROLE_FP == 4
    assert REG_ROLE_FLAGS == 8
    assert REG_ROLE_TLS == 0x10
    assert REG_ROLE_LR == 0x20


def test_end_of_extension_block_type():
    assert BlockType.END_OF_EXTENSION == 0x0FFE
    assert BlockType(0x0FFE).name == "END_OF_EXTENSION"


def test_extension_forbidden_types():
    expected = frozenset({
        0x0001, 0x0002,                      # Memory Region, Module Entry
        0x0010, 0x0011, 0x0012, 0x0013,      # Module List Index .. Network Conn
        0x0014, 0x0015,                      # Environment Block, Security Token
        0x0030,                              # Import Provenance
        0x0040,                              # Process Identity
        0x0050, 0x0051, 0x0052, 0x0053,      # System Context .. Handle Table
        0x0054, 0x0055, 0x0056, 0x0057,      # .. Connectivity Table ..
        0x0058,
        0x0FFF,                              # End of Capture
    })
    assert isinstance(EXTENSION_FORBIDDEN_TYPES, frozenset)
    assert EXTENSION_FORBIDDEN_TYPES == expected
    for allowed in (0x0020, 0x0041, 0x0059, 0x005A, 0x005B, 0x1001, 0x1003):
        assert allowed not in EXTENSION_FORBIDDEN_TYPES


def test_vas_name_source_values():
    assert VasNameSource.UNSPECIFIED == 0
    assert VasNameSource.LIVE == 1
    assert VasNameSource.SOURCE_METADATA == 2
    assert VasNameSource.SYNTHESIZED == 3


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
