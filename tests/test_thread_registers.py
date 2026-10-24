"""Tests for msl.thread_registers (Thread Context register decoders, spec 5.7)."""

import struct

import pytest

from memdiver.msl.enums import (REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR,
                                REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_TLS,
                                TC_FLAG_CRASHED, TC_FLAG_CURRENT,
                                TC_FLAG_PARTIAL, TC_FLAG_SUSPENDED)
from memdiver.msl.thread_registers import (
    CONTEXT_AMD64, CONTEXT_ARM64, CONTEXT_CONTROL, CONTEXT_INTEGER,
    CONTEXT_SEGMENTS, elf_aarch64_prstatus_regs, elf_x86_64_prstatus_regs,
    minidump_context_amd64_regs, minidump_context_arm64_regs,
    thread_context_flags,
)

X86_64_USER_REGS = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "rflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]
AARCH64_USER_REGS = [f"x{i}" for i in range(31)] + ["sp", "pc", "pstate"]


def _distinct(n):
    return [0x1111_0000_0000_0000 + i * 0x0101 for i in range(n)]


def _as_dict(regs):
    return {r.name: r for r in regs}


def _u64(reg):
    return int.from_bytes(reg.value, "little")


def _roles(regs):
    return {r.name: r.flags for r in regs if r.flags}


# ELF x86_64 ------------------------------------------------------------------


def test_elf_x86_64_names_order_values_widths():
    values = _distinct(27)
    regs, partial = elf_x86_64_prstatus_regs(struct.pack("<27Q", *values))
    assert partial is False
    assert [r.name for r in regs] == X86_64_USER_REGS
    assert all(r.width == 8 and len(r.value) == 8 for r in regs)
    assert [_u64(r) for r in regs] == values


def test_elf_x86_64_sp_index_matches_elf_core_reader():
    values = _distinct(27)
    regs, _ = elf_x86_64_prstatus_regs(struct.pack("<27Q", *values))
    assert regs[19].name == "rsp"
    assert _u64(regs[19]) == values[19]


def test_elf_x86_64_roles():
    regs, _ = elf_x86_64_prstatus_regs(bytes(27 * 8))
    assert _roles(regs) == {
        "rip": REG_ROLE_PC, "rsp": REG_ROLE_SP, "rbp": REG_ROLE_FP,
        "rflags": REG_ROLE_FLAGS, "fs_base": REG_ROLE_TLS,
    }


def test_elf_x86_64_accepts_longer_buffer():
    regs, _ = elf_x86_64_prstatus_regs(bytes(27 * 8 + 16))
    assert len(regs) == 27


def test_elf_x86_64_short_buffer_raises():
    with pytest.raises(ValueError):
        elf_x86_64_prstatus_regs(bytes(27 * 8 - 1))


# ELF aarch64 -----------------------------------------------------------------


def test_elf_aarch64_names_order_values():
    values = _distinct(34)
    regs, partial = elf_aarch64_prstatus_regs(struct.pack("<34Q", *values))
    assert partial is False
    assert [r.name for r in regs] == AARCH64_USER_REGS
    assert [_u64(r) for r in regs] == values
    assert regs[31].name == "sp" and _u64(regs[31]) == values[31]
    assert all(r.width == 8 for r in regs)


def test_elf_aarch64_roles_without_tls():
    regs, _ = elf_aarch64_prstatus_regs(bytes(34 * 8))
    assert _roles(regs) == {
        "x29": REG_ROLE_FP, "x30": REG_ROLE_LR, "sp": REG_ROLE_SP,
        "pc": REG_ROLE_PC, "pstate": REG_ROLE_FLAGS,
    }
    assert "tpidr_el0" not in _as_dict(regs)


def test_elf_aarch64_nt_arm_tls_appended():
    tls = struct.pack("<QQ", 0x7F00_DEAD_BEEF, 0x99)  # tpidr_el0, tpidr2_el0
    regs, _ = elf_aarch64_prstatus_regs(bytes(34 * 8), tls)
    last = regs[-1]
    assert last.name == "tpidr_el0"
    assert last.flags == REG_ROLE_TLS
    assert _u64(last) == 0x7F00_DEAD_BEEF
    assert len(regs) == 35


@pytest.mark.parametrize("pr_reg, tls", [
    (bytes(34 * 8 - 1), None),
    (bytes(34 * 8), bytes(7)),
])
def test_elf_aarch64_short_buffers_raise(pr_reg, tls):
    with pytest.raises(ValueError):
        elf_aarch64_prstatus_regs(pr_reg, tls)


# Minidump CONTEXT_AMD64 ------------------------------------------------------

AMD64_GPRS = {  # name -> offset (winnt.h CONTEXT, _M_AMD64)
    "rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98,
    "rbp": 0xA0, "rsi": 0xA8, "rdi": 0xB0,
    **{f"r{n}": 0xB8 + (n - 8) * 8 for n in range(8, 16)},
    "rip": 0xF8,
}
AMD64_SEGS = {"cs": 0x38, "ds": 0x3A, "es": 0x3C, "fs": 0x3E, "gs": 0x40,
              "ss": 0x42}
ALL_AMD64 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS


def _amd64_context(context_flags):
    ctx = bytearray(1232)
    struct.pack_into("<I", ctx, 0x30, context_flags)
    for i, (name, off) in enumerate(AMD64_GPRS.items()):
        struct.pack_into("<Q", ctx, off, 0xA000_0000_0000_0000 + i)
    for i, (name, off) in enumerate(AMD64_SEGS.items()):
        struct.pack_into("<H", ctx, off, 0x10 + i)
    struct.pack_into("<I", ctx, 0x44, 0x246)
    return bytes(ctx)


def test_amd64_full_context():
    regs, partial = minidump_context_amd64_regs(_amd64_context(ALL_AMD64))
    assert partial is False
    by_name = _as_dict(regs)
    for i, name in enumerate(AMD64_GPRS):
        assert _u64(by_name[name]) == 0xA000_0000_0000_0000 + i
    for i, name in enumerate(AMD64_SEGS):
        assert _u64(by_name[name]) == 0x10 + i
    assert _u64(by_name["rflags"]) == 0x246
    assert all(r.width == 8 for r in regs)
    assert len(regs) == 17 + 1 + 6
    assert "gs_base" not in by_name
    assert _roles(regs) == {
        "rip": REG_ROLE_PC, "rsp": REG_ROLE_SP, "rbp": REG_ROLE_FP,
        "rflags": REG_ROLE_FLAGS,
    }


def test_amd64_teb_becomes_gs_base_tls():
    regs, _ = minidump_context_amd64_regs(_amd64_context(ALL_AMD64),
                                          teb=0x7FF6_0000_1000)
    gs_base = _as_dict(regs)["gs_base"]
    assert gs_base.flags == REG_ROLE_TLS
    assert _u64(gs_base) == 0x7FF6_0000_1000
    assert _as_dict(regs)["gs"].flags == 0


def test_amd64_missing_segments_is_partial():
    ctx = _amd64_context(CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER)
    regs, partial = minidump_context_amd64_regs(ctx)
    names = {r.name for r in regs}
    assert partial is True
    assert not names & {"ds", "es", "fs", "gs"}
    assert {"cs", "ss", "rip", "rsp", "rax"} <= names


def test_amd64_missing_integer_is_partial():
    ctx = _amd64_context(CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_SEGMENTS)
    regs, partial = minidump_context_amd64_regs(ctx)
    names = {r.name for r in regs}
    assert partial is True
    assert "rax" not in names and "rbp" not in names
    assert {"rip", "rsp", "rflags"} <= names


def test_amd64_control_only_drops_pc_sp_when_missing():
    ctx = _amd64_context(CONTEXT_AMD64 | CONTEXT_INTEGER)
    regs, partial = minidump_context_amd64_regs(ctx)
    names = {r.name for r in regs}
    assert partial is True
    assert not names & {"rip", "rsp", "rflags", "cs", "ss"}


def test_amd64_wrong_arch_bit_raises():
    with pytest.raises(ValueError):
        minidump_context_amd64_regs(_amd64_context(CONTEXT_ARM64 | 0x7))


def test_amd64_short_buffer_raises():
    with pytest.raises(ValueError):
        minidump_context_amd64_regs(_amd64_context(ALL_AMD64)[:0xFF])


# Minidump CONTEXT_ARM64 ------------------------------------------------------

ALL_ARM64 = CONTEXT_ARM64 | CONTEXT_CONTROL | CONTEXT_INTEGER


def _arm64_context(context_flags):
    ctx = bytearray(912)
    struct.pack_into("<II", ctx, 0, context_flags, 0x6000_03C5)
    for i in range(29):
        struct.pack_into("<Q", ctx, 0x8 + i * 8, 0xB000_0000_0000_0000 + i)
    struct.pack_into("<4Q", ctx, 0xF0, 0xF0F0, 0x1A1A, 0x5050, 0xC0C0)
    return bytes(ctx)


def test_arm64_full_context():
    regs, partial = minidump_context_arm64_regs(_arm64_context(ALL_ARM64))
    assert partial is False
    assert [r.name for r in regs] == AARCH64_USER_REGS
    by_name = _as_dict(regs)
    for i in range(29):
        assert _u64(by_name[f"x{i}"]) == 0xB000_0000_0000_0000 + i
    assert _u64(by_name["x29"]) == 0xF0F0
    assert _u64(by_name["x30"]) == 0x1A1A
    assert _u64(by_name["sp"]) == 0x5050
    assert _u64(by_name["pc"]) == 0xC0C0
    assert _u64(by_name["pstate"]) == 0x6000_03C5
    assert all(r.width == 8 for r in regs)
    assert _roles(regs) == {
        "x18": REG_ROLE_TLS, "x29": REG_ROLE_FP, "x30": REG_ROLE_LR,
        "sp": REG_ROLE_SP, "pc": REG_ROLE_PC, "pstate": REG_ROLE_FLAGS,
    }


def test_arm64_missing_integer_is_partial():
    ctx = _arm64_context(CONTEXT_ARM64 | CONTEXT_CONTROL)
    regs, partial = minidump_context_arm64_regs(ctx)
    assert partial is True
    assert [r.name for r in regs] == ["x29", "x30", "sp", "pc", "pstate"]


def test_arm64_missing_control_is_partial():
    ctx = _arm64_context(CONTEXT_ARM64 | CONTEXT_INTEGER)
    regs, partial = minidump_context_arm64_regs(ctx)
    assert partial is True
    assert [r.name for r in regs] == [f"x{i}" for i in range(29)]


def test_arm64_wrong_arch_bit_raises():
    with pytest.raises(ValueError):
        minidump_context_arm64_regs(_arm64_context(CONTEXT_AMD64 | 0x3))


def test_arm64_short_buffer_raises():
    with pytest.raises(ValueError):
        minidump_context_arm64_regs(_arm64_context(ALL_ARM64)[:0x10F])


# thread_context_flags --------------------------------------------------------


@pytest.mark.parametrize("crashed, current, partial, expected", [
    (False, False, False, TC_FLAG_SUSPENDED),
    (True, False, False, TC_FLAG_SUSPENDED | TC_FLAG_CRASHED),
    (False, True, False, TC_FLAG_SUSPENDED | TC_FLAG_CURRENT),
    (False, False, True, TC_FLAG_SUSPENDED | TC_FLAG_PARTIAL),
    (True, True, True, 0x000F),
])
def test_thread_context_flags(crashed, current, partial, expected):
    assert thread_context_flags(crashed=crashed, current=current,
                                partial=partial) == expected
