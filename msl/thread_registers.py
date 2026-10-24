"""Register-file decoders for Thread Context blocks (spec Section 5.7).

Pure functions that turn the raw register structures found in ELF core
``NT_PRSTATUS`` notes and Minidump ``CONTEXT`` records into ordered
:class:`MslThreadRegister` lists named per spec Table 19g, with the
``REG_ROLE_*`` role bits of Table 19b set on PC/SP/FP/FLAGS/TLS/LR.

Every decoder returns ``DecodedRegisters(registers, partial)``; ``partial``
is True when the source says part of the register file is absent (Minidump
``ContextFlags``). A buffer too short for the decoded layout raises
``ValueError`` so the caller can skip that thread.

Integer registers are written little-endian and zero-extended to the
8-byte GPR width (spec "Canonical register names": flags and segment
registers use the GPR width).
"""

from __future__ import annotations

import struct
from typing import Iterable, List, NamedTuple, Optional, Sequence, Tuple

from .enums import (REG_ROLE_FLAGS, REG_ROLE_FP, REG_ROLE_LR, REG_ROLE_PC,
                    REG_ROLE_SP, REG_ROLE_TLS, TC_FLAG_CRASHED,
                    TC_FLAG_CURRENT, TC_FLAG_PARTIAL, TC_FLAG_SUSPENDED)
from .types import MslThreadRegister

GPR_WIDTH = 8

# Minidump ContextFlags bits (Windows SDK winnt.h).
CONTEXT_AMD64 = 0x00100000
CONTEXT_ARM64 = 0x00400000
CONTEXT_CONTROL = 0x1
CONTEXT_INTEGER = 0x2
CONTEXT_SEGMENTS = 0x4


class DecodedRegisters(NamedTuple):
    """Decoder result: ordered register entries + "register file incomplete"."""
    registers: List[MslThreadRegister]
    partial: bool


# (name, role flags) per slot.
_Slot = Tuple[str, int]


# ELF NT_PRSTATUS layouts -----------------------------------------------------

# x86_64 ``struct user_regs_struct`` (Linux arch/x86/include/asm/user_64.h):
# 27 x unsigned long, in this order. ``eflags`` is renamed ``rflags``.
_ELF_X86_64_SLOTS: Tuple[_Slot, ...] = (
    ("r15", 0), ("r14", 0), ("r13", 0), ("r12", 0),
    ("rbp", REG_ROLE_FP), ("rbx", 0), ("r11", 0), ("r10", 0),
    ("r9", 0), ("r8", 0), ("rax", 0), ("rcx", 0), ("rdx", 0),
    ("rsi", 0), ("rdi", 0), ("orig_rax", 0), ("rip", REG_ROLE_PC),
    ("cs", 0), ("rflags", REG_ROLE_FLAGS), ("rsp", REG_ROLE_SP),
    ("ss", 0), ("fs_base", REG_ROLE_TLS), ("gs_base", 0),
    ("ds", 0), ("es", 0), ("fs", 0), ("gs", 0),
)

# aarch64 ``struct user_pt_regs`` (Linux arch/arm64/include/uapi/asm/ptrace.h):
# regs[31], sp, pc, pstate -- 34 x __u64.
_ELF_AARCH64_SLOTS: Tuple[_Slot, ...] = (
    tuple((f"x{i}", 0) for i in range(29))
    + (("x29", REG_ROLE_FP), ("x30", REG_ROLE_LR), ("sp", REG_ROLE_SP),
       ("pc", REG_ROLE_PC), ("pstate", REG_ROLE_FLAGS))
)

# NT_ARM_TLS (0x401) note: first u64 is tpidr_el0 (newer kernels append
# tpidr2_el0, which is ignored here).
NT_ARM_TLS = 0x401


# Minidump CONTEXT layouts ----------------------------------------------------

# CONTEXT_AMD64 (winnt.h ``_CONTEXT`` for _M_AMD64, 0x4D0 = 1232 bytes):
# P1Home..P6Home @0x00, ContextFlags u32 @0x30, MxCsr u32 @0x34,
# SegCs/SegDs/SegEs/SegFs/SegGs/SegSs u16 @0x38..0x42, EFlags u32 @0x44,
# Dr0-Dr3/Dr6/Dr7 @0x48..0x70, Rax @0x78, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
# R8..R15 (u64 each), Rip @0xF8. Only the prefix up to Rip is decoded.
_AMD64_CONTEXT_FLAGS_OFFSET = 0x30
_AMD64_DECODED_SIZE = 0x100
# (name, offset, size, roles, ContextFlags group). Order follows Table 19g.
_AMD64_FIELDS: Tuple[Tuple[str, int, int, int, int], ...] = (
    ("rax", 0x78, 8, 0, CONTEXT_INTEGER),
    ("rbx", 0x90, 8, 0, CONTEXT_INTEGER),
    ("rcx", 0x80, 8, 0, CONTEXT_INTEGER),
    ("rdx", 0x88, 8, 0, CONTEXT_INTEGER),
    ("rsi", 0xA8, 8, 0, CONTEXT_INTEGER),
    ("rdi", 0xB0, 8, 0, CONTEXT_INTEGER),
    ("rbp", 0xA0, 8, REG_ROLE_FP, CONTEXT_INTEGER),
    ("rsp", 0x98, 8, REG_ROLE_SP, CONTEXT_CONTROL),
) + tuple(
    (f"r{n}", 0xB8 + (n - 8) * 8, 8, 0, CONTEXT_INTEGER) for n in range(8, 16)
) + (
    ("rip", 0xF8, 8, REG_ROLE_PC, CONTEXT_CONTROL),
    ("rflags", 0x44, 4, REG_ROLE_FLAGS, CONTEXT_CONTROL),
    ("cs", 0x38, 2, 0, CONTEXT_CONTROL),
    ("ss", 0x42, 2, 0, CONTEXT_CONTROL),
    ("ds", 0x3A, 2, 0, CONTEXT_SEGMENTS),
    ("es", 0x3C, 2, 0, CONTEXT_SEGMENTS),
    ("fs", 0x3E, 2, 0, CONTEXT_SEGMENTS),
    ("gs", 0x40, 2, 0, CONTEXT_SEGMENTS),
)
_AMD64_GROUPS = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS

# CONTEXT_ARM64 (winnt.h ``ARM64_NT_CONTEXT``, 0x390 = 912 bytes):
# ContextFlags u32 @0x0, Cpsr u32 @0x4, X0..X28 @0x8 (29 x u64), Fp @0xF0,
# Lr @0xF8, Sp @0x100, Pc @0x108, then V[32] @0x110 (not decoded).
_ARM64_DECODED_SIZE = 0x110
_ARM64_FIELDS: Tuple[Tuple[str, int, int, int, int], ...] = tuple(
    (f"x{i}", 0x8 + i * 8, 8, REG_ROLE_TLS if i == 18 else 0, CONTEXT_INTEGER)
    for i in range(29)
) + (
    ("x29", 0xF0, 8, REG_ROLE_FP, CONTEXT_CONTROL),
    ("x30", 0xF8, 8, REG_ROLE_LR, CONTEXT_CONTROL),
    ("sp", 0x100, 8, REG_ROLE_SP, CONTEXT_CONTROL),
    ("pc", 0x108, 8, REG_ROLE_PC, CONTEXT_CONTROL),
    ("pstate", 0x4, 4, REG_ROLE_FLAGS, CONTEXT_CONTROL),
)
_ARM64_GROUPS = CONTEXT_CONTROL | CONTEXT_INTEGER


# Helpers ---------------------------------------------------------------------


def _gpr(name: str, flags: int, value: int) -> MslThreadRegister:
    """An 8-byte little-endian register entry."""
    return MslThreadRegister(
        name=name, width=GPR_WIDTH, flags=flags,
        value=value.to_bytes(GPR_WIDTH, "little"),
    )


def _require_size(buf: bytes, size: int, what: str) -> None:
    if len(buf) < size:
        raise ValueError(f"{what} too short: {len(buf)} < {size} bytes")


def _decode_u64_array(buf: bytes, slots: Sequence[_Slot],
                      what: str) -> List[MslThreadRegister]:
    """Decode a packed little-endian u64 array named by *slots*."""
    _require_size(buf, len(slots) * GPR_WIDTH, what)
    values = struct.unpack_from(f"<{len(slots)}Q", buf, 0)
    return [_gpr(name, flags, v) for (name, flags), v in zip(slots, values)]


def _decode_context_fields(
    ctx: bytes, fields: Iterable[Tuple[str, int, int, int, int]],
    present_groups: int,
) -> List[MslThreadRegister]:
    """Decode the fields whose ContextFlags group is present."""
    registers = []
    for name, offset, size, flags, group in fields:
        if group & present_groups:
            value = int.from_bytes(ctx[offset:offset + size], "little")
            registers.append(_gpr(name, flags, value))
    return registers


def _present_groups(context_flags: int, arch_bit: int, all_groups: int,
                    what: str) -> int:
    """Group bits present in *context_flags* (``ValueError`` on wrong arch)."""
    if not context_flags & arch_bit:
        raise ValueError(
            f"{what} ContextFlags {context_flags:#x} lacks arch bit "
            f"{arch_bit:#x}")
    return context_flags & all_groups


# ELF decoders ----------------------------------------------------------------


def elf_x86_64_prstatus_regs(pr_reg: bytes) -> DecodedRegisters:
    """Decode an x86_64 ``NT_PRSTATUS`` ``pr_reg`` (Linux ``user_regs_struct``).

    ``fs_base`` carries the TLS role (Linux thread pointer). Raises
    ``ValueError`` if *pr_reg* is shorter than 27 x u64.
    """
    regs = _decode_u64_array(pr_reg, _ELF_X86_64_SLOTS, "x86_64 pr_reg")
    return DecodedRegisters(regs, False)


def elf_aarch64_prstatus_regs(pr_reg: bytes,
                              tls: Optional[bytes] = None) -> DecodedRegisters:
    """Decode an aarch64 ``NT_PRSTATUS`` ``pr_reg`` (``user_pt_regs``).

    *tls* is the ``NT_ARM_TLS`` note descriptor; when given, its first u64
    is appended as ``tpidr_el0`` with the TLS role. Raises ``ValueError``
    if *pr_reg* is shorter than 34 x u64 or *tls* shorter than 8 bytes.
    """
    regs = _decode_u64_array(pr_reg, _ELF_AARCH64_SLOTS, "aarch64 pr_reg")
    if tls is not None:
        _require_size(tls, GPR_WIDTH, "NT_ARM_TLS")
        tpidr = struct.unpack_from("<Q", tls, 0)[0]
        regs.append(_gpr("tpidr_el0", REG_ROLE_TLS, tpidr))
    return DecodedRegisters(regs, False)


# Minidump decoders -----------------------------------------------------------


def minidump_context_amd64_regs(ctx: bytes,
                                teb: Optional[int] = None) -> DecodedRegisters:
    """Decode a Minidump ``CONTEXT_AMD64`` record.

    Register groups missing from ``ContextFlags`` (CONTROL / INTEGER /
    SEGMENTS) are omitted and reported as ``partial``. When *teb* is given
    it is written as ``gs_base`` with the TLS role (Windows thread pointer).
    Raises ``ValueError`` on a buffer shorter than the decoded prefix
    (0x100 bytes) or a ``ContextFlags`` without the ``CONTEXT_AMD64`` bit.
    """
    _require_size(ctx, _AMD64_DECODED_SIZE, "CONTEXT_AMD64")
    flags = struct.unpack_from("<I", ctx, _AMD64_CONTEXT_FLAGS_OFFSET)[0]
    groups = _present_groups(flags, CONTEXT_AMD64, _AMD64_GROUPS,
                             "CONTEXT_AMD64")
    regs = _decode_context_fields(ctx, _AMD64_FIELDS, groups)
    if teb is not None:
        regs.append(_gpr("gs_base", REG_ROLE_TLS, teb))
    return DecodedRegisters(regs, groups != _AMD64_GROUPS)


def minidump_context_arm64_regs(ctx: bytes) -> DecodedRegisters:
    """Decode a Minidump ``CONTEXT_ARM64`` (``ARM64_NT_CONTEXT``) record.

    ``x18`` carries the TLS role (TEB on Windows); ``Cpsr`` becomes
    ``pstate``. Groups missing from ``ContextFlags`` (CONTROL / INTEGER)
    are omitted and reported as ``partial``. Raises ``ValueError`` on a
    buffer shorter than 0x110 bytes or a ``ContextFlags`` without the
    ``CONTEXT_ARM64`` bit.
    """
    _require_size(ctx, _ARM64_DECODED_SIZE, "CONTEXT_ARM64")
    flags = struct.unpack_from("<I", ctx, 0)[0]
    groups = _present_groups(flags, CONTEXT_ARM64, _ARM64_GROUPS,
                             "CONTEXT_ARM64")
    regs = _decode_context_fields(ctx, _ARM64_FIELDS, groups)
    return DecodedRegisters(regs, groups != _ARM64_GROUPS)


# Thread Context flags --------------------------------------------------------


def thread_context_flags(*, crashed: bool, current: bool,
                         partial: bool) -> int:
    """Thread Context ``Flags`` (Table 19a) for a core / minidump thread.

    ``Suspended`` is always set: both formats are stopped snapshots.
    """
    flags = TC_FLAG_SUSPENDED
    if crashed:
        flags |= TC_FLAG_CRASHED
    if current:
        flags |= TC_FLAG_CURRENT
    if partial:
        flags |= TC_FLAG_PARTIAL
    return flags
