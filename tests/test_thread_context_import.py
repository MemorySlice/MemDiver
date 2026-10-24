"""Thread Context (0x0011) writing: MslWriter encoding + importer wiring.

Covers ``MslWriter.add_thread_context`` (spec Tables 19a/19b, CapBitmap
bit 2) and the ELF core / Minidump importers emitting one Thread Context
block per thread ahead of the first Memory Region (spec §5.7, §11).
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List

import pytest

from memdiver.core.binary_formats.elf_core_reader import EM_AARCH64, EM_X86_64
from memdiver.core.binary_formats.minidump_reader import (
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
    PROCESSOR_ARCHITECTURE_INTEL)
from memdiver.msl.decoders_ext import decode_thread_context
from memdiver.msl.enums import (REG_ROLE_PC, REG_ROLE_SP, REG_ROLE_TLS,
                                TC_FLAG_CRASHED, TC_FLAG_CURRENT,
                                TC_FLAG_PARTIAL, TC_FLAG_SUSPENDED, BlockType,
                                ThreadState)
from memdiver.msl.importer import import_elf_core, import_minidump
from memdiver.msl.reader import MslReader
from memdiver.msl.thread_registers import (CONTEXT_AMD64, CONTEXT_ARM64,
                                           CONTEXT_CONTROL, CONTEXT_INTEGER,
                                           CONTEXT_SEGMENTS)
from memdiver.msl.types import MslThreadContext, MslThreadRegister
from memdiver.msl.writer import CapBit, MslWriter
from tests.fixtures.generate_msl_fixtures import _build_thread_context
from tests.fixtures.synth_elf_core import SynthThread, build_core_bytes
from tests.test_minidump_reader import _build_minidump

_SIGSEGV = 11
_X86_RIP, _X86_RSP = 16, 19
_ARM_SP, _ARM_PC = 31, 32
_SUSPENDED_CURRENT = TC_FLAG_SUSPENDED | TC_FLAG_CURRENT
_CRASHED_FLAGS = TC_FLAG_SUSPENDED | TC_FLAG_CRASHED | TC_FLAG_CURRENT


def _reg(name: str, value: int, flags: int = 0, width: int = 8) -> MslThreadRegister:
    return MslThreadRegister(name=name, width=width, flags=flags,
                             value=value.to_bytes(width, "little"))


def _u64(register: MslThreadRegister) -> int:
    return int.from_bytes(register.value, "little")


def _by_name(tc: MslThreadContext) -> dict:
    return {r.name: r for r in tc.registers}


def _write_one(tmp_path: Path, registers, **kwargs) -> Path:
    out = tmp_path / "tc.msl"
    writer = MslWriter(out)
    writer.add_thread_context(0x1234, registers, **kwargs)
    writer.add_memory_region(0x1000, b"\x00" * 4096)
    writer.add_end_of_capture()
    writer.write()
    return out


def _thread_payloads(path: Path) -> List[bytes]:
    with MslReader(path) as reader:
        return [payload for hdr, payload in reader.iter_blocks()
                if hdr.block_type == BlockType.THREAD_CONTEXT]


def _block_types(path: Path) -> List[int]:
    with MslReader(path) as reader:
        return [hdr.block_type for hdr, _ in reader.iter_blocks()]


def _contexts(path: Path) -> List[MslThreadContext]:
    with MslReader(path) as reader:
        return reader.collect_thread_contexts()


def _cap_bitmap(path: Path) -> int:
    with MslReader(path) as reader:
        return reader.file_header.cap_bitmap


def _assert_threads_precede_regions(path: Path) -> None:
    types = _block_types(path)
    assert types[0] == BlockType.IMPORT_PROVENANCE
    first_region = types.index(BlockType.MEMORY_REGION)
    tc_positions = [i for i, t in enumerate(types)
                    if t == BlockType.THREAD_CONTEXT]
    assert tc_positions and max(tc_positions) < first_region


# -- Writer encoding ----------------------------------------------------------


def test_writer_round_trip_decodes(tmp_path) -> None:
    regs = [_reg("RIP", 0x4010, REG_ROLE_PC), _reg("rsp", 0x7FF0, REG_ROLE_SP),
            _reg("xmm0", 0x0102, width=16), _reg("cs", 0x33, width=1)]
    out = _write_one(tmp_path, regs, flags=_CRASHED_FLAGS, arch=0x02,
                     name="worker-1", start_time=99,
                     state=ThreadState.SLEEPING)
    [tc] = _contexts(out)
    assert (tc.thread_id, tc.start_time_ns, tc.flags, tc.state, tc.arch,
            tc.name) == (0x1234, 99, _CRASHED_FLAGS, ThreadState.SLEEPING,
                         0x02, "worker-1")
    assert [(r.name, r.width, r.flags) for r in tc.registers] == [
        ("rip", 8, REG_ROLE_PC), ("rsp", 8, REG_ROLE_SP),
        ("xmm0", 16, 0), ("cs", 1, 0)]
    assert [r.value for r in tc.registers] == [r.value for r in regs]
    assert _thread_payloads(out)[0][0x13] == 0x02  # Arch byte at +0x13
    assert _cap_bitmap(out) & CapBit.THREAD_CONTEXTS


def test_writer_default_state_stopped_no_name(tmp_path) -> None:
    out = _write_one(tmp_path, [_reg("pc", 1, REG_ROLE_PC)], flags=0)
    [tc] = _contexts(out)
    assert (tc.state, tc.name, tc.arch) == (ThreadState.STOPPED, "", 0)
    payload = _thread_payloads(out)[0]
    assert struct.unpack_from("<H", payload, 0x18)[0] == 0  # NameLen
    assert payload[0x1A:0x20] == b"\x00" * 6  # Reserved2


def test_writer_bytes_match_fixture_encoder(tmp_path) -> None:
    spec = [("rip", 8, REG_ROLE_PC, (0xDEADBEEF).to_bytes(8, "little")),
            ("rsp", 8, REG_ROLE_SP, (0x7FFE_0000).to_bytes(8, "little")),
            ("x", 3, 0, b"\x01\x02\x03")]
    regs = [MslThreadRegister(n, w, f, v) for n, w, f, v in spec]
    out = _write_one(tmp_path, regs, flags=TC_FLAG_CURRENT,
                     state=ThreadState.RUNNING, name="main", start_time=7)
    expected, _ = _build_thread_context(
        thread_id=0x1234, start_time_ns=7, flags=TC_FLAG_CURRENT,
        state=ThreadState.RUNNING, arch=0, name="main", registers=spec)
    assert _thread_payloads(out) == [expected[80:]]


@pytest.mark.parametrize("register", [
    MslThreadRegister("", 8, 0, b"\x00" * 8),
    MslThreadRegister("rip", 8, 0, b"\x00" * 4),
    MslThreadRegister("rip", 0, 0, b""),
])
def test_writer_rejects_invalid_register(tmp_path, register) -> None:
    writer = MslWriter(tmp_path / "bad.msl")
    with pytest.raises(ValueError):
        writer.add_thread_context(1, [register], flags=0)


def test_writer_rejects_wide_arch(tmp_path) -> None:
    writer = MslWriter(tmp_path / "bad.msl")
    with pytest.raises(ValueError):
        writer.add_thread_context(1, [_reg("pc", 1)], flags=0, arch=0x100)


def test_writer_parent_uuid(tmp_path) -> None:
    out = tmp_path / "p.msl"
    writer = MslWriter(out, imported=False)
    pi = writer.add_process_identity(ppid=1)
    writer.add_thread_context(5, [_reg("pc", 1, REG_ROLE_PC)], flags=0,
                              parent_uuid=pi)
    writer.add_end_of_capture()
    writer.write()
    [tc] = _contexts(out)
    assert tc.block_header.parent_uuid == pi


# -- ELF core import ----------------------------------------------------------


def _import_core(tmp_path: Path, machine: int, threads) -> Path:
    core = tmp_path / "core"
    core.write_bytes(build_core_bytes(machine=machine, threads=threads))
    out = tmp_path / "core.msl"
    import_elf_core(core, out)
    return out


def test_elf_x86_64_threads_imported(tmp_path) -> None:
    threads = [
        SynthThread(tid=100, regs={_X86_RIP: 0x401000, _X86_RSP: 0x7FF000}),
        SynthThread(tid=101, regs={_X86_RIP: 0x402000, _X86_RSP: 0x7FE000,
                                   21: 0x7F00_0000_1000}, cursig=_SIGSEGV),
    ]
    out = _import_core(tmp_path, EM_X86_64, threads)
    contexts = _contexts(out)
    assert [tc.thread_id for tc in contexts] == [100, 101]
    assert [tc.flags for tc in contexts] == [TC_FLAG_SUSPENDED, _CRASHED_FLAGS]
    regs = _by_name(contexts[1])
    assert {"rip", "rsp", "rflags", "fs_base"} <= regs.keys()
    assert (_u64(regs["rip"]), _u64(regs["rsp"])) == (0x402000, 0x7FE000)
    assert regs["fs_base"].flags == REG_ROLE_TLS
    assert _u64(regs["fs_base"]) == 0x7F00_0000_1000
    assert all(tc.state == ThreadState.STOPPED for tc in contexts)
    assert _cap_bitmap(out) & CapBit.THREAD_CONTEXTS
    _assert_threads_precede_regions(out)


def test_elf_aarch64_threads_with_tls(tmp_path) -> None:
    threads = [
        SynthThread(tid=7, regs={_ARM_SP: 0xFFFF_0000, _ARM_PC: 0x4000},
                    arm_tls=(0x7777).to_bytes(8, "little")),
        SynthThread(tid=8, regs={_ARM_SP: 0xFFFE_0000, _ARM_PC: 0x5000}),
    ]
    out = _import_core(tmp_path, EM_AARCH64, threads)
    contexts = _contexts(out)
    # No crashed thread: Current falls back to the first emitted thread.
    assert [tc.flags for tc in contexts] == [_SUSPENDED_CURRENT,
                                             TC_FLAG_SUSPENDED]
    regs = _by_name(contexts[0])
    assert {"x29", "x30", "pc", "sp", "pstate", "tpidr_el0"} <= regs.keys()
    assert (_u64(regs["pc"]), _u64(regs["sp"]), _u64(regs["tpidr_el0"])) == (
        0x4000, 0xFFFF_0000, 0x7777)
    assert "tpidr_el0" not in _by_name(contexts[1])
    _assert_threads_precede_regions(out)


def test_elf_without_threads_has_no_cap_bit(tmp_path) -> None:
    out = _import_core(tmp_path, EM_X86_64, None)
    assert _contexts(out) == []
    assert not _cap_bitmap(out) & CapBit.THREAD_CONTEXTS


def test_elf_unsupported_machine_emits_nothing(tmp_path) -> None:
    out = _import_core(tmp_path, 0x28, [(1, 0x1000)])  # EM_ARM
    assert _contexts(out) == []
    assert not _cap_bitmap(out) & CapBit.THREAD_CONTEXTS


# -- Minidump import ----------------------------------------------------------

_TEB_A, _TEB_B = 0x00D1_2345_0000, 0x00D1_2346_0000
_MD_THREADS = [
    (0x1A2B, _TEB_A, 0x00D1_0000_0000, 0x10000),
    (0x1A2C, _TEB_B, 0x00D2_0000_0000, 0x8000),
]
_ALL_AMD64 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
_ALL_ARM64 = CONTEXT_ARM64 | CONTEXT_CONTROL | CONTEXT_INTEGER


def _amd64_context(rsp: int, rip: int, flags: int = _ALL_AMD64) -> bytes:
    ctx = bytearray(0x4D0)
    struct.pack_into("<I", ctx, 0x30, flags)
    struct.pack_into("<Q", ctx, 0x98, rsp)
    struct.pack_into("<Q", ctx, 0xF8, rip)
    return bytes(ctx)


def _arm64_context(sp: int, pc: int, x18: int) -> bytes:
    ctx = bytearray(912)
    struct.pack_into("<I", ctx, 0, _ALL_ARM64)
    struct.pack_into("<Q", ctx, 0x8 + 18 * 8, x18)
    struct.pack_into("<QQ", ctx, 0x100, sp, pc)
    return bytes(ctx)


def _import_dump(tmp_path: Path, **kwargs) -> Path:
    dmp = tmp_path / "t.dmp"
    dmp.write_bytes(_build_minidump([(0x10000, b"A" * 4096)], **kwargs))
    out = tmp_path / "t.msl"
    import_minidump(dmp, out)
    return out


def test_minidump_amd64_threads_and_exception(tmp_path) -> None:
    out = _import_dump(
        tmp_path, arch=PROCESSOR_ARCHITECTURE_AMD64, threads=_MD_THREADS,
        thread_contexts=[_amd64_context(0x1111, 0x2222),
                         _amd64_context(0x3333, 0x4444)],
        exception_thread_id=0x1A2C)
    contexts = _contexts(out)
    assert [tc.thread_id for tc in contexts] == [0x1A2B, 0x1A2C]
    assert [tc.flags for tc in contexts] == [TC_FLAG_SUSPENDED, _CRASHED_FLAGS]
    regs = _by_name(contexts[1])
    assert (_u64(regs["rsp"]), _u64(regs["rip"])) == (0x3333, 0x4444)
    assert regs["gs_base"].flags == REG_ROLE_TLS
    assert _u64(regs["gs_base"]) == _TEB_B
    assert _cap_bitmap(out) & CapBit.THREAD_CONTEXTS
    _assert_threads_precede_regions(out)


def test_minidump_arm64_x18_tls(tmp_path) -> None:
    out = _import_dump(
        tmp_path, arch=PROCESSOR_ARCHITECTURE_ARM64, threads=_MD_THREADS[:1],
        thread_contexts=[_arm64_context(0x5050, 0xC0C0, _TEB_A)],
        exception_thread_id=0x1A2B)
    [tc] = _contexts(out)
    assert tc.flags == _CRASHED_FLAGS
    regs = _by_name(tc)
    assert (_u64(regs["sp"]), _u64(regs["pc"])) == (0x5050, 0xC0C0)
    assert regs["x18"].flags == REG_ROLE_TLS and _u64(regs["x18"]) == _TEB_A
    _assert_threads_precede_regions(out)


def test_minidump_skips_thread_without_context(tmp_path) -> None:
    out = _import_dump(
        tmp_path, arch=PROCESSOR_ARCHITECTURE_AMD64, threads=_MD_THREADS,
        thread_contexts=[None, _amd64_context(0x3333, 0x4444)])
    [tc] = _contexts(out)
    # No exception stream: the only emitted thread becomes Current.
    assert (tc.thread_id, tc.flags) == (0x1A2C, _SUSPENDED_CURRENT)


def test_minidump_skips_context_without_pc_sp(tmp_path) -> None:
    no_control = _amd64_context(0, 0, CONTEXT_AMD64 | CONTEXT_INTEGER)
    out = _import_dump(
        tmp_path, arch=PROCESSOR_ARCHITECTURE_AMD64, threads=_MD_THREADS,
        thread_contexts=[no_control, b"\x00" * 16])
    assert _contexts(out) == []
    assert not _cap_bitmap(out) & CapBit.THREAD_CONTEXTS


def test_minidump_partial_flag(tmp_path) -> None:
    ctx = _amd64_context(0x10, 0x20,
                         CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER)
    out = _import_dump(tmp_path, arch=PROCESSOR_ARCHITECTURE_AMD64,
                       threads=_MD_THREADS[:1], thread_contexts=[ctx])
    [tc] = _contexts(out)
    assert tc.flags == _SUSPENDED_CURRENT | TC_FLAG_PARTIAL


def test_minidump_no_threads_no_cap_bit(tmp_path) -> None:
    out = _import_dump(tmp_path, arch=PROCESSOR_ARCHITECTURE_AMD64)
    assert _contexts(out) == []
    assert not _cap_bitmap(out) & CapBit.THREAD_CONTEXTS


def test_minidump_x86_emits_nothing(tmp_path) -> None:
    out = _import_dump(
        tmp_path, arch=PROCESSOR_ARCHITECTURE_INTEL, threads=_MD_THREADS[:1],
        thread_contexts=[_amd64_context(1, 2)])
    assert _contexts(out) == []


def test_decoder_round_trip_matches_writer_helper() -> None:
    from memdiver.msl.writer import _build_thread_context_payload
    payload = _build_thread_context_payload(
        9, 0, TC_FLAG_SUSPENDED, ThreadState.STOPPED, 0, "",
        [_reg("pc", 0xABC, REG_ROLE_PC), _reg("sp", 0xDEF, REG_ROLE_SP)])
    tc = decode_thread_context(None, payload, "<")
    assert [(r.name, _u64(r)) for r in tc.registers] == [("pc", 0xABC),
                                                         ("sp", 0xDEF)]
