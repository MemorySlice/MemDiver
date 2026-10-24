"""Raw thread-context data exposed by the ELF core and minidump readers.

Covers the bytes the Thread Context decoders in :mod:`msl.thread_registers`
consume: ``pr_reg`` / ``pr_cursig`` / ``NT_ARM_TLS`` from ELF cores and the
per-thread ``CONTEXT`` record + ExceptionStream thread id from minidumps.
"""

from __future__ import annotations

import struct
from pathlib import Path

from memdiver.core.binary_formats.elf_core_reader import (
    EM_AARCH64,
    EM_X86_64,
    ElfCoreReader,
    ThreadInfo,
    _parse_prstatus_cursig,
    _parse_prstatus_pr_reg,
)
from memdiver.core.binary_formats.minidump_reader import (
    MinidumpReader,
    MinidumpThread,
)
from memdiver.msl.thread_registers import (
    CONTEXT_AMD64,
    CONTEXT_CONTROL,
    CONTEXT_INTEGER,
    CONTEXT_SEGMENTS,
    elf_aarch64_prstatus_regs,
    elf_x86_64_prstatus_regs,
    minidump_context_amd64_regs,
)
from tests.fixtures.synth_elf_core import SynthThread, build_core_bytes
from tests.test_minidump_reader import _build_minidump

_SIGSEGV = 11
_X86_RIP, _X86_RSP = 16, 19
_ARM_SP, _ARM_PC = 31, 32


def _write(tmp_path: Path, data: bytes, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _distinct_regs(count: int, seed: int) -> dict:
    return {i: seed + i * 0x10 for i in range(count)}


def _pr_reg_bytes(regs: dict, count: int) -> bytes:
    return b"".join(regs.get(i, 0).to_bytes(8, "little") for i in range(count))


def _open_core(tmp_path: Path, machine: int, threads) -> ElfCoreReader:
    data = build_core_bytes(machine=machine, threads=threads)
    return ElfCoreReader(_write(tmp_path, data, "core"))


def _x86_threads():
    return [
        SynthThread(tid=100, regs=_distinct_regs(27, 0x1000)),
        SynthThread(tid=101, regs=_distinct_regs(27, 0x2000),
                    cursig=_SIGSEGV),
    ]


# -- ELF core -----------------------------------------------------------------


def test_elf_pr_reg_round_trips_per_thread(tmp_path) -> None:
    threads = _x86_threads()
    with _open_core(tmp_path, EM_X86_64, threads) as reader:
        parsed = reader.info.threads
    assert [t.pr_reg for t in parsed] == [
        _pr_reg_bytes(t.regs, 27) for t in threads
    ]
    # sp stays the decoded slot 19 of the same buffer.
    assert [t.sp for t in parsed] == [t.regs[_X86_RSP] for t in threads]


def test_elf_cursig_and_crashed_thread(tmp_path) -> None:
    with _open_core(tmp_path, EM_X86_64, _x86_threads()) as reader:
        info = reader.info
    assert [t.cursig for t in info.threads] == [0, _SIGSEGV]
    assert info.crashed_thread().tid == 101


def test_elf_no_crashed_thread(tmp_path) -> None:
    with _open_core(tmp_path, EM_X86_64, [(7, 0x1000)]) as reader:
        assert reader.info.crashed_thread() is None


def test_elf_stop_signals_are_not_crashes(tmp_path) -> None:
    # gdb gcore records SIGSTOP (19) / SIGTRAP (5) for live, stopped threads.
    threads = [
        SynthThread(tid=200, regs=_distinct_regs(27, 0x1000), cursig=19),
        SynthThread(tid=201, regs=_distinct_regs(27, 0x2000), cursig=5),
    ]
    with _open_core(tmp_path, EM_X86_64, threads) as reader:
        info = reader.info
    assert [t.cursig for t in info.threads] == [19, 5]
    assert info.crashed_thread() is None


def test_elf_crashed_thread_is_first_with_fault_signal(tmp_path) -> None:
    # Kernel cores give every thread the dump signal; the dumping thread is first.
    threads = [
        SynthThread(tid=300, regs=_distinct_regs(27, 0x1000), cursig=_SIGSEGV),
        SynthThread(tid=301, regs=_distinct_regs(27, 0x2000), cursig=_SIGSEGV),
    ]
    with _open_core(tmp_path, EM_X86_64, threads) as reader:
        assert reader.info.crashed_thread().tid == 300


def test_elf_arm_tls_attached_to_preceding_thread(tmp_path) -> None:
    tls = (0xDEAD_BEEF_0000_1000).to_bytes(8, "little") + b"\x00" * 8
    threads = [
        SynthThread(tid=1, sp=0xA000),
        SynthThread(tid=2, sp=0xB000, arm_tls=tls),
        SynthThread(tid=3, sp=0xC000),
    ]
    with _open_core(tmp_path, EM_AARCH64, threads) as reader:
        parsed = reader.info.threads
    assert [t.arm_tls for t in parsed] == [None, tls, None]
    assert [len(t.pr_reg) for t in parsed] == [34 * 8] * 3


def test_elf_raw_fields_excluded_from_equality(tmp_path) -> None:
    with _open_core(tmp_path, EM_X86_64, _x86_threads()) as reader:
        first = reader.info.threads[0]
    assert first == ThreadInfo(100, first.sp)


def test_elf_unknown_machine_has_empty_pr_reg() -> None:
    assert _parse_prstatus_pr_reg(b"\x00" * 336, 0x1234) == b""


def test_elf_short_note_cursig_zero() -> None:
    assert _parse_prstatus_cursig(b"\x00" * 12) == 0


def test_elf_x86_64_pr_reg_decodes_rsp_rip(tmp_path) -> None:
    with _open_core(tmp_path, EM_X86_64, _x86_threads()) as reader:
        crashed = reader.info.crashed_thread()
    regs = {r.name: r for r in elf_x86_64_prstatus_regs(crashed.pr_reg).registers}
    assert int.from_bytes(regs["rsp"].value, "little") == 0x2000 + 19 * 0x10
    assert int.from_bytes(regs["rip"].value, "little") == 0x2000 + 16 * 0x10


def test_elf_aarch64_pr_reg_and_tls_decode(tmp_path) -> None:
    thread = SynthThread(tid=5, regs={_ARM_SP: 0xFFFF_0000, _ARM_PC: 0x4000},
                         arm_tls=(0x7777).to_bytes(8, "little"))
    with _open_core(tmp_path, EM_AARCH64, [thread]) as reader:
        parsed = reader.info.threads[0]
    decoded = elf_aarch64_prstatus_regs(parsed.pr_reg, tls=parsed.arm_tls)
    regs = {r.name: int.from_bytes(r.value, "little") for r in decoded.registers}
    assert (regs["sp"], regs["pc"], regs["tpidr_el0"]) == (0xFFFF_0000, 0x4000,
                                                           0x7777)


# -- Minidump -----------------------------------------------------------------

_MD_THREADS = [
    (0x1A2B, 0x00D1_2345_0000, 0x00D1_0000_0000, 0x10000),
    (0x1A2C, 0x00D1_2346_0000, 0x00D2_0000_0000, 0x8000),
]
_ALL_AMD64 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS


def _amd64_context(rsp: int, rip: int) -> bytes:
    ctx = bytearray(0x4D0)
    struct.pack_into("<I", ctx, 0x30, _ALL_AMD64)
    struct.pack_into("<Q", ctx, 0x98, rsp)
    struct.pack_into("<Q", ctx, 0xF8, rip)
    return bytes(ctx)


def _open_dump(tmp_path: Path, **kwargs) -> MinidumpReader:
    data = _build_minidump([(0x1000, b"ABCD")], **kwargs)
    return MinidumpReader(_write(tmp_path, data, "t.dmp"))


def test_minidump_context_bytes_read_back(tmp_path) -> None:
    contexts = [_amd64_context(0x1111, 0x2222), b"\xAB" * 0x390]
    with _open_dump(tmp_path, threads=_MD_THREADS,
                    thread_contexts=contexts) as reader:
        threads = reader.info.threads
        assert [t.ctx_size for t in threads] == [0x4D0, 0x390]
        assert [reader.read_thread_context(t) for t in threads] == contexts
        # Memory descriptors are unaffected by the appended CONTEXT blobs.
        desc = reader.info.memory_descriptors[0]
        assert reader.read_at(desc.rva, desc.size) == b"ABCD"


def test_minidump_missing_context_reads_empty(tmp_path) -> None:
    with _open_dump(tmp_path, threads=_MD_THREADS,
                    thread_contexts=[None, b"\x01" * 16]) as reader:
        threads = reader.info.threads
        assert reader.read_thread_context(threads[0]) == b""
        assert reader.read_thread_context(threads[1]) == b"\x01" * 16


def test_minidump_out_of_range_context_reads_empty(tmp_path) -> None:
    with _open_dump(tmp_path) as reader:
        bogus = MinidumpThread(1, 0, 0, 0, ctx_rva=reader.size, ctx_size=64)
        assert reader.read_thread_context(bogus) == b""


def test_minidump_exception_thread_id(tmp_path) -> None:
    with _open_dump(tmp_path, threads=_MD_THREADS,
                    exception_thread_id=0x1A2C) as reader:
        assert reader.info.exception_thread_id == 0x1A2C


def test_minidump_without_exception_stream(tmp_path) -> None:
    with _open_dump(tmp_path, threads=_MD_THREADS) as reader:
        assert reader.info.exception_thread_id is None


def test_minidump_amd64_context_decodes_rsp_rip(tmp_path) -> None:
    contexts = [_amd64_context(0x00D1_0000_FF00, 0x7FF6_1234_5678), None]
    with _open_dump(tmp_path, threads=_MD_THREADS, thread_contexts=contexts,
                    exception_thread_id=0x1A2B) as reader:
        info = reader.info
        crashed = next(t for t in info.threads
                       if t.thread_id == info.exception_thread_id)
        ctx = reader.read_thread_context(crashed)
    decoded = minidump_context_amd64_regs(ctx, teb=crashed.teb)
    regs = {r.name: int.from_bytes(r.value, "little") for r in decoded.registers}
    assert decoded.partial is False
    assert regs["rsp"] == 0x00D1_0000_FF00
    assert regs["rip"] == 0x7FF6_1234_5678
    assert regs["gs_base"] == 0x00D1_2345_0000
