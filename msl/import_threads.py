"""Thread Context extraction for the ELF core / Minidump importers (spec §5.7).

Turns the per-thread register records of an imported dump into
:class:`ImportedThread` values that :func:`add_thread_contexts` writes as
Thread Context blocks (type 0x0011). Spec §11 step (4): importers MAY emit
Thread Context blocks from source-format thread records.

Flag policy (spec Table 19a):
  * ``Suspended`` always: both formats are stopped snapshots.
  * ``Partial`` when the register decoder says the file is incomplete.
  * ``Crashed`` + ``Current`` on the faulting thread (ELF: first thread with
    a non-zero ``pr_cursig``; Minidump: the exception stream's thread).
  * Without a faulting thread, ``Current`` goes on the first emitted thread
    (consumers treat the first block as current anyway; this makes it
    explicit).

A thread whose register record cannot be decoded, or that lacks a
program-counter or stack-pointer register (spec: MUST include both), is
skipped with a debug log. Unsupported architectures emit nothing.
"""

from __future__ import annotations

import logging
from typing import Callable, List, NamedTuple, Optional, Sequence

from memdiver.core.binary_formats.elf_core_reader import (EM_AARCH64,
                                                          EM_X86_64,
                                                          ElfCoreInfo,
                                                          ThreadInfo)
from memdiver.core.binary_formats.minidump_reader import (
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
    MinidumpInfo, MinidumpReader, MinidumpThread)

from .enums import REG_ROLE_PC, REG_ROLE_SP, TC_FLAG_CURRENT
from .thread_registers import (DecodedRegisters, elf_aarch64_prstatus_regs,
                               elf_x86_64_prstatus_regs,
                               minidump_context_amd64_regs,
                               minidump_context_arm64_regs,
                               thread_context_flags)
from .types import MslThreadRegister
from .writer import MslWriter

logger = logging.getLogger("memdiver.msl.import_threads")


class ImportedThread(NamedTuple):
    """One thread ready to be written as a Thread Context block."""
    thread_id: int
    registers: List[MslThreadRegister]
    flags: int


# Candidate thread before flag assignment: (tid, decoded registers, crashed).
class _Candidate(NamedTuple):
    thread_id: int
    decoded: DecodedRegisters
    crashed: bool


def add_thread_contexts(writer: MslWriter,
                        threads: Sequence[ImportedThread]) -> int:
    """Queue one Thread Context block per thread; return the count.

    Call before the first memory region so the blocks precede it. The
    writer sets CapBit.THREAD_CONTEXTS only when at least one is added.
    """
    for thread in threads:
        writer.add_thread_context(thread.thread_id, thread.registers,
                                  flags=thread.flags)
    return len(threads)


# ELF core --------------------------------------------------------------------


def elf_thread_contexts(info: ElfCoreInfo) -> List[ImportedThread]:
    """Thread Context inputs for every decodable ``NT_PRSTATUS`` thread."""
    decode = _elf_decoder(info.machine)
    if decode is None:
        return []
    crashed = info.crashed_thread()
    candidates = []
    for thread in info.threads:
        decoded = _try_decode(thread.tid, lambda t=thread: decode(t))
        if decoded is not None:
            candidates.append(_Candidate(thread.tid, decoded, thread is crashed))
    return _assign_flags(candidates)


def _elf_decoder(machine: int) -> Optional[Callable[[ThreadInfo], DecodedRegisters]]:
    """Register decoder for an ELF e_machine, or None when unsupported."""
    if machine == EM_X86_64:
        return lambda t: elf_x86_64_prstatus_regs(t.pr_reg)
    if machine == EM_AARCH64:
        return lambda t: elf_aarch64_prstatus_regs(t.pr_reg, t.arm_tls)
    return None


# Minidump --------------------------------------------------------------------


def minidump_thread_contexts(reader: MinidumpReader,
                             info: MinidumpInfo) -> List[ImportedThread]:
    """Thread Context inputs for every Minidump thread with a CONTEXT."""
    arch = info.system_info.arch if info.system_info else None
    decode = _minidump_decoder(arch)
    if decode is None:
        return []
    candidates = []
    for thread in info.threads:
        ctx = reader.read_thread_context(thread)
        if not ctx:
            logger.debug("Thread %#x: no CONTEXT record; skipped",
                         thread.thread_id)
            continue
        decoded = _try_decode(thread.thread_id,
                              lambda t=thread, c=ctx: decode(t, c))
        if decoded is not None:
            crashed = thread.thread_id == info.exception_thread_id
            candidates.append(_Candidate(thread.thread_id, decoded, crashed))
    return _assign_flags(candidates)


def _minidump_decoder(
    arch: Optional[int],
) -> Optional[Callable[[MinidumpThread, bytes], DecodedRegisters]]:
    """CONTEXT decoder for a ProcessorArchitecture, or None when unsupported."""
    if arch == PROCESSOR_ARCHITECTURE_AMD64:
        return lambda t, ctx: minidump_context_amd64_regs(ctx, teb=t.teb or None)
    if arch == PROCESSOR_ARCHITECTURE_ARM64:
        return lambda t, ctx: minidump_context_arm64_regs(ctx)
    return None


# Shared ----------------------------------------------------------------------


def _try_decode(thread_id: int,
                decode: Callable[[], DecodedRegisters]) -> Optional[DecodedRegisters]:
    """Decode one thread; None (debug-logged) on error or missing PC/SP."""
    try:
        decoded = decode()
    except ValueError as exc:
        logger.debug("Thread %#x: register decode failed (%s); skipped",
                     thread_id, exc)
        return None
    if not _has_pc_and_sp(decoded.registers):
        logger.debug("Thread %#x: no PC/SP register; skipped", thread_id)
        return None
    return decoded


def _has_pc_and_sp(registers: Sequence[MslThreadRegister]) -> bool:
    roles = 0
    for register in registers:
        roles |= register.flags
    return (roles & REG_ROLE_PC) != 0 and (roles & REG_ROLE_SP) != 0


def _assign_flags(candidates: Sequence[_Candidate]) -> List[ImportedThread]:
    """Apply the module's flag policy; ``Current`` falls back to the first."""
    threads = [
        ImportedThread(c.thread_id, c.decoded.registers, thread_context_flags(
            crashed=c.crashed, current=c.crashed, partial=c.decoded.partial))
        for c in candidates
    ]
    if threads and not any(t.flags & TC_FLAG_CURRENT for t in threads):
        first = threads[0]
        threads[0] = first._replace(flags=first.flags | TC_FLAG_CURRENT)
    return threads
