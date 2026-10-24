"""Per-thread stack information exposed by the ELF core and minidump readers."""

from __future__ import annotations

import dataclasses
import struct
from pathlib import Path

import pytest

from memdiver.core.binary_formats.elf_core_reader import (
    EM_386,
    EM_AARCH64,
    EM_ARM,
    EM_X86_64,
    ElfCoreReader,
    ThreadInfo,
    _parse_prstatus_sp,
    machine_to_arch_type,
)
from memdiver.core.binary_formats.minidump_reader import (
    THREAD_LIST_STREAM,
    MinidumpReader,
    MinidumpThread,
)
from memdiver.msl.enums import ArchType
from tests.fixtures import synth_elf_core
from tests.test_minidump_reader import _build_minidump

_X86_THREADS = [(4242, 0x7FFD_1234_5670), (4243, 0x7F00_DEAD_BEE0)]
_ARM_THREADS = [(777, 0x0000_FFFF_C0DE_0000)]


def _write(tmp_path: Path, data: bytes, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _open_core(tmp_path: Path, machine: int, threads) -> ElfCoreReader:
    data = synth_elf_core.build_core_bytes(machine=machine, threads=threads)
    return ElfCoreReader(_write(tmp_path, data, "core"))


# -- ELF core -----------------------------------------------------------------


def test_elf_x86_64_threads_and_rsp(tmp_path) -> None:
    with _open_core(tmp_path, EM_X86_64, _X86_THREADS) as reader:
        info = reader.info
        assert info.machine == EM_X86_64
        assert info.threads == [ThreadInfo(tid, sp) for tid, sp in _X86_THREADS]
        assert info.pid == _X86_THREADS[0][0]


def test_elf_aarch64_sp(tmp_path) -> None:
    with _open_core(tmp_path, EM_AARCH64, _ARM_THREADS) as reader:
        assert reader.info.machine == EM_AARCH64
        assert reader.info.threads == [ThreadInfo(777, _ARM_THREADS[0][1])]


def test_elf_unknown_machine_sp_none(tmp_path) -> None:
    with _open_core(tmp_path, 0x1234, [(9, 0xABC)]) as reader:
        assert reader.info.threads == [ThreadInfo(9, None)]


def test_elf_legacy_short_prstatus_keeps_pid(tmp_path) -> None:
    run_dir = synth_elf_core.build(tmp_path / "run_0001")
    with ElfCoreReader(run_dir / "gcore.core") as reader:
        assert reader.info.pid == synth_elf_core._PID
        assert reader.info.threads == [ThreadInfo(synth_elf_core._PID, None)]


def test_parse_prstatus_sp_too_short() -> None:
    assert _parse_prstatus_sp(b"\x00" * 200, EM_X86_64) is None
    assert _parse_prstatus_sp(b"\x00" * 272, EM_X86_64) == 0


def test_thread_info_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        ThreadInfo(1, 2).tid = 3  # type: ignore[misc]


@pytest.mark.parametrize("machine, expected", [
    (EM_X86_64, ArchType.X86_64),
    (EM_AARCH64, ArchType.ARM64),
    (EM_386, ArchType.X86),
    (EM_ARM, ArchType.ARM32),
    (0xBEEF, ArchType.UNKNOWN),
])
def test_machine_to_arch_type(machine, expected) -> None:
    assert machine_to_arch_type(machine) == expected


# -- Minidump -----------------------------------------------------------------

_MD_THREADS = [
    (0x1A2B, 0x0000_00D1_2345_0000, 0x0000_00D1_0000_0000, 0x10000),
    (0x1A2C, 0x0000_00D1_2346_0000, 0x0000_00D2_0000_0000, 0x8000),
]


def test_minidump_thread_list(tmp_path) -> None:
    data = _build_minidump([(0x1000, b"ABCD")], threads=_MD_THREADS)
    with MinidumpReader(_write(tmp_path, data, "t.dmp")) as reader:
        assert reader.info.threads == [
            MinidumpThread(thread_id=t, teb=teb, stack_start=s, stack_size=n)
            for t, teb, s, n in _MD_THREADS
        ]


def test_minidump_without_thread_list(tmp_path) -> None:
    data = _build_minidump([(0x1000, b"ABCD")])
    with MinidumpReader(_write(tmp_path, data, "t.dmp")) as reader:
        assert reader.info.threads == []


def _patch_thread_count(data: bytes, count: int) -> bytes:
    """Overwrite NumberOfThreads in the THREAD_LIST stream body."""
    num_streams, dir_rva = struct.unpack_from("<II", data, 8)
    for i in range(num_streams):
        stype, _size, rva = struct.unpack_from("<III", data, dir_rva + i * 12)
        if stype == THREAD_LIST_STREAM:
            out = bytearray(data)
            struct.pack_into("<I", out, rva, count)
            return bytes(out)
    raise AssertionError("no thread list stream")


def test_minidump_thread_count_overrun_is_clamped(tmp_path) -> None:
    data = _patch_thread_count(
        _build_minidump([(0x1000, b"ABCD")], threads=_MD_THREADS), 0xFFFFFFFF,
    )
    with MinidumpReader(_write(tmp_path, data, "t.dmp")) as reader:
        assert [t.thread_id for t in reader.info.threads] == [0x1A2B, 0x1A2C]


def test_minidump_truncated_thread_list_skipped(tmp_path) -> None:
    # No memory blobs, so the thread list is the final stream body: chop
    # through the second entry so only the first one fits in the file.
    data = _build_minidump([], threads=_MD_THREADS)
    truncated = data[:len(data) - 30]
    with MinidumpReader(_write(tmp_path, truncated, "t.dmp")) as reader:
        assert [t.thread_id for t in reader.info.threads] == [0x1A2B]
