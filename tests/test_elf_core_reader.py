"""Tests for :mod:`core.binary_formats.elf_core_reader`."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.binary_formats.elf_core_reader import (
    ElfCoreReader,
    _align4,
    _align_padding,
    _parse_nt_file,
    _parse_prstatus_pid,
)
from tests._paths import SKIP_REASON, dataset_root


def test_align4_helpers() -> None:
    assert _align4(0) == 0
    assert _align4(1) == 4
    assert _align4(4) == 4
    assert _align4(5) == 8
    assert _align_padding(5) == 3
    assert _align_padding(4) == 0


def test_parse_prstatus_pid_layout() -> None:
    """``pr_pid`` lives at offset 32 in the elf_prstatus struct."""
    buf = bytearray(120)
    buf[32:36] = (65219).to_bytes(4, "little", signed=True)
    assert _parse_prstatus_pid(bytes(buf)) == 65219


def test_parse_prstatus_pid_too_short() -> None:
    assert _parse_prstatus_pid(b"") is None


def test_parse_nt_file_empty_desc() -> None:
    assert _parse_nt_file(b"") == []


def test_parse_nt_file_synthetic() -> None:
    """Hand-build a tiny NT_FILE payload with one mapping."""
    count = (1).to_bytes(8, "little")
    page_size = (4096).to_bytes(8, "little")
    start = (0x400000).to_bytes(8, "little")
    end = (0x401000).to_bytes(8, "little")
    file_ofs_pages = (0).to_bytes(8, "little")
    names = b"/usr/bin/example\x00"
    payload = count + page_size + start + end + file_ofs_pages + names

    entries = _parse_nt_file(payload)
    assert len(entries) == 1
    assert entries[0].start == 0x400000
    assert entries[0].end == 0x401000
    assert entries[0].path == "/usr/bin/example"


def test_open_real_gcore() -> None:
    """Open a real ``gcore.core`` and assert we parsed plausible data."""
    root = dataset_root()
    if root is None:
        pytest.skip(SKIP_REASON)
    core_path = (
        root / "dataset_memory_slice" / "gocryptfs"
        / "dataset_gocryptfs" / "run_0001" / "gcore.core"
    )
    if not core_path.is_file():
        pytest.skip("Real gcore.core not present at expected path")

    reader = ElfCoreReader(core_path)
    try:
        reader.open()
        info = reader.info
        assert len(info.segments) > 10
        assert info.pid is not None and info.pid > 0
        assert len(info.file_mappings) >= 1
        # A basic read: the file must start with \x7fELF.
        header = reader.read_at(0, 4)
        assert header == b"\x7fELF"
    finally:
        reader.close()


def test_open_non_core_raises(tmp_path: Path) -> None:
    """Feeding a non-ELF file surfaces a clear error."""
    bad = tmp_path / "not_elf.bin"
    bad.write_bytes(b"XYZ1" + b"\x00" * 256)

    reader = ElfCoreReader(bad)
    with pytest.raises(ValueError):
        reader.open()
    reader.close()
