"""Tests for the DumpSource Protocol and the open_dump detector registry.

These tests use tiny synthetic byte fixtures: ``open_dump`` only *constructs*
the appropriate source (it does not ``open()`` it), so a few header bytes with
the right magic / filename suffix are enough to exercise dispatch without
needing a valid dump body.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest

from memdiver.core import dump_source as ds
from memdiver.core.dump_source import (
    DumpSource,
    RawDumpSource,
    open_dump,
    register_dump_source,
)
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
from memdiver.core.dump_sources.lldb_raw import LldbRawDumpSource
from memdiver.msl.enums import FILE_MAGIC


@pytest.fixture
def isolated_registry():
    """Snapshot the global detector registry and restore it after the test.

    Registration mutates module-global state; this keeps custom test
    registrations from leaking into other tests.
    """
    saved = list(ds._DUMP_SOURCE_REGISTRY)
    try:
        yield
    finally:
        ds._DUMP_SOURCE_REGISTRY[:] = saved


# -- Synthetic fixture builders ---------------------------------------------


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _msl_header() -> bytes:
    # 8-byte MSL magic + padding out to the 18-byte probe window.
    return FILE_MAGIC + b"\x00" * 10


def _elf_core_header() -> bytes:
    # \x7fELF, EI_DATA=1 (little-endian), e_type=ET_CORE(4) at offset 16.
    header = bytearray(b"\x7fELF")
    header += b"\x01"  # EI_CLASS
    header += b"\x01"  # EI_DATA = ELFDATA2LSB
    header += b"\x00" * 10  # pad to offset 16
    header += (4).to_bytes(2, "little")  # e_type == ET_CORE
    return bytes(header)


# -- (c) runtime_checkable Protocol -----------------------------------------


def test_builtin_sources_satisfy_protocol(tmp_path: Path) -> None:
    raw = RawDumpSource(_write(tmp_path / "x.dump", b"abc"))
    gcore = GCoreDumpSource(_write(tmp_path / "x.core", b"abc"))
    gdb = GdbRawDumpSource(_write(tmp_path / "x.gdb_raw.bin", b"abc"))
    lldb = LldbRawDumpSource(_write(tmp_path / "x.lldb_raw.bin", b"abc"))

    # runtime_checkable Protocol: isinstance holds for every built-in source.
    for src in (raw, gcore, gdb, lldb):
        assert isinstance(src, DumpSource)


def test_non_source_object_is_not_a_dump_source() -> None:
    assert not isinstance(object(), DumpSource)
    assert not isinstance("not a source", DumpSource)


# -- (b) built-in precedence unchanged --------------------------------------


def test_dispatch_msl_magic(tmp_path: Path) -> None:
    from memdiver.core.dump_source import MslDumpSource
    src = open_dump(_write(tmp_path / "cap.msl", _msl_header()))
    assert isinstance(src, MslDumpSource)


def test_dispatch_elf_core(tmp_path: Path) -> None:
    # Deliberately non-suffixed name: ELF-core detection must win over any
    # filename-based branch, matching the legacy precedence.
    src = open_dump(_write(tmp_path / "weirdname.bin", _elf_core_header()))
    assert isinstance(src, GCoreDumpSource)


def test_dispatch_gdb_suffix(tmp_path: Path) -> None:
    src = open_dump(_write(tmp_path / "cap.gdb_raw.bin", b"\x00" * 32))
    assert isinstance(src, GdbRawDumpSource)
    assert not isinstance(src, LldbRawDumpSource)


def test_dispatch_lldb_suffix(tmp_path: Path) -> None:
    src = open_dump(_write(tmp_path / "cap.lldb_raw.bin", b"\x00" * 32))
    assert isinstance(src, LldbRawDumpSource)


def test_dispatch_raw_fallback(tmp_path: Path) -> None:
    src = open_dump(_write(tmp_path / "mystery.dump", b"\x01\x02\x03\x04"))
    assert type(src) is RawDumpSource


def test_maps_sidecar_redirects_to_bin(tmp_path: Path) -> None:
    _write(tmp_path / "cap.gdb_raw.bin", b"\x00" * 32)
    maps = _write(tmp_path / "cap.gdb_raw.maps", b"# maps\n")
    src = open_dump(maps)
    assert isinstance(src, GdbRawDumpSource)
    assert src.path.name == "cap.gdb_raw.bin"


def test_lldb_maps_sidecar_redirects_to_bin(tmp_path: Path) -> None:
    # Mirror of the gdb sidecar redirect for the lldb flavour.
    _write(tmp_path / "cap.lldb_raw.bin", b"\x00" * 32)
    maps = _write(tmp_path / "cap.lldb_raw.maps", b"# maps\n")
    src = open_dump(maps)
    assert isinstance(src, LldbRawDumpSource)
    assert src.path.name == "cap.lldb_raw.bin"


# -- ELF-core vs regioned-raw suffix tie-break ------------------------------


def test_elf_core_beats_gdb_suffix(tmp_path: Path) -> None:
    # A file carrying the .gdb_raw.bin suffix but ELF-core *contents*: ELF-core
    # detection (priority 90) must win over the gdb suffix detector (80).
    src = open_dump(_write(tmp_path / "cap.gdb_raw.bin", _elf_core_header()))
    assert isinstance(src, GCoreDumpSource)


def test_elf_core_beats_lldb_suffix(tmp_path: Path) -> None:
    src = open_dump(_write(tmp_path / "cap.lldb_raw.bin", _elf_core_header()))
    assert isinstance(src, GCoreDumpSource)


# -- OSError -> empty-header path still dispatches to raw --------------------


def test_unreadable_file_falls_through_to_raw(tmp_path: Path) -> None:
    # A path that cannot be read yields an empty header (OSError branch); with
    # no magic and a plain name, dispatch must still reach the raw fallback
    # rather than crashing.
    missing = tmp_path / "does_not_exist.dump"
    src = open_dump(missing)
    assert type(src) is RawDumpSource


# -- Faulty detector isolation ----------------------------------------------


def test_faulty_detector_is_isolated(
    isolated_registry, tmp_path: Path, caplog
) -> None:
    def boom(path: Path, header: bytes) -> bool:
        raise RuntimeError("bad detector")

    # Register above every built-in so it is consulted first.
    register_dump_source(boom, lambda p, **_: _DummyDumpSource(p), priority=5000)

    with caplog.at_level(logging.WARNING):
        src = open_dump(_write(tmp_path / "plain.bin", b"\x00\x01\x02\x03"))

    # The faulty detector was logged + skipped; dispatch fell through to raw.
    assert type(src) is RawDumpSource
    assert any("boom" in r.getMessage() for r in caplog.records)

    # A genuine MSL file is still dispatched correctly despite the bad detector.
    from memdiver.core.dump_source import MslDumpSource
    msl = open_dump(_write(tmp_path / "cap.msl", _msl_header()))
    assert isinstance(msl, MslDumpSource)


# -- (a) custom source dispatched via register_dump_source ------------------


class _DummyDumpSource:
    """Minimal source that structurally satisfies :class:`DumpSource`."""

    format_name = "dummy"
    _MAGIC = b"DUMMYFMT"

    def __init__(self, path: Path):
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def size(self) -> int:
        return self._path.stat().st_size

    def size_for(self, view: str = "raw") -> int:
        return self.size

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self) -> "_DummyDumpSource":
        self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def read_range(self, offset: int, length: int, view: str = "raw") -> bytes:
        return self._path.read_bytes()[offset:offset + length]

    def find_all(self, needle: bytes, view: str = "raw") -> List[int]:
        return []

    def iter_ranges(self, *args: Any, **kwargs: Any) -> Iterator[Tuple[int, int, Any]]:
        yield (0, self.size, self._path.read_bytes())

    def metadata(self) -> Dict[str, Any]:
        return {"format": self.format_name, "path": str(self._path)}


def _detect_dummy(path: Path, header: bytes) -> bool:
    return header[:8] == _DummyDumpSource._MAGIC


def test_custom_source_is_dispatched(isolated_registry, tmp_path: Path) -> None:
    register_dump_source(_detect_dummy, lambda path, **_: _DummyDumpSource(path))

    src = open_dump(_write(tmp_path / "thing.bin", _DummyDumpSource._MAGIC + b"payload"))
    assert isinstance(src, _DummyDumpSource)
    # The dummy also structurally satisfies the Protocol.
    assert isinstance(src, DumpSource)


def test_custom_default_priority_beats_raw_but_not_builtins(
    isolated_registry, tmp_path: Path
) -> None:
    register_dump_source(_detect_dummy, lambda path, **_: _DummyDumpSource(path))

    # Non-magic file still falls through to the raw fallback.
    raw = open_dump(_write(tmp_path / "plain.bin", b"\x00\x01\x02\x03"))
    assert type(raw) is RawDumpSource

    # An MSL file is still claimed by the higher-priority built-in MSL detector.
    from memdiver.core.dump_source import MslDumpSource
    msl = open_dump(_write(tmp_path / "cap.msl", _msl_header()))
    assert isinstance(msl, MslDumpSource)


def test_high_priority_custom_detector_preempts_builtin(
    isolated_registry, tmp_path: Path
) -> None:
    # A detector matching MSL magic but registered above the MSL built-in
    # (priority 100) intercepts even a genuine MSL file.
    register_dump_source(
        lambda path, header: header[:8] == FILE_MAGIC,
        lambda path, **_: _DummyDumpSource(path),
        priority=1000,
    )
    src = open_dump(_write(tmp_path / "cap.msl", _msl_header()))
    assert isinstance(src, _DummyDumpSource)


def test_key_material_forwarded_to_factory(isolated_registry, tmp_path: Path) -> None:
    captured: Dict[str, Any] = {}

    def factory(path: Path, **key_material: Any) -> _DummyDumpSource:
        captured.update(key_material)
        return _DummyDumpSource(path)

    register_dump_source(_detect_dummy, factory, priority=1000)
    open_dump(
        _write(tmp_path / "thing.bin", _DummyDumpSource._MAGIC),
        key=b"k", passphrase=b"p", kem_private_key=b"kem",
    )
    assert captured == {"key": b"k", "passphrase": b"p", "kem_private_key": b"kem"}
