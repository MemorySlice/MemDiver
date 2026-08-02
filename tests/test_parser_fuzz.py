"""Hypothesis-based fuzz suite for MemDiver's untrusted-input parsers.

Every parser reachable from an "import an attacker-supplied dump" path is
exercised here with mutated and random bytes. The contract each parser must
honour is TIGHT: malformed input may raise ONLY ``(ValueError,
NotImplementedError)`` — never ``struct.error``, ``IndexError``,
``OverflowError``, or any other raw exception. That is the CLEAN-EXCEPTION
contract these tests actually enforce via ``_assert_only_accepted``: any other
escaping exception (including a ``MemoryError``) FAILS LOUDLY rather than being
swallowed, signalling either an un-hardened boundary or a genuine bug the
maintainer must see.

Process-terminating faults — a segfault, an OOM-kill, or an infinite hang —
cannot be caught by an ``except`` and are therefore NOT asserted here; they are
bounded separately by keeping fuzz inputs small and by the tested
``MAX_REGION_PAGES`` allocation cap (see ``test_check_region_pages_cap``).

File-based parsers (``MinidumpReader``, ``ElfCoreReader``,
``extract_secrets_from_path``, the importer entry points) need a real file on
disk. To avoid mixing pytest's function-scoped ``tmp_path`` fixture with
``@given`` (which trips hypothesis' ``function_scoped_fixture`` health-check),
each test writes bytes to a module-level ``tempfile.NamedTemporaryFile`` helper
and cleans up in a ``finally``.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from memdiver.msl.compress import decompress
from memdiver.msl.enums import CompAlgo
from memdiver.msl.types import MslParseError

from memdiver.core.binary_formats.elf_core_reader import ElfCoreReader
from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    MinidumpReader,
)
from memdiver.core.proc_maps_parser import parse_maps_text
from memdiver.msl.importer import (
    MAX_REGION_PAGES,
    _check_region_pages,
    import_dump,
    import_raw_dump,
)
from memdiver.msl.key_extract import (
    extract_secrets_from_path,
    map_key_type,
    map_protocol,
)
from tests.fixtures.synth_elf_core import _build_core_bytes
from tests.fixtures.generate_msl_fixtures import generate_msl_file
from tests.test_minidump_reader import _build_minidump

# The ONLY exceptions a parser is allowed to raise on malformed input.
ACCEPTED = (ValueError, NotImplementedError)

# Seeds are built once — they are deterministic and small.
_MINIDUMP_SEED = _build_minidump([(0x1000, b"hello!!!"), (0x2000, b"\xDE\xAD\xBE\xEF")])
_ELF_CORE_SEED = _build_core_bytes()
_MSL_SEED = generate_msl_file()

# A richer minidump carrying BOTH a MemoryInfoList and a Memory64List. The
# MemoryInfoList (``mem_infos``) makes ``reader.info.has_memory_info_list``
# True, so ``_derive_regions`` routes each MEM_COMMIT range through
# ``_committed_region_spec`` (the OOM-cap call site + captured/failed page
# accounting), and ``use_memory64=True`` exercises the Memory64List read path.
# Fuzzing this seed covers the minidump importer branch the plain reader/ELF
# seeds miss.
_MINIDUMP_RICH_SEED = _build_minidump(
    [(0x1000, b"hello!!!"), (0x4000, b"\xDE\xAD\xBE\xEF")],
    mem_infos=[
        (0x1000, 0x1000, PAGE_READWRITE, 0x2000, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        (0x4000, 0x4000, PAGE_EXECUTE_READ, 0x1000, MEM_COMMIT,
         PAGE_EXECUTE_READ, MEM_IMAGE),
    ],
    use_memory64=True,
)


# -- Temp-file helpers --------------------------------------------------------


def _run_with_tempfile(data: bytes, fn: Callable[[Path], None], suffix: str = "") -> None:
    """Write ``data`` to a temp file, invoke ``fn(path)``, always clean up."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        tmp.write(data)
        tmp.close()
        fn(Path(tmp.name))
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _new_temp_path(suffix: str = "") -> Path:
    """Return a fresh (closed) temp-file path the caller must unlink."""
    fd, name = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return Path(name)


def _assert_only_accepted(fn: Callable[[], object]) -> None:
    """Call ``fn``; require any exception be an ACCEPTED instance, else re-raise."""
    try:
        fn()
    except ACCEPTED:
        pass  # Contract honoured: a clean rejection.
    except BaseException as exc:  # noqa: BLE001 — deliberate: surface the leak.
        raise AssertionError(
            f"Parser leaked a disallowed exception: {type(exc).__name__}: {exc!r}"
        ) from exc


# -- Byte-mutation strategies -------------------------------------------------


def _flip_byte(seed: bytes, index: int, value: int) -> bytes:
    """Return ``seed`` with one byte replaced (byte-flip mutation)."""
    if not seed:
        return seed
    idx = index % len(seed)
    out = bytearray(seed)
    out[idx] = value & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# 1. proc_maps_parser.parse_maps_text
# ---------------------------------------------------------------------------


@given(st.text(max_size=4096))
def test_proc_maps_arbitrary_text(text: str) -> None:
    """Any text either parses to a list or is rejected with ValueError."""
    try:
        result = parse_maps_text(text)
    except ValueError:
        return
    assert isinstance(result, list)


# Tokens that hammer the split()/int(..., 16) paths inside _parse_line.
_MAPS_TOKENS = st.sampled_from(
    [
        "-", " ", "rwxp", "00000000", "deadbeef", "ffffffffffffffffff",
        "z", "0x", "7f00-", "1000-2000", "\t", "[heap]", "[stack]",
        "0000000000000000-ffffffffffffffff", "", "r-xp 00000000 08:01 1234",
    ]
)


@given(st.lists(st.lists(_MAPS_TOKENS, max_size=8), max_size=32))
def test_proc_maps_corrupt_lines(rows: list[list[str]]) -> None:
    """Semi-structured corrupt lines still yield a list or a ValueError only."""
    text = "\n".join(" ".join(row) for row in rows)
    try:
        result = parse_maps_text(text)
    except ValueError:
        return
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 2. MinidumpReader
# ---------------------------------------------------------------------------


def _open_minidump(path: Path) -> None:
    with MinidumpReader(path):
        pass


@given(st.data())
def test_minidump_byte_flip(data: st.DataObject) -> None:
    """A single flipped byte in a valid minidump never leaks a raw parse error."""
    index = data.draw(st.integers(min_value=0, max_value=len(_MINIDUMP_SEED) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = _flip_byte(_MINIDUMP_SEED, index, value)
    _run_with_tempfile(mutated, lambda p: _assert_only_accepted(lambda: _open_minidump(p)))


@given(st.integers(min_value=0, max_value=len(_MINIDUMP_SEED)))
def test_minidump_truncation(cut: int) -> None:
    """Truncating the seed at any offset is rejected cleanly."""
    mutated = _MINIDUMP_SEED[:cut]
    _run_with_tempfile(mutated, lambda p: _assert_only_accepted(lambda: _open_minidump(p)))


@given(st.binary(max_size=4096))
def test_minidump_random_bytes(blob: bytes) -> None:
    """Arbitrary random bytes never leak a raw parse error."""
    _run_with_tempfile(blob, lambda p: _assert_only_accepted(lambda: _open_minidump(p)))


# ---------------------------------------------------------------------------
# 3. ElfCoreReader
# ---------------------------------------------------------------------------


def _open_elf_core(path: Path) -> None:
    with ElfCoreReader(path):
        pass


@given(st.data())
def test_elf_core_byte_flip(data: st.DataObject) -> None:
    """A single flipped byte in a valid ELF core never leaks a raw parse error."""
    index = data.draw(st.integers(min_value=0, max_value=len(_ELF_CORE_SEED) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = _flip_byte(_ELF_CORE_SEED, index, value)
    _run_with_tempfile(mutated, lambda p: _assert_only_accepted(lambda: _open_elf_core(p)))


@given(st.integers(min_value=0, max_value=len(_ELF_CORE_SEED)))
def test_elf_core_truncation(cut: int) -> None:
    """Truncating the ELF-core seed at any offset is rejected cleanly."""
    mutated = _ELF_CORE_SEED[:cut]
    _run_with_tempfile(mutated, lambda p: _assert_only_accepted(lambda: _open_elf_core(p)))


@given(st.binary(max_size=4096))
def test_elf_core_random_bytes(blob: bytes) -> None:
    """Arbitrary random bytes never leak a raw parse error."""
    _run_with_tempfile(blob, lambda p: _assert_only_accepted(lambda: _open_elf_core(p)))


# ---------------------------------------------------------------------------
# 4. msl.importer
# ---------------------------------------------------------------------------


@given(st.integers(min_value=0, max_value=MAX_REGION_PAGES * 4))
def test_check_region_pages_cap(pages: int) -> None:
    """P0.1 OOM cap: pages > cap -> ValueError; pages <= cap -> no raise."""
    if pages > MAX_REGION_PAGES:
        try:
            _check_region_pages(pages, 0x1000, "committed")
        except ValueError as exc:
            assert "refusing to allocate" in str(exc)
        else:
            raise AssertionError("expected ValueError above the page cap")
    else:
        _check_region_pages(pages, 0x1000, "committed")  # must not raise


@given(st.binary(max_size=4096))
def test_import_raw_dump_random(blob: bytes) -> None:
    """import_raw_dump structurally succeeds on any bytes (ValueError tolerated)."""
    def _do(src: Path) -> None:
        out = _new_temp_path(suffix=".msl")
        try:
            _assert_only_accepted(lambda: import_raw_dump(src, out))
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    _run_with_tempfile(blob, _do, suffix=".dump")


@given(st.data())
def test_import_dump_mutated_elf(data: st.DataObject) -> None:
    """import_dump on a mutated ELF core either succeeds (raw fallback) or ValueErrors."""
    index = data.draw(st.integers(min_value=0, max_value=len(_ELF_CORE_SEED) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = _flip_byte(_ELF_CORE_SEED, index, value)

    def _do(src: Path) -> None:
        out = _new_temp_path(suffix=".msl")
        try:
            _assert_only_accepted(lambda: import_dump(src, out))
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    _run_with_tempfile(mutated, _do, suffix=".core")


@given(st.data())
def test_import_dump_mutated_minidump(data: st.DataObject) -> None:
    """import_dump on a mutated minidump (MemoryInfoList + Memory64List) either
    succeeds or ValueErrors — never leaks a raw parse error.

    The rich seed routes through ``import_minidump`` -> ``_derive_regions`` ->
    ``_committed_region_spec``/``_captured_span_spec`` -> ``reader.read_at``,
    the importer branch the ELF/raw seeds do not reach.
    """
    index = data.draw(st.integers(min_value=0, max_value=len(_MINIDUMP_RICH_SEED) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = _flip_byte(_MINIDUMP_RICH_SEED, index, value)

    def _do(src: Path) -> None:
        out = _new_temp_path(suffix=".msl")
        try:
            _assert_only_accepted(lambda: import_dump(src, out))
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    _run_with_tempfile(mutated, _do, suffix=".dmp")


@given(st.integers(min_value=0, max_value=len(_MINIDUMP_RICH_SEED)))
def test_import_dump_truncated_minidump(cut: int) -> None:
    """Truncating the rich minidump seed at any offset is rejected cleanly."""
    mutated = _MINIDUMP_RICH_SEED[:cut]

    def _do(src: Path) -> None:
        out = _new_temp_path(suffix=".msl")
        try:
            _assert_only_accepted(lambda: import_dump(src, out))
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    _run_with_tempfile(mutated, _do, suffix=".dmp")


# ---------------------------------------------------------------------------
# 5. msl.key_extract
# ---------------------------------------------------------------------------


@given(st.integers())
def test_map_key_type_total(value: int) -> None:
    """map_key_type never raises and always returns a str, for any int."""
    result = map_key_type(value)
    assert isinstance(result, str)


@given(st.integers())
def test_map_protocol_total(value: int) -> None:
    """map_protocol never raises and always returns a str, for any int."""
    result = map_protocol(value)
    assert isinstance(result, str)


@given(st.data())
def test_extract_secrets_mutated_msl(data: st.DataObject) -> None:
    """extract_secrets_from_path on a mutated MSL yields a list or ValueError only."""
    index = data.draw(st.integers(min_value=0, max_value=len(_MSL_SEED) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = _flip_byte(_MSL_SEED, index, value)

    def _do(path: Path) -> None:
        try:
            result = extract_secrets_from_path(path)
        except ACCEPTED:
            return
        except BaseException as exc:  # noqa: BLE001 — surface the leak.
            raise AssertionError(
                f"extract_secrets_from_path leaked {type(exc).__name__}: {exc!r}"
            ) from exc
        assert isinstance(result, list)

    _run_with_tempfile(mutated, _do, suffix=".msl")


# ---------------------------------------------------------------------------
# 6. msl.compress.decompress — DIRECT regression for the P2.3 zstd/lz4 hardening
# ---------------------------------------------------------------------------
# The mutated-MSL fuzz seed carries no compressed blocks, so the decompression
# boundary (the original ZstdError leak this hardening thread started from) is
# only *incidentally* exercised by a byte-flip landing on a block's compression
# flag. These feed malformed compressed bytes straight to decompress() so the
# "raw codec error -> MslParseError" translation is asserted directly, not by
# luck. importorskip guards the optional codec libs (a missing lib raises
# MslParseError too, but for a different reason — we want the decode-error path).


def test_decompress_malformed_zstd_raises_mslparseerror() -> None:
    pytest.importorskip("zstandard")
    with pytest.raises(MslParseError):
        decompress(b"\xff\xff\xff\xff not a valid zstd frame", CompAlgo.ZSTD)


def test_decompress_malformed_lz4_raises_mslparseerror() -> None:
    pytest.importorskip("lz4.frame")
    with pytest.raises(MslParseError):
        decompress(b"\xff\xff\xff\xff not a valid lz4 frame", CompAlgo.LZ4)
