"""MappedFile / RunSource keep source pages out of the RSS.

Two strategies, both zero-copy: ``MADV_DONTNEED`` behind the cursor (Linux)
and one short-lived mmap per chunk / scan window (elsewhere). Both are forced here regardless of the
host platform. Behavioural tests only: they check that each path runs and
never corrupts data (released pages re-fault from the file). RSS is not
asserted (platform- and page-cache-dependent; would make the test flaky).
"""

from __future__ import annotations

import mmap
import os
from pathlib import Path

import pytest

from memdiver.msl import import_sources
from memdiver.msl.import_sources import MappedFile, RunBuilder, RunSource
from memdiver.msl.importer import import_dump
from tests.test_importer_streaming import _secret, _snapshot

CHUNK = 64 * 1024


def _pattern_file(path: Path, size: int) -> bytes:
    data = os.urandom(size)
    path.write_bytes(data)
    return data


@pytest.fixture
def madvise_path(monkeypatch):
    """Force the Linux strategy (zero-copy views + MADV_DONTNEED)."""
    monkeypatch.setattr(import_sources, "_DONTNEED_DROPS_PAGES", True)


@pytest.fixture
def window_path(monkeypatch):
    """Force the non-Linux strategy (one mmap per chunk / window)."""
    monkeypatch.setattr(import_sources, "_DONTNEED_DROPS_PAGES", False)


@pytest.fixture
def released(monkeypatch, madvise_path):
    """Record every (offset, length) passed to MappedFile.release."""
    calls = []
    real = MappedFile.release

    def spy(self, offset, length):
        calls.append((offset, length))
        real(self, offset, length)

    monkeypatch.setattr(MappedFile, "release", spy)
    return calls


def test_streamed_chunks_release_previous_chunk(tmp_path, released):
    data = _pattern_file(tmp_path / "src.bin", 8 * CHUNK)
    with MappedFile(tmp_path / "src.bin") as mapped:
        builder = RunBuilder()
        builder.add_file(0, len(data))
        source = RunSource(mapped, builder.runs)
        chunks = [source(off, CHUNK) for off in range(0, len(data), CHUNK)]
        # Every chunk but the last was released once its successor was read.
        assert released == [(off, CHUNK) for off in range(0, 7 * CHUNK, CHUNK)]
        # Released pages re-fault from the file: the views still read true.
        assert b"".join(bytes(c) for c in chunks) == data
        del chunks


def test_assembled_spans_release_copied_file_ranges(tmp_path, released):
    data = _pattern_file(tmp_path / "src.bin", 4 * CHUNK)
    with MappedFile(tmp_path / "src.bin") as mapped:
        builder = RunBuilder()
        builder.add_file(0, CHUNK)
        builder.add_zeros(100)
        builder.add_file(2 * CHUNK, CHUNK)
        out = RunSource(mapped, builder.runs)(0, 2 * CHUNK + 100)
    assert bytes(out) == data[:CHUNK] + b"\0" * 100 + data[2 * CHUNK:3 * CHUNK]
    assert (0, CHUNK) in released and (2 * CHUNK, CHUNK) in released


def test_find_releases_scanned_range_and_still_finds(tmp_path, released):
    data = bytearray(_pattern_file(tmp_path / "src.bin", 4 * CHUNK))
    needle = b"NEEDLE-0123456789"
    data[3 * CHUNK + 5:3 * CHUNK + 5 + len(needle)] = needle
    (tmp_path / "src.bin").write_bytes(data)
    with MappedFile(tmp_path / "src.bin") as mapped:
        assert mapped.find(needle, 0, len(data)) == 3 * CHUNK + 5
        assert released[-1] == (0, len(data))
        assert mapped.find(needle, 0, len(data)) == 3 * CHUNK + 5  # re-faults


@pytest.mark.parametrize("drops_pages", [True, False])
def test_windowed_find_matches_mmap_find(tmp_path, monkeypatch, drops_pages):
    monkeypatch.setattr(import_sources, "_DONTNEED_DROPS_PAGES", drops_pages)
    monkeypatch.setattr(import_sources, "_FIND_WINDOW", 1000)  # many windows
    data = bytearray(_pattern_file(tmp_path / "src.bin", 4 * CHUNK + 77))
    needle = b"straddles-a-window"
    data[2995:2995 + len(needle)] = needle  # crosses the 3000 boundary
    (tmp_path / "src.bin").write_bytes(data)
    with MappedFile(tmp_path / "src.bin") as mapped:
        for start, end in [(0, len(data)), (2995, 3013), (2996, len(data)),
                           (0, 3012), (100, 50), (0, 10 * CHUNK)]:
            assert mapped.find(needle, start, end) == \
                mapped._mmap.find(needle, start, end), (start, end)
        assert mapped.find(b"", 7, 9) == 7


def test_window_stream_view_clamps_like_view(tmp_path, window_path):
    data = _pattern_file(tmp_path / "src.bin", 4 * CHUNK + 77)
    with MappedFile(tmp_path / "src.bin") as mapped:
        chunk = mapped.stream_view(CHUNK, CHUNK)
        assert isinstance(chunk, memoryview)
        assert chunk.obj is not mapped._mmap  # its own window mapping
        assert chunk == data[CHUNK:2 * CHUNK]
        unaligned = mapped.stream_view(CHUNK + 4097, 333)
        assert unaligned == data[CHUNK + 4097:CHUNK + 4430]
        assert mapped.stream_view(4 * CHUNK, CHUNK) == data[4 * CHUNK:]
        assert mapped.stream_view(10 * CHUNK, CHUNK) == b""
        del chunk, unaligned  # mapping outlives nothing; close() must work


def test_window_run_source_round_trip(tmp_path, window_path):
    data = _pattern_file(tmp_path / "src.bin", 3 * CHUNK)
    with MappedFile(tmp_path / "src.bin") as mapped:
        builder = RunBuilder()
        builder.add_file(0, CHUNK)
        builder.add_zeros(10)
        builder.add_file(2 * CHUNK, CHUNK)
        source = RunSource(mapped, builder.runs)
        stream = b"".join(bytes(source(off, min(4096, source.length - off)))
                          for off in range(0, source.length, 4096))
        assert stream == data[:CHUNK] + b"\0" * 10 + data[2 * CHUNK:]
        assert source.find(data[2 * CHUNK + 5:2 * CHUNK + 40]) == CHUNK + 15


def test_release_is_a_noop_without_madvise(tmp_path, monkeypatch, madvise_path):
    monkeypatch.setattr(import_sources, "_MADV_DONTNEED", None)
    data = _pattern_file(tmp_path / "src.bin", CHUNK)
    with MappedFile(tmp_path / "src.bin") as mapped:
        mapped.release(0, CHUNK)
        assert bytes(mapped.stream_view(0, CHUNK)) == data


def test_release_clamps_and_tolerates_odd_ranges(tmp_path):
    _pattern_file(tmp_path / "src.bin", CHUNK + 123)
    with MappedFile(tmp_path / "src.bin") as mapped:
        mapped.release(mmap.PAGESIZE + 7, 10 * CHUNK)  # unaligned, past EOF
        mapped.release(CHUNK + 500, 10)                # wholly past EOF
        mapped.release(0, 0)
    (tmp_path / "empty.bin").write_bytes(b"")
    with MappedFile(tmp_path / "empty.bin") as empty:
        empty.release(0, 4096)


def test_madvise_errors_are_swallowed(tmp_path):
    class _FailingMmap:
        def madvise(self, *args):
            raise OSError("not supported")

    _pattern_file(tmp_path / "src.bin", CHUNK)
    with MappedFile(tmp_path / "src.bin") as mapped:
        real = mapped._mmap
        mapped._mmap = _FailingMmap()
        try:
            mapped.release(0, CHUNK)
        finally:
            mapped._mmap = real


def _content(path: Path):
    """Region rows (minus timestamps) and key hints of an imported .msl."""
    regions, hints, _ = _snapshot(path)
    return [row[:5] + row[6:] for row in regions], hints


@pytest.mark.parametrize("strategy", ["madvise", "window"])
def test_raw_import_output_unchanged_by_release(tmp_path, monkeypatch,
                                                strategy):
    size = 3 * (16 << 20) // 2  # spans more than one 16 MiB writer chunk
    data = bytearray(os.urandom(size))
    secret = b"S" * 32
    data[size - 4096:size - 4096 + 32] = secret
    src = tmp_path / "raw.dump"
    src.write_bytes(data)
    secrets = [_secret(secret)]

    with_release = tmp_path / "a.msl"
    monkeypatch.setattr(import_sources, "_DONTNEED_DROPS_PAGES",
                        strategy == "madvise")
    import_dump(src, with_release, secrets=secrets)
    # Baseline: plain mmap views, no advice.
    monkeypatch.setattr(import_sources, "_DONTNEED_DROPS_PAGES", True)
    monkeypatch.setattr(import_sources, "_MADV_DONTNEED", None)
    without_release = tmp_path / "b.msl"
    import_dump(src, without_release, secrets=secrets)

    expected = _content(without_release)
    assert _content(with_release) == expected
    assert len(expected[1]) == 1
