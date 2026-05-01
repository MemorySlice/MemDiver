"""Tests for chunked streaming string extraction (WS-3a).

Covers:
- Full-scan of small files with the chunked pipeline.
- Cursor-based pagination across multiple calls.
- Correct dedupe of strings straddling a chunk boundary.
- Streaming avoids ``read_all`` on very large inputs.
- Window offset/length restricts which strings are returned.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_server import tools_inspect
from mcp_server.tools_inspect import TAIL_OVERLAP, _extract_strings as extract_strings_tool


class _DummySession:
    """Minimal stand-in for ToolSession — the tool never touches it."""


def _write_bytes(path: Path, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def _make_tempfile(suffix: str = ".dump") -> Path:
    fd, name = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return Path(name)


# --------------------------------------------------------------------------- #
# 1. Small file, full scan through the chunked pipeline.
# --------------------------------------------------------------------------- #
def test_single_small_file_full_scan():
    path = _make_tempfile()
    try:
        payload = b"\x00" * 16 + b"AlphaBravo" + b"\x00" * 16 + b"CharlieDelta" + b"\x00" * 16 + b"EchoFoxtrot" + b"\x00" * 16
        _write_bytes(path, payload)

        result = extract_strings_tool(
            _DummySession(), str(path),
            cursor=0, chunk_size=8 * 1024 * 1024,
        )

        values = [s["value"] for s in result["strings"]]
        assert values == ["AlphaBravo", "CharlieDelta", "EchoFoxtrot"]
        assert result["truncated"] is False
        assert result["next_cursor"] is None
        assert result["window_end"] == len(payload)
        assert result["total_count"] == 3
    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# 2. Pagination via cursor with max_results smaller than total string count.
# --------------------------------------------------------------------------- #
def test_paginated_with_cursor():
    path = _make_tempfile()
    try:
        # 20 distinct 8-char strings separated by NULs. Total file size well
        # under one chunk so the pagination logic is exercised purely by
        # max_results + cursor, not by chunk boundaries.
        parts = []
        for i in range(20):
            parts.append(b"\x00" * 8)
            parts.append(f"STR{i:05d}".encode("ascii"))  # 8 chars
        parts.append(b"\x00" * 8)
        payload = b"".join(parts)
        _write_bytes(path, payload)

        collected = []
        cursor = 0
        calls = 0
        while True:
            calls += 1
            assert calls < 10, "pagination should terminate in <10 calls"
            result = extract_strings_tool(
                _DummySession(), str(path),
                max_results=5, cursor=cursor,
            )
            collected.extend(s["value"] for s in result["strings"])
            if not result["truncated"]:
                assert result["next_cursor"] is None
                break
            assert result["next_cursor"] is not None
            assert result["next_cursor"] > cursor
            cursor = result["next_cursor"]

        assert collected == [f"STR{i:05d}" for i in range(20)]


    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# 3. String straddling the 4 MiB chunk boundary must appear exactly once.
# --------------------------------------------------------------------------- #
def test_string_at_chunk_boundary():
    path = _make_tempfile()
    try:
        chunk = 4 * 1024 * 1024
        straddling = b"S" * 200  # 200 printable bytes; well above min_length
        # Start 100 bytes before the boundary so it straddles evenly.
        start_off = chunk - 100
        end_off = start_off + len(straddling)
        payload = bytearray(b"\x00" * (chunk * 2))
        payload[start_off:end_off] = straddling
        _write_bytes(path, bytes(payload))

        result = extract_strings_tool(
            _DummySession(), str(path),
            chunk_size=chunk, min_length=100,
        )

        hits = [s for s in result["strings"] if s["value"] == straddling.decode("ascii")]
        assert len(hits) == 1, f"expected one hit, got {len(hits)}: {hits}"
        assert hits[0]["offset"] == start_off
    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# 4. Large file: verify ``read_all`` is never called (streaming-only).
# --------------------------------------------------------------------------- #
def test_large_file_does_not_read_all(monkeypatch):
    path = _make_tempfile()
    try:
        # Sparse 100 MiB file with a couple of planted strings.
        size = 100 * 1024 * 1024
        with open(path, "wb") as fh:
            fh.truncate(size)
            fh.seek(1 * 1024 * 1024)
            fh.write(b"PlantedA-string-number-one")
            fh.seek(50 * 1024 * 1024)
            fh.write(b"PlantedB-string-number-two")

        # Monkey-patch read_all on every dump source class so any accidental
        # full-buffer slurp blows up the test immediately.
        import core.dump_source as dump_source_mod

        def _boom(self, *args, **kwargs):  # noqa: ANN001
            raise AssertionError("read_all should never be called by chunked path")

        monkeypatch.setattr(dump_source_mod.RawDumpSource, "read_all", _boom)
        if hasattr(dump_source_mod, "MslDumpSource"):
            monkeypatch.setattr(dump_source_mod.MslDumpSource, "read_all", _boom)

        result = extract_strings_tool(
            _DummySession(), str(path),
            chunk_size=8 * 1024 * 1024, max_results=500,
        )

        values = {s["value"] for s in result["strings"]}
        assert "PlantedA-string-number-one" in values
        assert "PlantedB-string-number-two" in values
    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# 5. Window (offset, length) restricts results.
# --------------------------------------------------------------------------- #
def test_respects_window_offset_length():
    path = _make_tempfile()
    try:
        before = b"\x00" * 32 + b"BeforeWindow" + b"\x00" * 32  # inside [0, 76)
        inside = b"InsideWindowA" + b"\x00" * 16 + b"InsideWindowB" + b"\x00" * 16
        after = b"AfterWindow" + b"\x00" * 32
        payload = before + inside + after
        _write_bytes(path, payload)

        win_offset = len(before)
        win_length = len(inside)

        result = extract_strings_tool(
            _DummySession(), str(path),
            offset=win_offset, length=win_length,
        )

        values = [s["value"] for s in result["strings"]]
        assert "InsideWindowA" in values
        assert "InsideWindowB" in values
        assert "BeforeWindow" not in values
        assert "AfterWindow" not in values
        assert result["window_end"] == win_offset + win_length
        assert result["truncated"] is False
    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Sanity: TAIL_OVERLAP is exposed and sane.
# --------------------------------------------------------------------------- #
def test_tail_overlap_constant_is_reasonable():
    assert TAIL_OVERLAP >= 64
    assert tools_inspect.TAIL_OVERLAP == TAIL_OVERLAP
