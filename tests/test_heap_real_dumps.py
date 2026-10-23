"""Opt-in sanity checks of heap detection/analysis on real dumps.

Skipped unless ``MEMDIVER_REAL_HEAP_DUMPS`` names a directory. Every dump
file in it (``.msl``, ELF cores, ``*.gdb_raw.bin`` / ``*.lldb_raw.bin``, raw
``.bin``/``.dump``) is opened with ``open_dump``. An optional sidecar
``<dump>.expect.json`` ``{"allocator": "ptmalloc2", "min_chunks": 100}``
tightens the assertions.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_ENV = "MEMDIVER_REAL_HEAP_DUMPS"
_SKIP_SUFFIXES = (".maps", ".json", ".txt", ".md", ".log", ".csv")


def _dump_files():
    root = os.environ.get(_ENV)
    if not root or not Path(root).is_dir():
        return []
    return sorted(p for p in Path(root).iterdir()
                  if p.is_file() and not p.name.endswith(_SKIP_SUFFIXES))


pytestmark = pytest.mark.skipif(
    not os.environ.get(_ENV) or not Path(os.environ[_ENV]).is_dir(),
    reason=f"set {_ENV} to a directory of real dumps to run",
)

DUMPS = _dump_files()


def _expectations(dump: Path) -> dict:
    sidecar = dump.with_name(dump.name + ".expect.json")
    return json.loads(sidecar.read_text()) if sidecar.exists() else {}


@pytest.fixture
def source(request):
    from memdiver.core.dump_source import open_dump

    src = open_dump(request.param)
    src.open()
    yield src
    src.close()


@pytest.mark.parametrize("source", DUMPS, ids=lambda p: p.name, indirect=True)
def test_detect_allocator(source):
    detect = pytest.importorskip("memdiver.heap.detect")
    result = detect.detect_allocator(source)
    assert result.candidates, "detection returned no candidate"
    assert 0.0 <= result.confidence <= 1.0
    expected = _expectations(Path(source.path)).get("allocator")
    if expected:
        assert result.best.value == expected


@pytest.mark.parametrize("source", DUMPS, ids=lambda p: p.name, indirect=True)
def test_analyze_heap(source):
    analyze = pytest.importorskip("memdiver.heap.analyze")
    layout = analyze.analyze_heap(source)
    chunks = layout.chunks
    for prev, cur in zip(chunks, chunks[1:]):
        assert prev.va + prev.size <= cur.va, f"overlap at {cur.va:#x}"
    assert layout.coverage, "coverage not reported"
    expect = _expectations(Path(source.path))
    if "allocator" in expect:
        assert layout.allocator.value == expect["allocator"]
    assert len(chunks) >= expect.get("min_chunks", 0)
