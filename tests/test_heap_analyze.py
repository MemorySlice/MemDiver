"""Tests for heap/analyze.py: the analyze_heap facade, fallback and cache."""
from __future__ import annotations

import os

import pytest

from memdiver.heap import analyze as analyze_mod
from memdiver.heap.analyze import (analyze_heap, clear_heap_cache,
                                   heap_cache_size, parse_allocator_hint)
from memdiver.heap.model import AllocatorKind, HeapLayout
from memdiver.heap.registry import (AllocatorDescriptor, DetectScore,
                                    get_allocator, register_allocator)
from tests.fixtures import synth_heap as sh


@pytest.fixture(autouse=True)
def _fresh_cache():
    clear_heap_cache()
    yield
    clear_heap_cache()


def _dump(tmp_path, builder, stem="synth"):
    return sh.as_regioned_raw(tmp_path, [builder()], stem=stem)


def _attempts(layout: HeapLayout):
    return [a["allocator"] for a in layout.coverage["analysis"]["attempts"]]


@pytest.mark.parametrize("builder, expected", [
    (sh.glibc_heap, AllocatorKind.PTMALLOC2),
    (sh.scudo_primary, AllocatorKind.SCUDO),
    (sh.mallocng_group, AllocatorKind.MALLOCNG),
    (sh.jemalloc_slab, AllocatorKind.JEMALLOC),
    (sh.dlmalloc_heap, AllocatorKind.DLMALLOC),
])
def test_auto_picks_the_fixture_allocator(tmp_path, builder, expected):
    heap = builder()
    layout = analyze_heap(sh.as_regioned_raw(tmp_path, [heap]))
    assert layout.allocator is expected
    # Parsers may add allocator-metadata chunks (mallocng meta areas).
    assert {c.va for c in heap.chunks} <= {c.va for c in layout.chunks}
    assert layout.coverage["analysis"]["fell_back"] is False
    assert layout.coverage["analysis"]["detected"] == expected.value
    assert layout.evidence, "detection evidence is attached to the layout"
    assert layout.platform is not None


def test_accepts_an_opened_source(tmp_path):
    source = sh.open_regioned(_dump(tmp_path, sh.glibc_heap))
    try:
        layout = analyze_heap(source)
    finally:
        source.close()
    assert layout.allocator is AllocatorKind.PTMALLOC2


def test_random_region_is_empty_generic_layout_not_an_error(tmp_path):
    layout = analyze_heap(_dump(tmp_path, sh.random_region))
    assert layout.chunks == ()
    assert layout.allocator is AllocatorKind.GENERIC
    assert "generic: parser found no chunks" in layout.diagnostics


def test_wrong_hint_falls_back_to_generic_with_diagnostics(tmp_path):
    layout = analyze_heap(_dump(tmp_path, sh.glibc_heap), "scudo")
    assert layout.allocator is AllocatorKind.GENERIC
    assert layout.chunks
    assert _attempts(layout) == ["scudo", "generic"]
    assert layout.coverage["analysis"]["fell_back"] is True
    assert layout.coverage["analysis"]["requested"] == "scudo"
    assert "scudo: parser found no chunks" in layout.diagnostics
    assert "fell back from scudo to generic" in layout.diagnostics


def test_wrong_hint_with_no_usable_parser_keeps_the_hinted_layout(tmp_path):
    layout = analyze_heap(_dump(tmp_path, sh.scudo_primary), "mallocng")
    assert layout.chunks == ()
    assert layout.allocator is AllocatorKind.MALLOCNG
    assert _attempts(layout) == ["mallocng", "generic"]


def test_hint_is_case_insensitive_and_accepts_the_enum(tmp_path):
    path = _dump(tmp_path, sh.scudo_primary)
    assert analyze_heap(path, "SCUDO").allocator is AllocatorKind.SCUDO
    assert analyze_heap(path, AllocatorKind.SCUDO).allocator is AllocatorKind.SCUDO


def test_unknown_allocator_name_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="unknown allocator"):
        analyze_heap(_dump(tmp_path, sh.glibc_heap), "tcmalloc")


@pytest.mark.parametrize("value, expected", [
    ("auto", None), (None, None), ("", None), (" Auto ", None),
    ("ptmalloc2", AllocatorKind.PTMALLOC2),
    (AllocatorKind.GENERIC, AllocatorKind.GENERIC),
])
def test_parse_allocator_hint(value, expected):
    assert parse_allocator_hint(value) is expected


@pytest.fixture
def raising_scudo():
    """Swap the scudo parser for one that raises; restore it afterwards."""
    original = get_allocator(AllocatorKind.SCUDO)

    def _boom(mem, ctx, opts):
        raise RuntimeError("synthetic parser failure")

    register_allocator(AllocatorDescriptor(
        AllocatorKind.SCUDO, detect=lambda ctx: DetectScore(1.0),
        parse=_boom, priority=99))
    yield
    register_allocator(original)


def test_raising_parser_falls_down_the_ranked_candidates(tmp_path, raising_scudo):
    layout = analyze_heap(_dump(tmp_path, sh.glibc_heap))
    assert layout.allocator is AllocatorKind.PTMALLOC2
    first = layout.coverage["analysis"]["attempts"][0]
    assert first["allocator"] == "scudo"
    assert "synthetic parser failure" in first["error"]
    assert any(d.startswith("scudo: parser raised") for d in layout.diagnostics)
    assert "fell back from scudo to ptmalloc2" in layout.diagnostics


def test_detection_failure_never_raises(tmp_path, monkeypatch):
    def _broken(ctx, hint="auto"):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(analyze_mod, "detect_in_context", _broken)
    layout = analyze_heap(_dump(tmp_path, sh.glibc_heap))
    assert layout.allocator is AllocatorKind.GENERIC
    assert any("detector exploded" in d for d in layout.diagnostics)


# -- cache ------------------------------------------------------------------------


def _count_detections(monkeypatch):
    calls = []
    real = analyze_mod.detect_in_context

    def _counting(ctx, hint="auto"):
        calls.append(hint)
        return real(ctx, hint)

    monkeypatch.setattr(analyze_mod, "detect_in_context", _counting)
    return calls


def test_cache_hit_returns_the_same_layout(tmp_path, monkeypatch):
    calls = _count_detections(monkeypatch)
    path = _dump(tmp_path, sh.glibc_heap)
    first = analyze_heap(path)
    second = analyze_heap(str(path))
    assert second is first
    assert len(calls) == 1
    assert heap_cache_size() == 1


def test_cache_key_covers_every_option(tmp_path, monkeypatch):
    calls = _count_detections(monkeypatch)
    path = _dump(tmp_path, sh.glibc_heap)
    analyze_heap(path)
    analyze_heap(path, "generic")
    analyze_heap(path, max_chunks=3)
    analyze_heap(path, regions=["[heap]"])
    analyze_heap(path, base_va=0x1000)
    assert len(calls) == 5


def test_cache_invalidated_when_file_changes(tmp_path, monkeypatch):
    calls = _count_detections(monkeypatch)
    path = _dump(tmp_path, sh.glibc_heap)
    analyze_heap(path)
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    analyze_heap(path)
    assert len(calls) == 2


def test_cache_is_bounded_lru(tmp_path):
    path = _dump(tmp_path, sh.glibc_heap)
    for max_chunks in range(1, analyze_mod.CACHE_SIZE + 3):
        analyze_heap(path, max_chunks=max_chunks)
    assert heap_cache_size() == analyze_mod.CACHE_SIZE


def test_clear_heap_cache(tmp_path):
    analyze_heap(_dump(tmp_path, sh.glibc_heap))
    clear_heap_cache()
    assert heap_cache_size() == 0


def test_encrypted_sources_bypass_the_cache():
    from memdiver.msl.enums import TagStatus

    class _Keyed:
        path = __file__
        tag_status = TagStatus.VALID

    assert analyze_mod._source_cache_key(
        _Keyed(), None, None, analyze_mod.ParseOptions()) is None


def test_pathless_sources_bypass_the_cache():
    class _Pathless:
        pass

    assert analyze_mod._source_cache_key(
        _Pathless(), None, None, analyze_mod.ParseOptions()) is None
