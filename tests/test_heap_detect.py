"""Tests for heap/detect.py: allocator detection from names, modules and OS."""

from pathlib import Path

import pytest

from memdiver.core.dump_source import RawDumpSource
from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
from memdiver.heap.detect import (DetectionResult, detect_allocator,
                                  rank_candidates)
from memdiver.heap.model import AllocatorKind
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.registry import DetectContext
from tests.fixtures import synth_raw_regions
from tests.fixtures.android.generate_app_process_bin import \
    write_app_process_bin

PAGE = 0x1000
LINUX = TargetPlatform("linux", "x86_64", 8, "little", "test")
ANDROID = TargetPlatform("android", "arm64", 8, "little", "test")


def _write_regioned(tmp_path: Path, names) -> Path:
    """A gdb_raw ``.bin`` + ``.maps`` pair with one page per name."""
    lines = []
    for idx, name in enumerate(names):
        start = 0x10000000 + idx * 0x10000
        lines.append(f"{start:08x}-{start + PAGE:08x} rw-p 00000000 00:00 0 {name}")
    bin_path = tmp_path / "gdb_raw.bin"
    bin_path.write_bytes(bytes(PAGE * len(names)))
    bin_path.with_suffix(".maps").write_text("\n".join(lines) + "\n")
    return bin_path


def _detect_regioned(bin_path: Path, **kwargs) -> DetectionResult:
    with GdbRawDumpSource(bin_path, bin_path.with_suffix(".maps")) as src:
        return detect_allocator(src, **kwargs)


def _ctx(names, platform=LINUX) -> DetectContext:
    regions = [MappedRegion(0x1000 * i, PAGE, "rw-", name,
                            name if name.startswith("/") else None, True)
               for i, name in enumerate(names)]
    return DetectContext(None, platform=platform, regions=regions)


def _scores(ctx: DetectContext):
    return {c.kind: c.score for c in rank_candidates(ctx)}


def test_android_app_process_is_scudo(tmp_path):
    result = _detect_regioned(write_app_process_bin(tmp_path / "app.bin"))
    assert result.best is AllocatorKind.SCUDO
    assert result.platform.is_android
    assert result.confidence > 0.8
    details = [e.detail for e in result.candidates[0].evidence]
    assert any("scudo" in d for d in details)


def test_android_libc_malloc_not_jemalloc_when_scudo_named(tmp_path):
    result = _detect_regioned(write_app_process_bin(tmp_path / "app.bin"))
    scores = {c.kind: c.score for c in result.candidates}
    assert scores[AllocatorKind.JEMALLOC] == 0.0


def test_linux_heap_with_glibc_is_ptmalloc2(tmp_path):
    run = synth_raw_regions.build(tmp_path)
    result = _detect_regioned(run / "gdb_raw.bin")
    assert result.best is AllocatorKind.PTMALLOC2
    assert result.confidence == pytest.approx(0.85)
    sources = {e.source for e in result.candidates[0].evidence}
    assert {"module", "region"} <= sources


def test_musl_module_is_mallocng(tmp_path):
    bin_path = _write_regioned(
        tmp_path, ["/lib/ld-musl-x86_64.so.1", "[heap]", "[stack]"])
    result = _detect_regioned(bin_path)
    assert result.best is AllocatorKind.MALLOCNG


def test_raw_source_is_unknown(tmp_path):
    path = tmp_path / "flat.dump"
    path.write_bytes(bytes(range(256)))
    with RawDumpSource(path) as src:
        result = detect_allocator(src)
    assert result.best is AllocatorKind.UNKNOWN
    assert result.confidence == 0.0


def test_map_without_signals_is_generic(tmp_path):
    result = _detect_regioned(_write_regioned(tmp_path, ["", "[stack]"]))
    assert result.best is AllocatorKind.GENERIC
    assert result.confidence < 0.2


def test_hint_overrides_detection(tmp_path):
    run = synth_raw_regions.build(tmp_path)
    result = _detect_regioned(run / "gdb_raw.bin", hint="jemalloc")
    assert result.best is AllocatorKind.JEMALLOC
    assert result.confidence == 1.0 and result.hinted
    assert result.candidates[0].evidence[0].detail == "user hint"


def test_unknown_hint_raises(tmp_path):
    path = tmp_path / "flat.dump"
    path.write_bytes(b"\0" * 64)
    with RawDumpSource(path) as src, pytest.raises(ValueError):
        detect_allocator(src, hint="tcmalloc")


def test_to_dict_is_json_shaped(tmp_path):
    run = synth_raw_regions.build(tmp_path)
    data = _detect_regioned(run / "gdb_raw.bin").to_dict()
    assert data["best"] == "ptmalloc2"
    assert data["platform"]["os"] == "linux"
    assert data["candidates"][0]["evidence"][0]["source"] == "module"
    assert {c["kind"] for c in data["candidates"]} >= {"scudo", "generic"}


# -- individual signals on synthetic contexts -------------------------------------


def test_pre11_bionic_libc_malloc_is_jemalloc():
    ctx = _ctx(["[anon:libc_malloc]", "/system/lib64/libc.so"], ANDROID)
    scores = _scores(ctx)
    assert max(scores, key=lambda k: scores[k]) is AllocatorKind.JEMALLOC


def test_libjemalloc_module_is_jemalloc():
    scores = _scores(_ctx(["/usr/lib/libjemalloc.so.2", "[heap]"]))
    assert scores[AllocatorKind.JEMALLOC] > scores[AllocatorKind.PTMALLOC2]


def test_libscudo_module_scores_scudo():
    assert _scores(_ctx(["/usr/lib/libscudo.so"]))[AllocatorKind.SCUDO] >= 0.6


def test_old_glibc_name_scores_ptmalloc2():
    scores = _scores(_ctx(["/lib/x86_64-linux-gnu/libc-2.27.so"]))
    assert scores[AllocatorKind.PTMALLOC2] == pytest.approx(0.6)


def test_android_heap_region_is_not_ptmalloc2():
    scores = _scores(_ctx(["[heap]"], ANDROID))
    assert scores[AllocatorKind.PTMALLOC2] == 0.0
    assert scores[AllocatorKind.SCUDO] > 0.0
