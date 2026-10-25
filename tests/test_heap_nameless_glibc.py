"""A glibc heap whose map lost the ``[heap]`` label (imported .msl)."""
from __future__ import annotations

import dataclasses

from memdiver.heap.allocators import scudo
from memdiver.heap.allocators.ptmalloc2 import parse_ptmalloc2
from memdiver.heap.detect import detect_in_context
from memdiver.heap.model import AllocatorKind
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh

ARM64_LINUX = TargetPlatform("linux", "arm64", 8, "little", "test")
EXE = "/app/client"
LIBC = "/usr/lib/aarch64-linux-gnu/libc.so.6"


class _Memory:
    platform = ARM64_LINUX

    def __init__(self, heap):
        self.heap = heap

    def read(self, va, n):
        try:
            return self.heap.read(va, n)
        except ValueError:
            return None


def _ctx(heap, *, with_libc=True, heap_name=""):
    va, size, _ = heap.regions[0]
    regions = [
        MappedRegion(va - 0x100000, 0x2000, "r-x", EXE, EXE, True),
        MappedRegion(va, size, "rw-", heap_name, None, True),
    ]
    modules = [EXE]
    if with_libc:
        regions.append(MappedRegion(0xFFFF_8000_0000, 0x1000, "r-x", LIBC, LIBC, True))
        modules.append(LIBC)
    ctx = DetectContext(None, platform=ARM64_LINUX, regions=regions, modules=modules)
    ctx.__dict__["memory"] = _Memory(heap)
    return ctx


def test_nameless_brk_heap_is_walked_whole_as_ptmalloc2():
    heap = sh.glibc_heap()
    ctx = _ctx(heap)
    layout = parse_ptmalloc2(ctx.memory, ctx, ParseOptions())
    assert [(c.va, c.size) for c in layout.chunks] == \
        [(c.va, c.size) for c in heap.chunks]
    assert layout.coverage["bytes_walked"] == heap.tiled_span[1] - heap.tiled_span[0]


def test_detection_prefers_ptmalloc2_over_anonymous_scudo_lookalike():
    ctx = _ctx(sh.glibc_heap())
    assert detect_in_context(ctx).best is AllocatorKind.PTMALLOC2


def test_scudo_fallback_is_off_when_glibc_is_mapped():
    heap = sh.glibc_heap()
    assert scudo._fallback_regions(_ctx(heap)) == []
    assert scudo._fallback_regions(_ctx(heap, with_libc=False)) != []


def test_without_glibc_a_nameless_region_is_not_claimed_by_ptmalloc2():
    ctx = _ctx(sh.glibc_heap(), with_libc=False)
    layout = parse_ptmalloc2(ctx.memory, ctx, ParseOptions())
    assert layout.chunks == ()


def test_named_heap_still_wins_over_the_fallback():
    heap = sh.glibc_heap()
    ctx = _ctx(heap, heap_name="[heap]")
    layout = parse_ptmalloc2(ctx.memory, ctx, ParseOptions())
    assert len(layout.chunks) == len(heap.chunks)
    assert dataclasses.is_dataclass(layout)


def _with_bss_and_shuffled_order(heap):
    ctx = _ctx(heap)
    va, size, _ = heap.regions[0]
    bss = MappedRegion(va - 0x4000, 0x2000, "rw-", "", None, True)  # exe .bss: no heap bytes
    regions = [ctx.regions[1], ctx.regions[2], bss, ctx.regions[0]]   # deliberately unsorted
    shuffled = DetectContext(None, platform=ARM64_LINUX, regions=regions, modules=ctx.modules)
    shuffled.__dict__["memory"] = ctx.memory
    return shuffled, va


def test_bss_continuation_below_the_heap_is_skipped_by_the_content_probe():
    ctx, heap_va = _with_bss_and_shuffled_order(sh.glibc_heap())
    layout = parse_ptmalloc2(ctx.memory, ctx, ParseOptions())
    assert layout.chunks and layout.chunks[0].va == heap_va


def test_first_module_end_ignores_region_order():
    from memdiver.heap.allocators.ptmalloc2 import _first_module_end
    low = MappedRegion(0x1000, 0x1000, "r-x", EXE, EXE, True)
    high = MappedRegion(0x9000, 0x1000, "r-x", LIBC, LIBC, True)
    assert _first_module_end([high, low]) == low.end


def test_standalone_llvm_scudo_keeps_the_fallback_enabled():
    ctx = _ctx(sh.glibc_heap())
    lib = "/system/lib64/libclang_rt.scudo_standalone-aarch64-android.so"
    ctx.modules.append(lib)
    ctx.__dict__.pop("module_basenames", None)
    assert not scudo._foreign_libc_without_scudo(ctx)
