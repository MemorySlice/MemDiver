"""Tests for core/image/adapters.py over fakes (no Volatility image, no ISF)."""

import threading
from types import SimpleNamespace

import pytest

from memdiver.core.image.adapters import (
    UNRESOLVED_NAME,
    PhysicalAdapter,
    Vma,
    _iter_vmas,
    adapter_for_view,
    classify,
    physical_runs,
)
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError, ErrorCategory

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT
SHA = "ab" * 32


# ------------------------------------------------------------ classify

class FakeBelow:
    def __init__(self, valid):
        self._valid = valid     # callable (offset, length) -> bool

    def is_valid(self, offset, length=1):
        return self._valid(offset, length)


class FakeLayer:
    """``segments``: (offset, size, mapped, mapped_size) translated pieces."""

    def __init__(self, segments, valid=lambda o, n: True):
        self.segments = segments
        self.context = SimpleNamespace(layers={"below": FakeBelow(valid)})
        self.mapping_calls = []

    def mapping(self, start, length, ignore_errors=False):
        self.mapping_calls.append((start, length, ignore_errors))
        for off, size, mapped, msize in self.segments:
            yield off, size, mapped, msize, "below"


def _runs(layer, start, length, **kw):
    return [(r.start, r.length, r.state) for r in classify(layer, start, length, **kw)]


def test_classify_fully_translated_is_one_captured_run():
    layer = FakeLayer([(0x1000, 0x2000, 0x9000, 0x2000)])
    assert _runs(layer, 0x1000, 0x2000) == [(0x1000, 0x2000, C)]
    assert layer.mapping_calls == [(0x1000, 0x2000, True)]


def test_classify_marks_leading_middle_and_trailing_gaps_not_resident():
    layer = FakeLayer([(0x2000, 0x1000, 0x9000, 0x1000), (0x4000, 0x1000, 0xA000, 0x1000)])
    assert _runs(layer, 0x1000, 0x6000) == [
        (0x1000, 0x1000, N), (0x2000, 0x1000, C), (0x3000, 0x1000, N),
        (0x4000, 0x1000, C), (0x5000, 0x2000, N)]


def test_classify_with_no_translation_is_all_missing():
    assert _runs(FakeLayer([]), 0x1000, 0x3000) == [(0x1000, 0x3000, N)]


def test_classify_missing_state_is_configurable():
    layer = FakeLayer([(0x2000, 0x1000, 0x9000, 0x1000)])
    runs = _runs(layer, 0x1000, 0x3000, missing=F)
    assert runs == [(0x1000, 0x1000, F), (0x2000, 0x1000, C), (0x3000, 0x1000, F)]


def test_classify_translated_but_unreadable_target_is_failed():
    layer = FakeLayer([(0x1000, 0x1000, 0x9000, 0x1000), (0x2000, 0x1000, 0xA000, 0x1000)],
                      valid=lambda o, n: o == 0x9000)
    assert _runs(layer, 0x1000, 0x2000) == [(0x1000, 0x1000, C), (0x2000, 0x1000, F)]


def test_classify_clips_chunks_overhanging_the_requested_range():
    layer = FakeLayer([(0x0, 0x5000, 0x9000, 0x5000)])
    assert _runs(layer, 0x1000, 0x2000) == [(0x1000, 0x2000, C)]


def test_classify_ignores_chunks_entirely_outside_the_range():
    layer = FakeLayer([(0x0, 0x1000, 0x9000, 0x1000), (0x2000, 0x1000, 0xA000, 0x1000)])
    assert _runs(layer, 0x1000, 0x1000) == [(0x1000, 0x1000, N)]


@pytest.mark.parametrize("segments", [
    [],
    [(0x1800, 0x400, 0x9000, 0x400)],
    [(0x0, 0x1800, 0x9000, 0x1800), (0x2200, 0x2000, 0xA000, 0x2000)],
    [(0x1000, 0x3000, 0x9000, 0x3000), (0x5000, 0x1000, 0xA000, 0x1000)],
])
def test_classify_partitions_the_request_exactly(segments):
    start, length = 0x1000, 0x4000
    runs = list(classify(FakeLayer(segments), start, length))
    assert sum(r.length for r in runs) == length
    cursor = start
    for r in runs:
        assert r.start == cursor and r.length > 0
        cursor = r.end
    assert cursor == start + length


def test_classify_checks_the_mapped_range_in_the_layer_below():
    seen = []
    layer = FakeLayer([(0x1000, 0x1000, 0x9000, 0x1000)],
                      valid=lambda o, n: seen.append((o, n)) or True)
    list(classify(layer, 0x1000, 0x1000))
    assert seen == [(0x9000, 0x1000)]


# ------------------------------------------------------------ physical_runs

def test_physical_runs_flat_layer_is_one_captured_run():
    layer = SimpleNamespace(maximum_address=0xFFF)
    assert physical_runs(layer) == [LayerRun(0, 0x1000, C)]


def test_physical_runs_mapped_layer_gives_one_run_per_segment():
    layer = FakeLayer([(0x1000, 0x1000, 0, 0x1000), (0x8000, 0x2000, 0x1000, 0x2000)])
    layer.maximum_address = 0x9FFF
    assert physical_runs(layer) == [LayerRun(0x1000, 0x1000, C), LayerRun(0x8000, 0x2000, C)]
    assert layer.mapping_calls == [(0, 0xA000, True)]


# ------------------------------------------------------------ _iter_vmas

class FakeVma:
    def __init__(self, start, end, name="a.so", prot="r-x", name_exc=None, vm_file=0):
        self.vm_start, self.vm_end = start, end
        self.vm_file = vm_file
        self._name, self._prot, self._exc = name, prot, name_exc

    def get_name(self, context, task):
        if self._exc:
            raise self._exc
        return self._name

    def get_protection(self):
        return self._prot


def _task(vmas, start_brk=0x5000, brk=0x7000):
    mm = SimpleNamespace(start_brk=start_brk, brk=brk, get_vma_iter=lambda: iter(vmas))
    return SimpleNamespace(mm=mm)


def _vmas(vmas, **brk):
    return list(_iter_vmas(SimpleNamespace(context=object()), _task(vmas, **brk)))


def test_vma_overlapping_the_brk_range_is_labelled_heap():
    out = _vmas([FakeVma(0x1000, 0x2000), FakeVma(0x5000, 0x8000, "x", "rw-"),
                 FakeVma(0x9000, 0xA000)])
    assert [(v.name, v.is_heap) for v in out] == [("a.so", False), ("[heap]", True),
                                                  ("a.so", False)]
    assert out[1] == Vma(0x5000, 0x8000, "[heap]", "rw-", True)


@pytest.mark.parametrize("lo, hi, heap", [
    (0x3000, 0x5000, False),   # ends exactly at start_brk
    (0x3000, 0x5001, True),
    (0x6FFF, 0x9000, True),
    (0x7000, 0x9000, False),   # starts exactly at brk
    (0x5800, 0x6000, True),    # strictly inside
    (0x4000, 0x9000, True),    # strictly contains
])
def test_heap_overlap_boundaries(lo, hi, heap):
    assert _vmas([FakeVma(lo, hi)])[0].is_heap is heap


def test_no_heap_when_start_brk_equals_brk():
    out = _vmas([FakeVma(0x5000, 0x8000)], start_brk=0x6000, brk=0x6000)
    assert out[0].is_heap is False and out[0].name == "a.so"


def test_a_vma_whose_name_raises_is_unresolved_not_fatal():
    out = _vmas([FakeVma(0x1000, 0x2000, name_exc=RuntimeError("smashed dentry")),
                 FakeVma(0x2000, 0x3000, name="libc.so")])
    assert [v.name for v in out] == [UNRESOLVED_NAME, "libc.so"]


def test_an_anonymous_vma_has_an_empty_name():
    assert _vmas([FakeVma(0x1000, 0x2000, name=None)])[0].name == ""


def test_the_heap_label_skips_the_name_lookup():
    out = _vmas([FakeVma(0x5000, 0x6000, name_exc=RuntimeError("never asked"))])
    assert out[0].name == "[heap]"


# ------------------------------------------------------------ adapter_for_view

def _image_ctx(has_kernel=False):
    layer = SimpleNamespace(maximum_address=0xFFF)
    return SimpleNamespace(has_kernel=has_kernel, lock=threading.RLock(), physical_layer="phys",
                           context=SimpleNamespace(layers={"phys": layer}))


def _descriptor(kind):
    if kind is ViewKind.PROCESS:
        return ViewDescriptor("i", SHA, kind, pid=1, profile=ProfileRef("p.json"))
    if kind is ViewKind.KERNEL:
        return ViewDescriptor("i", SHA, kind, profile=ProfileRef("p.json"))
    return ViewDescriptor("i", SHA, kind)


@pytest.mark.parametrize("kind", [ViewKind.KERNEL, ViewKind.PROCESS])
def test_kernel_and_process_views_need_a_kernel_profile(kind):
    with pytest.raises(CapabilityError) as info:
        adapter_for_view(_image_ctx(has_kernel=False), _descriptor(kind))
    assert info.value.category is ErrorCategory.UNSUPPORTED
    assert kind.value in str(info.value)


def test_physical_view_needs_no_kernel():
    adapter = adapter_for_view(_image_ctx(has_kernel=False), _descriptor(ViewKind.PHYSICAL))
    assert isinstance(adapter, PhysicalAdapter)
    assert adapter.runs() == [LayerRun(0, 0x1000, C)]


def test_physical_adapter_reads_through_the_layer_unpadded():
    calls = []
    layer = SimpleNamespace(maximum_address=0xFFF,
                            read=lambda a, n, pad=True: calls.append((a, n, pad)) or b"x" * n)
    ctx = SimpleNamespace(has_kernel=False, lock=threading.RLock(), physical_layer="phys",
                          context=SimpleNamespace(layers={"phys": layer}))
    assert PhysicalAdapter(ctx).read(0x10, 4) == b"xxxx"
    assert calls == [(0x10, 4, False)]


# -- page-state policy for absent pages (MSL spec v1.1 Table 35) -----------------

class _PteLayer:
    """translate() fails like vol3: empty entry at a 2 MiB level, swap entry per page."""

    def __init__(self, swapped_pages=()):
        self._swapped = set(swapped_pages)

    def translate(self, address):
        from volatility3.framework import exceptions
        page = address & ~0xFFF
        if page in self._swapped:
            raise exceptions.PagedInvalidAddressException("l", address, 12, 0x1234_5000, "swap")
        raise exceptions.PagedInvalidAddressException("l", address, 21, 0, "none")


def test_pte_gap_runs_empty_entries_are_not_resident_and_skip_whole_blocks():
    from memdiver.core.image.adapters import pte_gap_runs
    runs = list(pte_gap_runs(_PteLayer(), 0x1000, 0x400000))
    assert {r.state for r in runs} == {RunState.NOT_RESIDENT}
    assert sum(r.length for r in runs) == 0x400000
    assert len(runs) <= 4  # 2 MiB blocks, not 1024 pages


def test_pte_gap_runs_swap_entries_are_failed_never_zero_content():
    from memdiver.core.image.adapters import pte_gap_runs
    runs = list(pte_gap_runs(_PteLayer(swapped_pages={0x3000}), 0x3000, 0x1000))
    assert [(r.start, r.length, r.state) for r in runs] == [(0x3000, 0x1000, RunState.FAILED)]


def test_file_backed_vma_gaps_are_failed_and_anonymous_use_pte_split():
    from memdiver.core.image.adapters import Vma, _vma_gap_policy, pte_gap_runs
    assert _vma_gap_policy(Vma(0, 0x1000, "/lib/x.so", "r-x", False, True)) is RunState.FAILED
    assert _vma_gap_policy(Vma(0, 0x1000, "", "rw-", False, False)) is pte_gap_runs


def test_unreadable_vm_file_is_treated_as_file_backed():
    from memdiver.core.image.adapters import _is_file_backed

    class Broken:
        @property
        def vm_file(self):
            raise ValueError("smashed")
    assert _is_file_backed(Broken()) is True


def test_classify_with_missing_none_drops_untranslated_gaps():
    runs = list(classify(FakeLayer([(0x2000, 0x1000, 0x9000, 0x1000)]), 0x1000, 0x3000,
                         missing=None))
    assert [(r.start, r.length) for r in runs] == [(0x2000, 0x1000)]
