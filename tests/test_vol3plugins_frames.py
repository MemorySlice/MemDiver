"""vol3plugins/memdiver/frames.py: the single-walk page-frame iterator and zero-page lookup.

Driven by synthetic x86_64 4-level page tables under a REAL vol3 ``LinuxIntel32e`` layer
(tests/_synthetic_pagetables.py), so vol3's own ``_translate_entry`` is exercised.
"""
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins.memdiver import frames as F  # noqa: E402
from tests._synthetic_pagetables import (  # noqa: E402
    ACCESSED, DIRTY, NX, P, PROTNONE, PSE, RW, SAVED_DIRTY, USER,
    PageTables, PhysMemory, layer, protnone_pte, pte, swap_pte,
)

BASE = 0x7F0000000000
THP_VA = 0x7F0000200000
DATA = 0x400000
THP_PA = 0x600000


@pytest.fixture
def mem():
    return PhysMemory()


def _frames(lay, start, end):
    return list(F.page_frames(lay, start, end))


def _covered(frames):
    return sum(f.length for f in frames)


def test_present_4k_page_gives_pfn_entry_and_flags(mem):
    pt = PageTables(mem)
    pt.map4k(BASE, DATA, P | RW | USER | ACCESSED | DIRTY | NX)
    (frame,) = _frames(layer(mem, pt), BASE, BASE + 0x1000)
    assert (frame.va, frame.pfn, frame.page_size, frame.state) == (BASE, DATA >> 12, 4096,
                                                                    F.RESIDENT)
    assert F.entry_is_writable(frame.entry) and F.entry_is_dirty(frame.entry)


def test_thp_leaf_yields_one_record_per_4k_subpage_from_one_walk(mem):
    pt = PageTables(mem)
    pt.set_pmd(THP_VA, pte(THP_PA, P | USER | ACCESSED | DIRTY | PSE))
    lay = layer(mem, pt)
    calls = []
    real = lay._translate_entry

    def counting(va):
        calls.append(va)
        return real(va)

    lay._translate_entry = counting
    frames = _frames(lay, THP_VA, THP_VA + (2 << 20))
    assert len(frames) == 512 and len(calls) == 2  # one probe + one walk for the leaf
    assert [f.pfn for f in frames] == list(range(THP_PA >> 12, (THP_PA >> 12) + 512))
    assert {f.page_size for f in frames} == {2 << 20}


def test_range_inside_a_thp_is_clipped_with_the_right_subpage_pfns(mem):
    pt = PageTables(mem)
    pt.set_pmd(THP_VA, pte(THP_PA, P | USER | PSE))
    frames = _frames(layer(mem, pt), THP_VA + 0x5000, THP_VA + 0x7000)
    assert [(f.va, f.pfn) for f in frames] == [(THP_VA + 0x5000, (THP_PA >> 12) + 5),
                                               (THP_VA + 0x6000, (THP_PA >> 12) + 6)]


def test_protnone_page_is_resident_with_the_uninverted_pfn(mem):
    pt = PageTables(mem)
    pt.set_pte(BASE, protnone_pte(DATA + 0x3000) | NX)
    for linux in (True, False):  # vol3 Linux layers accept it; plain Intel returns it raw
        (frame,) = _frames(layer(mem, pt, linux=linux), BASE, BASE + 0x1000)
        assert (frame.state, frame.pfn) == (F.RESIDENT, (DATA + 0x3000) >> 12)
        assert F.entry_is_protnone(frame.entry) and not F.entry_is_writable(frame.entry)


def test_protnone_thp_on_a_plain_intel_layer_comes_from_the_fault_entry(mem):
    pt = PageTables(mem)
    pt.set_pmd(THP_VA, protnone_pte(THP_PA, PROTNONE | USER | PSE))
    frames = _frames(layer(mem, pt, linux=False), THP_VA, THP_VA + 0x2000)
    assert [(f.state, f.pfn, f.page_size) for f in frames] == [
        (F.RESIDENT, THP_PA >> 12, 2 << 20), (F.RESIDENT, (THP_PA >> 12) + 1, 2 << 20)]


def test_swap_entry_is_swapped_without_a_pfn(mem):
    pt = PageTables(mem)
    pt.map4k(BASE, DATA)
    pt.set_pte(BASE + 0x1000, swap_pte(1, 0x42))
    frames = _frames(layer(mem, pt), BASE, BASE + 0x2000)
    assert [(f.state, f.pfn) for f in frames] == [(F.RESIDENT, DATA >> 12), (F.SWAPPED, None)]
    assert frames[1].entry == swap_pte(1, 0x42)
    assert not F.entry_is_dirty(frames[1].entry) and not F.entry_is_writable(frames[1].entry)


def test_pmd_migration_entry_is_swapped_per_subpage(mem):
    pt = PageTables(mem)
    pt.set_pmd(THP_VA, swap_pte(3, 0x99))
    frames = _frames(layer(mem, pt), THP_VA, THP_VA + (2 << 20))
    assert len(frames) == 512 and {f.state for f in frames} == {F.SWAPPED}


def test_saved_dirty_bit_counts_as_dirty(mem):
    pt = PageTables(mem)
    pt.map4k(BASE, DATA, P | USER | ACCESSED | SAVED_DIRTY)
    (frame,) = _frames(layer(mem, pt), BASE, BASE + 0x1000)
    assert F.entry_is_dirty(frame.entry) and not frame.entry & DIRTY


def test_absent_pages_are_merged_and_the_range_is_partitioned_exactly(mem):
    pt = PageTables(mem)
    pt.map4k(BASE + 0x3000, DATA)
    pt.set_pte(BASE + 0x5000, ACCESSED | DIRTY)  # pte_none() with KNL-erratum bits
    end = BASE + (8 << 20)  # crosses into PT/PMD blocks that do not exist at all
    frames = _frames(layer(mem, pt), BASE, end)
    assert [(f.va, f.state) for f in frames] == [
        (BASE, F.NOT_RESIDENT), (BASE + 0x3000, F.RESIDENT), (BASE + 0x4000, F.NOT_RESIDENT)]
    assert _covered(frames) == end - BASE
    assert frames[2].pfn is None and frames[2].entry is None


def test_unmapped_top_level_block_is_one_record(mem):
    pt = PageTables(mem)
    frames = _frames(layer(mem, pt), BASE, BASE + (1 << 30))
    assert [(f.va, f.length, f.state) for f in frames] == [(BASE, 1 << 30, F.NOT_RESIDENT)]


class _MappingOnly(object):
    """A layer exposing only the public mapping() API (vol3 dropped _translate_entry)."""

    def __init__(self, real):
        self._real = real

    def mapping(self, offset, length, ignore_errors=False):
        return self._real.mapping(offset, length, ignore_errors)


class _ChangedSignature(_MappingOnly):
    def _translate_entry(self, va, extra):  # a future vol3 with another signature
        raise AssertionError("never called with one argument")


@pytest.mark.parametrize("wrapper", [_MappingOnly, _ChangedSignature])
def test_without_a_usable_translate_entry_falls_back_to_mapping(mem, wrapper):
    pt = PageTables(mem)
    pt.map4k(BASE, DATA, P | RW | USER | DIRTY)
    pt.map4k(BASE + 0x1000, DATA + 0x1000)
    pt.set_pte(BASE + 0x2000, swap_pte())
    frames = _frames(wrapper(layer(mem, pt)), BASE, BASE + 0x4000)
    assert [(f.va, f.pfn, f.entry, f.state) for f in frames] == [
        (BASE, DATA >> 12, None, F.RESIDENT), (BASE + 0x1000, (DATA >> 12) + 1, None, F.RESIDENT),
        (BASE + 0x2000, None, None, F.NOT_RESIDENT)]  # swap is invisible without the entry
    assert _covered(frames) == 0x4000


def test_member_frames_pairs_each_frame_with_its_vma(mem):
    pt = PageTables(mem)
    pt.map4k(BASE, DATA)
    pt.map4k(BASE + 0x10000, DATA + 0x1000)
    vmas = [F.VmaInfo(BASE, BASE + 0x1000, 0, False), F.VmaInfo(BASE + 0x10000, BASE + 0x11000,
                                                                F.VM_SHARED, True)]
    pairs = list(F.member_frames(layer(mem, pt), vmas))
    assert [(v.start, f.pfn) for v, f in pairs] == [(BASE, DATA >> 12),
                                                    (BASE + 0x10000, (DATA >> 12) + 1)]


def test_vma_info_reads_flags_and_treats_unreadable_vm_file_as_file_backed():
    class Broken(object):
        vm_start, vm_end, vm_flags = 0x1000, 0x2000, 0x8

        @property
        def vm_file(self):
            raise AttributeError("smashed")

    assert F.vma_info(Broken()) == F.VmaInfo(0x1000, 0x2000, 0x8, True)
    ok = SimpleNamespace(vm_start=1, vm_end=2, vm_flags=3, vm_file=0)
    assert F.vma_info(ok).file_backed is False


class _Kernel(object):
    layer_name = "kernel"

    def __init__(self, symbols):
        self._symbols = symbols

    def has_symbol(self, name):
        return name in self._symbols

    def get_absolute_symbol_address(self, name):
        return self._symbols[name]

    def object_from_symbol(self, name):
        return self._symbols[name]


class _KernelLayer(object):
    def translate(self, va):
        return va - 0xFFFFFFFF80000000 + 0x1000000, "phys"


def _ctx():
    return SimpleNamespace(layers={"kernel": _KernelLayer()})


def test_zero_page_pfns_from_empty_zero_page_and_huge_zero_pfn():
    kernel = _Kernel({"empty_zero_page": 0xFFFFFFFF82000000, "huge_zero_pfn": 0x5000})
    pfns = F.zero_page_pfns(_ctx(), kernel)
    assert (0x1000000 + 0x2000000) >> 12 in pfns
    assert set(range(0x5000, 0x5000 + 512)) <= pfns and len(pfns) == 513


def test_unallocated_huge_zero_page_is_not_labelled():
    kernel = _Kernel({"empty_zero_page": 0xFFFFFFFF82000000, "huge_zero_pfn": (1 << 64) - 1})
    assert len(F.zero_page_pfns(_ctx(), kernel)) == 1


def test_huge_zero_page_pointer_fallback_uses_struct_page_to_paddr():
    page = SimpleNamespace(to_paddr=lambda: 0x8000000)
    kernel = _Kernel({"huge_zero_page": 0xFFFFEA0000200000})
    kernel.object = lambda type_name, offset, absolute: page
    assert F.zero_page_pfns(_ctx(), kernel) == set(range(0x8000, 0x8000 + 512))
