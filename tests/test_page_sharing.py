"""Frame classification of sibling processes (core/image/page_sharing.py over
vol3plugins/memdiver/frames.py): T0/T1/special tiers, smear guard, accounting, adapter hooks.

Every scenario walks synthetic page tables through a REAL vol3 LinuxIntel32e layer.
"""
import threading
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from memdiver.core.image import page_sharing as PS  # noqa: E402
from memdiver.core.image.adapters import (  # noqa: E402
    ProcessAdapter, Vma, _iter_vmas, classify, pte_gap_runs,
)
from memdiver.core.image.run_index import RunState  # noqa: E402
from memdiver.vol3plugins.memdiver import frames as F  # noqa: E402
from tests._synthetic_pagetables import (  # noqa: E402
    ACCESSED, DIRTY, P, PSE, RW, SAVED_DIRTY, USER,
    PageTables, PhysMemory, layer, layers, protnone_pte, pte, swap_pte,
)

HEAP = 0x555500000000
THP = 0x7F0000200000
LIB = 0x7F1000000000
SHM = 0x7F2000000000
PA = 0x400000
THP_PA = 0x600000
ZERO_PA = 0xA00000
RO = P | USER | ACCESSED              # W=0, clean
RO_DIRTY = RO | DIRTY                 # fork-CoW'd anon page: W=0, D kept
RW_DIRTY = P | RW | USER | ACCESSED | DIRTY
ANON = F.VmaInfo(HEAP, HEAP + 0x10000, F.VM_WRITE, False)
ANON_THP = F.VmaInfo(THP, THP + (2 << 20), F.VM_WRITE, False)
FILE = F.VmaInfo(LIB, LIB + 0x10000, F.VM_WRITE, True)
SHARED = F.VmaInfo(SHM, SHM + 0x10000, F.VM_WRITE | F.VM_SHARED, True)


def _classify(mem, tables_by_member, vmas, zero=()):
    lays = layers(mem, list(tables_by_member.values()))
    members = {m: list(F.member_frames(lay, vmas)) for m, lay in zip(tables_by_member, lays)}
    return F.classify_frames(members, zero)


def _page(result, member, va):
    (page,) = F.pages_at(result, member, [va])
    return page


@pytest.fixture
def mem():
    return PhysMemory()


def test_thp_split_mixes_shared_subpages_with_a_cow_private_one(mem):
    parent, child = PageTables(mem), PageTables(mem)
    parent.set_pmd(THP, pte(THP_PA, RO_DIRTY | PSE))          # parent keeps the THP
    for i in range(512):                                       # child's copy was split
        child.map4k(THP + i * 0x1000, THP_PA + i * 0x1000, RO_DIRTY)
    child.map4k(THP + 7 * 0x1000, PA, RW_DIRTY)                # ... and subpage 7 CoW'd
    result = _classify(mem, {"parent": parent, "child": child}, [ANON_THP])
    shared = _page(result, "child", THP)
    assert (shared.share_class, shared.decided_by, shared.smear_conflict) == (
        F.SHARED_LINEAGE, "T1", False)
    cowed = _page(result, "child", THP + 0x7000)
    assert (cowed.share_class, cowed.decided_by, cowed.possibly_shared) == (
        F.PRIVATE_DIRTY, "T0", False)
    # The parent's subpage 7 is now mapped by the parent alone: private, but W=0 only.
    orphan = _page(result, "parent", THP + 0x7000)
    assert (orphan.share_class, orphan.decided_by, orphan.possibly_shared) == (
        F.PRIVATE_DIRTY, "T1", True)
    assert result.accounting["child"]["shared"] == 511 * 4096
    assert result.accounting["child"]["private_dirty"] == 4096
    assert result.accounting["parent"]["private_dirty"] == 4096


def test_zero_page_is_special_never_shared_and_not_rss(mem):
    a, b = PageTables(mem), PageTables(mem)
    for t in (a, b):
        t.map4k(HEAP, ZERO_PA, RO)
    result = _classify(mem, {"a": a, "b": b}, [ANON], zero={ZERO_PA >> 12})
    page = _page(result, "a", HEAP)
    assert (page.share_class, page.decided_by) == (F.ZERO, "special")
    assert result.accounting["a"]["zero"] == 4096 and result.accounting["a"]["rss"] == 0


def test_saved_dirty_page_is_private_dirty(mem):
    a = PageTables(mem)
    a.map4k(HEAP, PA, RO | SAVED_DIRTY)
    page = _page(_classify(mem, {"a": a}, [ANON]), "a", HEAP)
    assert page.dirty and page.share_class == F.PRIVATE_DIRTY


def test_protnone_page_is_resident_and_classified_by_its_real_frame(mem):
    a, b = PageTables(mem), PageTables(mem)
    a.set_pte(HEAP, protnone_pte(PA))
    b.map4k(HEAP, PA, RO_DIRTY)
    result = _classify(mem, {"a": a, "b": b}, [ANON])
    assert _page(result, "a", HEAP).pfn == PA >> 12
    assert _page(result, "a", HEAP).share_class == F.SHARED_LINEAGE


def test_swap_entries_are_swapped_and_accounted(mem):
    a = PageTables(mem)
    a.set_pte(HEAP, swap_pte(0, 0x77))
    result = _classify(mem, {"a": a}, [ANON])
    page = _page(result, "a", HEAP)
    assert (page.share_class, page.decided_by, page.pfn) == (F.SWAPPED, "T0", None)
    assert result.accounting["a"]["swapped"] == 4096 and result.accounting["a"]["rss"] == 0


def test_smear_conflict_flags_a_shared_frame_that_one_member_maps_writable(mem):
    a, b = PageTables(mem), PageTables(mem)
    a.map4k(HEAP, PA, RW_DIRTY)   # W=1 claims exclusivity ...
    b.map4k(HEAP, PA, RO_DIRTY)   # ... but a sibling maps the same frame
    result = _classify(mem, {"a": a, "b": b}, [ANON])
    for member in ("a", "b"):
        assert _page(result, member, HEAP).smear_conflict
    assert result.accounting["a"]["smear_conflict"] == 4096


def test_w0_page_after_a_sibling_exited_stays_possibly_shared_never_shared(mem):
    survivor = PageTables(mem)
    survivor.map4k(HEAP, PA, RO_DIRTY)   # still write-protected from the fork
    page = _page(_classify(mem, {"survivor": survivor}, [ANON]), "survivor", HEAP)
    assert page.share_class in F.PRIVATE_CLASSES and page.share_class not in F.SHARED_CLASSES
    assert page.possibly_shared and page.decided_by == "T1"


def test_vm_shared_mapping_is_shmem_and_never_a_smear(mem):
    a, b = PageTables(mem), PageTables(mem)
    for t in (a, b):
        t.map4k(SHM, PA, RW_DIRTY)
    result = _classify(mem, {"a": a, "b": b}, [SHARED])
    page = _page(result, "a", SHM)
    assert (page.share_class, page.decided_by, page.smear_conflict) == (F.SHMEM, "T0", False)
    assert result.accounting["a"]["shared"] == 4096


def test_private_file_mapping_classes(mem):
    a, b = PageTables(mem), PageTables(mem)
    a.map4k(LIB, PA, RO)                        # page cache, a alone
    a.map4k(LIB + 0x1000, PA + 0x1000, RW_DIRTY)  # CoW'd .data
    a.map4k(LIB + 0x2000, PA + 0x2000, RO)      # page cache, both
    b.map4k(LIB + 0x2000, PA + 0x2000, RO)
    result = _classify(mem, {"a": a, "b": b}, [FILE])
    assert [(p.share_class, p.decided_by) for p in F.pages_at(result, "a", [
        LIB, LIB + 0x1000, LIB + 0x2000])] == [
        (F.SHARED_FILE, "T0"), (F.PRIVATE_FILE_COW, "T0"), (F.SHARED_FILE, "T1")]


def test_not_resident_and_accounting_totals(mem):
    a = PageTables(mem)
    a.map4k(HEAP, PA, RW_DIRTY)
    a.map4k(HEAP + 0x1000, PA + 0x1000, RO)
    acc = _classify(mem, {"a": a}, [ANON]).accounting["a"]
    assert acc["rss"] == 0x2000 and acc["private_dirty"] == 0x1000
    assert acc["private_clean"] == 0x1000 and acc["not_resident"] == 0x10000 - 0x2000
    assert F.private_ratio(acc) == 1.0 and F.private_ratio({"rss": 0}) == 0.0


def test_flags_unknown_frames_from_the_mapping_fallback_are_never_proof():
    frame = F.PageFrame(HEAP, 4096, 5, None, 4096, F.RESIDENT)
    result = F.classify_frames({"a": [(ANON, frame)]})
    page = result.pages[0]
    assert (page.share_class, page.decided_by, page.possibly_shared) == (
        F.PRIVATE_CLEAN, "T1", True)


# --- MemDiver adapter hooks ------------------------------------------------------------------

def _adapter(lay, vmas):
    adapter = object.__new__(ProcessAdapter)
    adapter._ctx = SimpleNamespace(lock=threading.RLock())
    adapter._layer, adapter._vmas, adapter._frames = lay, vmas, None
    return adapter


def test_process_adapter_page_frames_is_cached_and_accepts_core_vmas(mem):
    a = PageTables(mem)
    a.map4k(HEAP, PA, RW_DIRTY)
    vma = Vma(HEAP, HEAP + 0x2000, "[heap]", "rw-", True, False, F.VM_WRITE)
    adapter = _adapter(layer(mem, a), [vma])
    pairs = adapter.page_frames()
    assert adapter.page_frames() is pairs
    assert [(f.va, f.state) for _v, f in pairs] == [(HEAP, F.RESIDENT), (HEAP + 0x1000,
                                                                           F.NOT_RESIDENT)]
    page = F.classify_frames({1: pairs}).pages[0]
    assert page.share_class == F.PRIVATE_DIRTY


def test_vma_carries_vm_flags_and_shared():
    vma = SimpleNamespace(vm_start=0x1000, vm_end=0x2000, vm_flags=0xFB, vm_file=1,
                          get_name=lambda ctx, task: "/dev/shm/x",
                          get_protection=lambda: "rw-")
    task = SimpleNamespace(mm=SimpleNamespace(start_brk=0, brk=0, get_vma_iter=lambda: [vma]))
    (out,) = _iter_vmas(SimpleNamespace(), task)
    assert out.vm_flags == 0xFB and out.shared
    assert Vma(0, 1, "", "r--", False).vm_flags == 0 and not Vma(0, 1, "", "r--", False).shared


def test_classify_processes_dedups_tasks_sharing_an_mm(mem, monkeypatch):
    a, b = PageTables(mem), PageTables(mem)
    a.map4k(HEAP, PA, RO_DIRTY)
    b.map4k(HEAP, PA, RO_DIRTY)
    lay_a, lay_b = layers(mem, [a, b])
    by_pid = {1: (lay_a, 0xA), 2: (lay_a, 0xA), 3: (lay_b, 0xB)}

    class FakeAdapter(object):
        def __init__(self, image_ctx, pid):
            self._lay, self._mm = by_pid[pid]

        def mm_address(self):
            return self._mm

        def vmas(self):
            return [ANON]

        def page_frames(self):
            return list(F.member_frames(self._lay, self.vmas()))

    monkeypatch.setattr(PS, "ProcessAdapter", FakeAdapter)
    result = PS.classify_processes(SimpleNamespace(has_kernel=False), [1, 2, 3])
    assert result.same_address_space == {2: 1}
    assert set(result.accounting) == {1, 3} and set(result.walk_seconds) == {1, 3}
    assert _page(result.classification, 1, HEAP).share_class == F.SHARED_LINEAGE
    assert result.reduction(1) == 0.0


def test_protnone_is_already_captured_by_classify_on_linux_layers(mem):
    """Pin for the plan's "PROTNONE mislabelled FAILED" item: vol3's Linux layers treat a
    PROT_NONE leaf as present, so ``classify`` (mapping) yields CAPTURED and the gap
    labeller never sees it. Only a plain Intel layer reaches ``pte_gap_runs``, where FAILED
    stays correct: that layer cannot read the bytes, so CAPTURED would be a lie."""
    a = PageTables(mem)
    a.set_pte(HEAP, protnone_pte(PA))
    runs = list(classify(layer(mem, a), HEAP, 0x1000, missing=pte_gap_runs))
    assert [r.state for r in runs] == [RunState.CAPTURED]
    plain = list(classify(layer(mem, a, linux=False), HEAP, 0x1000, missing=pte_gap_runs))
    assert [r.state for r in plain] == [RunState.FAILED]
