"""vol3plugins/memdiver/page_sharing.py (``memdiver.page_sharing.PageSharing``), unit level.

The page walk + classification run over synthetic x86_64 page tables under a REAL vol3
``LinuxIntel32e`` layer (tests/_synthetic_pagetables.py); grouping, shape and ELF build-id
parsing are pure. The real-image claim (C-SIB1, stock vol) is in
tests/test_vol3plugins_corpus_gate.py.
"""
import struct
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins.memdiver import frames as F  # noqa: E402
from memdiver.vol3plugins.memdiver import page_sharing as PS  # noqa: E402
from memdiver.vol3plugins.memdiver import process_scope  # noqa: E402
from tests._synthetic_pagetables import (  # noqa: E402
    ACCESSED, DIRTY, P, RW, USER, PageTables, PhysMemory, layers,
)

CODE, HEAP = 0x555500000000, 0x555500100000
VM_RX = PS.VM_READ | PS.VM_EXEC
VM_RW = PS.VM_READ | PS.VM_WRITE


# --- ELF build-id ---------------------------------------------------------------------------

def _note(name=b"GNU\0", desc=bytes(range(20)), ntype=PS.NT_GNU_BUILD_ID):
    pad = lambda b: b + b"\0" * (-len(b) % 4)  # noqa: E731
    return struct.pack("<III", len(name), len(desc), ntype) + pad(name) + pad(desc)


def _elf(load_vaddr, note_vaddr, note_size):
    header = bytearray(4096)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 32, 64)        # e_phoff
    struct.pack_into("<HH", header, 54, 56, 2)    # e_phentsize, e_phnum
    struct.pack_into("<IIQQQQQQ", header, 64, PS.PT_LOAD, 5, 0, load_vaddr, load_vaddr,
                     0x2000, 0x2000, 0x1000)
    struct.pack_into("<IIQQQQQQ", header, 120, PS.PT_NOTE, 4, 0x2000, note_vaddr, note_vaddr,
                     note_size, note_size, 4)
    return bytes(header)


@pytest.mark.parametrize("load_vaddr,base", [(0, CODE), (0x400000, 0x400000)])
def test_build_id_from_pie_and_et_exec_with_the_load_bias(load_vaddr, base):
    notes = _note(b"stapsdt\0", b"x" * 8, 3) + _note()   # a non-GNU note first
    memory = {base + 0x2000: notes}
    header = _elf(load_vaddr, load_vaddr + 0x2000, len(notes))
    assert PS.parse_build_id(header, base, lambda va, size: memory.get(va, b"")[:size]) == \
        bytes(range(20)).hex()


def test_build_id_absent_or_unreadable_or_not_elf():
    header = _elf(0, 0x2000, 32)
    assert PS.parse_build_id(header, CODE, lambda va, size: None) is None
    assert PS.parse_build_id(b"\x7fELF\x01\x01" + bytes(100), CODE, lambda va, s: None) is None
    assert PS.parse_build_id(b"MZ" + bytes(100), CODE, lambda va, s: None) is None
    assert PS.note_build_id(_note(ntype=1)) is None
    assert PS.note_build_id(b"\xff" * 12) is None  # oversized namesz: stop, never overrun


# --- grouping and shape --------------------------------------------------------------------

def _member(pid, ppid, layout, identity="build-id:aa"):
    return PS.Member(pid, ppid, "x", "proc%d" % pid, [], identity, "aa", "/x", layout)


def test_forked_siblings_share_layout_and_parent():
    listener, a, b = _member(10, 1, (1,)), _member(11, 10, (1,)), _member(12, 10, (1,))
    parent_of = {10: 1, 11: 10, 12: 10}
    assert PS.group_shape([listener, a, b], parent_of) == PS.FORKED
    assert PS.layout_labels([listener, a, b]) == {10: "L1", 11: "L1", 12: "L1"}


def test_independent_instances_have_their_own_aslr_layout():
    members = [_member(20, 1, (1,)), _member(21, 1, (2,)), _member(22, 1, (3,))]
    assert PS.group_shape(members, {20: 1, 21: 1, 22: 1}) == PS.INDEPENDENT


def test_same_layout_without_lineage_is_not_forked():
    assert PS.pair_shape(_member(30, 2, (1,)), _member(31, 3, (1,)), {30: 2, 31: 3}) == \
        PS.INDEPENDENT


def test_reexec_monitor_with_forked_child_is_mixed():
    """OpenSSH 9.6: each monitor is re-exec'd (own layout), its session is forked from it."""
    members = [_member(40, 1, (1,)), _member(41, 40, (2,)), _member(42, 41, (2,)),
               _member(43, 40, (3,)), _member(44, 43, (3,))]
    parent_of = {40: 1, 41: 40, 42: 41, 43: 40, 44: 43}
    assert PS.group_shape(members, parent_of) == PS.MIXED
    assert PS.layout_labels(members) == {40: "L1", 41: "L2", 42: "L2", 43: "L3", 44: "L3"}
    assert PS.is_ancestor(40, 44, parent_of) and not PS.is_ancestor(41, 44, parent_of)
    assert PS.group_shape(members[:1], parent_of) == PS.SINGLE


def test_group_by_identity_keeps_first_seen_order():
    members = [_member(1, 0, (1,), "build-id:b"), _member(2, 0, (1,), "exe:/a"),
               _member(3, 0, (1,), "build-id:b")]
    assert [[m.pid for m in g] for g in PS.group_by_identity(members)] == [[1, 3], [2]]


# --- selection helpers (process_scope additions) -----------------------------------------

def test_dedup_by_mm_keeps_one_task_per_address_space():
    tasks = [SimpleNamespace(pid=1, mm=0x100), SimpleNamespace(pid=2, mm=0x200),
             SimpleNamespace(pid=3, mm=0x100)]
    kept, dropped = process_scope.dedup_by_mm(tasks)
    assert [t.pid for t in kept] == [1, 2] and dropped == {3: 1}


def test_selected_tasks_is_the_union_of_pid_and_comm(monkeypatch):
    from volatility3.plugins.linux import pslist

    def task(pid, name, mm=0x1000):
        return SimpleNamespace(pid=pid, mm=mm, comm=SimpleNamespace(
            cast=lambda *a, **k: name))

    tasks = [task(1, "init"), task(2, "sshd"), task(3, "dropbear"), task(4, "kthread", mm=0)]
    monkeypatch.setattr(pslist.PsList, "list_tasks", classmethod(lambda cls, ctx, k: iter(tasks)))
    pick = lambda **kw: [t.pid for t in process_scope.selected_tasks(None, "k", **kw)]  # noqa: E731
    assert pick() == [1, 2, 3]
    assert pick(pids=[1], comms=["dropbear"]) == [1, 3]
    assert pick(comms=["sshd"]) == [2]


# --- walk + classify + tally on a real vol3 layer ----------------------------------------

def _vma(start, end, flags, file_backed, name):
    return PS.VmaRecord(start, end, flags, file_backed, "", name)


@pytest.fixture
def siblings():
    """Two forked siblings: shared code page, one shared CoW heap page, one private heap
    page each, and a patched (dirty, private) code page in member B."""
    mem = PhysMemory()
    a, b = PageTables(mem), PageTables(mem)
    for pt in (a, b):
        pt.map4k(CODE, 0x10000, P | USER | ACCESSED)                   # page cache text
        pt.map4k(HEAP, 0x20000, P | USER | ACCESSED | DIRTY)           # fork CoW, W=0
    a.map4k(CODE + 0x1000, 0x11000, P | USER | ACCESSED)
    b.map4k(CODE + 0x1000, 0x31000, P | USER | ACCESSED | DIRTY)       # in-place patch
    a.map4k(HEAP + 0x1000, 0x21000, P | RW | USER | ACCESSED | DIRTY)
    b.map4k(HEAP + 0x1000, 0x22000, P | RW | USER | ACCESSED | DIRTY)
    vmas = [_vma(CODE, CODE + 0x2000, VM_RX, True, "/bin/x"),
            _vma(HEAP, HEAP + 0x3000, VM_RW, False, "[heap]")]
    walked = {pid: list(F.member_frames(lay, vmas)) for pid, lay in zip((1, 2), layers(mem, [a, b]))}
    return walked, PS.split_by_member(F.classify_frames(walked), walked)


def test_split_by_member_reattaches_each_vma(siblings):
    walked, labelled = siblings
    assert [len(labelled[m]) for m in (1, 2)] == [len(walked[1]), len(walked[2])]
    assert all(vma.start <= page.va < vma.end for pairs in labelled.values()
               for vma, page in pairs)


def test_tally_counts_the_classes_and_the_patched_code_page(siblings):
    _walked, labelled = siblings
    a, b = PS.tally(labelled[1]), PS.tally(labelled[2])
    assert (a["rss"], a["private_dirty"], a["shared_lineage"], a["shared_file"]) == \
        (0x4000, 0x1000, 0x1000, 0x2000)
    assert a["patched_code"] == 0 and b["patched_code"] == 1
    assert (b["private_dirty"], b["shared_file"]) == (0x2000, 0x1000)
    assert b["private_pct"] == 50.0 and a["private_pct"] == 25.0
    assert PS.counter_values(a)[:4] == (16, 4, 0, 4)


def test_class_runs_merge_adjacent_equal_pages(siblings):
    _walked, labelled = siblings
    runs = PS.class_runs(page for _vma, page in labelled[1])
    # the two code pages differ in evidence (T1: B maps it too; T0: only A), so no merge
    assert [r[:4] for r in runs] == [
        [hex(CODE), 0x1000, F.SHARED_FILE, "T1"], [hex(CODE + 0x1000), 0x1000, F.SHARED_FILE, "T0"],
        [hex(HEAP), 0x1000, F.SHARED_LINEAGE, "T1"],
        [hex(HEAP + 0x1000), 0x1000, F.PRIVATE_DIRTY, "T0"],
        [hex(HEAP + 0x2000), 0x1000, F.NOT_RESIDENT, "T0"]]
    same = F.ClassifiedPage(1, 0, 0x1000, 5, F.PRIVATE_DIRTY, "T0", False, False, True, True)
    assert PS.class_runs([same, same._replace(va=0x1000)]) == [
        ["0x0", 0x2000, F.PRIVATE_DIRTY, "T0", False, False]]


def test_is_code_needs_file_backed_exec_without_write():
    assert PS.is_code(_vma(0, 1, VM_RX, True, ""))
    assert not PS.is_code(_vma(0, 1, VM_RX | PS.VM_WRITE, True, ""))
    assert not PS.is_code(_vma(0, 1, VM_RX, False, ""))


def test_plugin_declares_the_documented_options():
    names = {r.name for r in PS.PageSharing.get_requirements()}
    assert {"kernel", "pid", "comm", "group", "per_vma", "global", "dump"} <= names
    assert [c for c, _t in PS.COUNTER_COLUMNS][-1] == "PatchedCode"
