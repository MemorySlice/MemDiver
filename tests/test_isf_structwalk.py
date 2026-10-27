"""Struct-walk helpers: synthetic views (always) + real Arista EOS image (gated)."""

import json
import os
import struct
from pathlib import Path

import pytest

from memdiver.isf.structwalk import (
    CLOSED, CYCLE_NOT_THROUGH_HEAD, MAX_NODES, NULL, UNREADABLE,
    find_list_cycles, render_struct, walk_list, walk_rbtree_view, walk_xarray_view)


class DictView:
    """VA->bytes pages; reads raise outside the mapped ranges."""

    def __init__(self):
        self.mem = {}

    def poke(self, va, data):
        for i, b in enumerate(data):
            self.mem[va + i] = b

    def poke_ptr(self, va, value):
        self.poke(va, struct.pack("<Q", value))

    def read(self, va, length):
        try:
            return bytes(self.mem[va + i] for i in range(length))
        except KeyError:
            raise ValueError(f"not captured: {va:#x}")


def ring(view, addrs, off=0):
    for a, b in zip(addrs, addrs[1:] + addrs[:1]):
        view.poke_ptr(a + off, b)


def test_closed_ring_with_container_offset():
    v = DictView()
    nodes = [0x1000 + 0x100 * i + 0x20 for i in range(5)]
    ring(v, nodes)
    w = walk_list(v, nodes[0], 0, container_off=0x20)
    assert w.closed and w.stop_reason == CLOSED
    assert w.nodes == tuple(n - 0x20 for n in nodes)
    assert walk_list(v, nodes[0], 0, include_head=False).nodes == tuple(nodes[1:])


def test_max_nodes_cut_is_not_closed():
    v = DictView()
    ring(v, [0x1000 + 0x10 * i for i in range(20)])
    w = walk_list(v, 0x1000, 0, max_nodes=7)
    assert not w.closed and w.stop_reason == MAX_NODES and len(w.nodes) == 7


def test_null_pointer():
    v = DictView()
    v.poke_ptr(0x1000, 0x2000)
    v.poke_ptr(0x2000, 0)
    w = walk_list(v, 0x1000, 0)
    assert (w.closed, w.stop_reason, w.nodes) == (False, NULL, (0x1000, 0x2000))


def test_unreadable_node_records_gap_not_zeros():
    v = DictView()
    v.poke_ptr(0x1000, 0x2000)          # 0x2000 is never mapped
    w = walk_list(v, 0x1000, 0)
    assert not w.closed and w.stop_reason == UNREADABLE
    assert w.gap["va"] == 0x2000 and "not captured" in w.gap["reason"]
    assert 0 not in w.nodes


def test_cycle_not_through_head():
    v = DictView()
    v.poke_ptr(0x1000, 0x2000)
    v.poke_ptr(0x2000, 0x3000)
    v.poke_ptr(0x3000, 0x2000)
    w = walk_list(v, 0x1000, 0)
    assert w.stop_reason == CYCLE_NOT_THROUGH_HEAD and not w.closed


def test_find_list_cycles_finds_right_offset_among_decoys():
    v = DictView()
    base = 0x10000
    v.poke(base, bytes(256))
    # real ring at offset 0x40 through 5 structs
    structs = [base + 0x1000 * i for i in range(5)]
    for s in structs:
        v.poke(s, bytes(256))
    ring(v, [s + 0x40 for s in structs])
    v.poke_ptr(base + 0x80, base + 0x1000 + 0x80)   # decoy: chain to null
    v.poke_ptr(base + 0x1000 + 0x80, 0)
    v.poke_ptr(base + 0x90, base + 0x90)            # decoy: self ring, length 1
    scan = find_list_cycles(v, base, 256, min_len=3)
    assert [c["offset"] for c in scan.candidates] == [0x40]
    assert scan.candidates[0]["ring_len"] == 5 and not scan.truncated
    assert find_list_cycles(v, base, 256, max_work=1).truncated


def isf():
    return {
        "base_types": {"unsigned int": {"size": 4, "signed": False, "kind": "int", "endian": "little"},
                       "int": {"size": 4, "signed": True, "kind": "int", "endian": "little"},
                       "char": {"size": 1, "signed": True, "kind": "char", "endian": "little"},
                       "pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"}},
        "user_types": {"demo": {"kind": "struct", "size": 40, "fields": {
            "pid": {"offset": 0, "type": {"kind": "base", "name": "int"}},
            "next": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "demo"}}},
            "comm": {"offset": 16, "type": {"kind": "array", "count": 16,
                                            "subtype": {"kind": "base", "name": "char"}}},
            "mystery": {"offset": 32, "type": {"kind": "base", "name": "nope"}},
            "inner": {"offset": 32, "type": {"kind": "struct", "name": "undefined"}}}}},
    }


def demo_bytes():
    return (struct.pack("<iI", -5, 0) + struct.pack("<Q", 0xFFFF888000001000)
            + b"systemd\x00" + bytes(8) + bytes(8))


def test_render_struct_types_and_unknown():
    v = DictView()
    v.poke(0x5000, demo_bytes())
    r = render_struct(v, 0x5000, isf(), "demo")
    f = {x["name"]: x for x in r["fields"]}
    assert f["pid"]["value"] == -5
    assert f["next"]["value"] == 0xFFFF888000001000
    assert f["comm"]["value"] == "systemd"
    assert f["mystery"]["raw_hex"] is None and f["mystery"]["coverage"] == "unsized"
    assert f["inner"]["value"] is None and f["inner"]["coverage"] == "unsized"
    assert r["coverage"] == "full"


def test_render_struct_partially_unreadable_and_draft_object():
    from memdiver.isf.draft import IsfDraft
    v = DictView()
    v.poke(0x5000, demo_bytes()[:16])          # comm and beyond not captured
    r = render_struct(v, 0x5000, IsfDraft.from_isf_dict(isf()), "demo")
    f = {x["name"]: x for x in r["fields"]}
    assert f["pid"]["coverage"] == "full" and f["next"]["coverage"] == "full"
    assert f["comm"]["coverage"] == "gap" and f["comm"]["raw_hex"] is None
    assert "not captured" in f["comm"]["gap_reason"]
    assert r["coverage"] == "partial"
    with pytest.raises(KeyError):
        render_struct(v, 0x5000, isf(), "missing")


def test_rbtree_view_walks_and_reports_gap():
    pytest.importorskip("pakunoda")
    v = DictView()
    # node layout: left @0, right @8; 0x100 root, 0x200 left, 0x300 right
    for va, l, r in ((0x100, 0x200, 0x300), (0x200, 0, 0), (0x300, 0, 0)):
        v.poke_ptr(va, l)
        v.poke_ptr(va + 8, r)
    w = walk_rbtree_view(v, 0x100, left_off=0, right_off=8)
    assert w.nodes == (0x200, 0x100, 0x300) and w.ok
    v.poke_ptr(0x100 + 8, 0x999)               # right child unmapped
    bad = walk_rbtree_view(v, 0x100, left_off=0, right_off=8)
    assert not bad.ok and bad.gap["va"] == 0x999


def test_xarray_view_leaf_head_needs_no_reads():
    pytest.importorskip("pakunoda")
    from pakunoda.recovery.xarray import XaNodeLayout
    layout = XaNodeLayout(shift=0, array=8, slots=16, chunk=64, stride=8)
    entries, gap = walk_xarray_view(DictView(), 0x1000, layout)
    assert entries == ((0, 0x1000),) and gap is None


# ------------------------------------------------------------- real image (gated)
STEM = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"
_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
_DIR = Path(_ROOT) if _ROOT else None
_HAS = _DIR is not None and all((_DIR / f"{STEM}{e}").is_file() for e in (".lime", ".isf.json"))


@pytest.mark.skipif(not _HAS, reason="set MEMDIVER_IMAGE_CORPUS (arista-eos-4.36.1F lime + isf.json)")
def test_real_arista_task_ring():
    pytest.importorskip("pakunoda")
    from pakunoda import probes
    from memdiver.core.image.context import ImageContext
    from memdiver.core.image.pakunoda_view import NoIsfKernelAdapter
    from memdiver.core.image.view_descriptor import PagingSpec

    lime = _DIR / f"{STEM}.lime"
    isf_doc = json.loads((_DIR / f"{STEM}.isf.json").read_text())
    root = probes.find_page_table_root(probes.open_dump(lime), probes.resolve_arch("x86_64"))
    assert root is not None
    image = ImageContext.build(lime)
    view = NoIsfKernelAdapter(image, PagingSpec(root.pgd_phys, "x86_64", root.va_bits, root.page_size))
    init_task = isf_doc["symbols"]["init_task"]["address"]
    tasks_off = isf_doc["user_types"]["task_struct"]["fields"]["tasks"]["offset"]
    assert tasks_off == 864

    walk = walk_list(view, init_task + 864, 0, container_off=864)
    assert walk.closed and init_task in walk.nodes
    # vol3 pslist (123 rows) omits the swapper/init_task head; the ring includes it
    ps = (_DIR / f"{STEM}.vol3_pslist.txt")
    if ps.is_file():
        rows = [ln for ln in ps.read_text().splitlines()[4:] if ln.strip()]
        assert len(walk.nodes) == len(rows) + 1
    assert len(walk.nodes) == 124

    scan = find_list_cycles(view, init_task, 7168)
    assert 864 in [c["offset"] for c in scan.candidates]
    assert not scan.truncated


def test_big_endian_pointer_and_enum_decoding():
    be = {"size": 8, "signed": False, "kind": "int", "endian": "big"}
    d = {"base_types": {"pointer": be, "u4": {"size": 4, "signed": False, "kind": "int",
                                              "endian": "big"}},
         "enums": {"e": {"size": 4, "base": "u4", "constants": {}}},
         "user_types": {"s": {"kind": "struct", "size": 12, "fields": {
             "p": {"offset": 0, "type": {"kind": "pointer"}},
             "e": {"offset": 8, "type": {"kind": "enum", "name": "e"}}}}}}
    v = DictView()
    v.poke(0x100, struct.pack(">Q", 0xFFFF888000001000) + struct.pack(">I", 7))
    got = {f["name"]: f["value"] for f in render_struct(v, 0x100, d, "s")["fields"]}
    assert got == {"p": 0xFFFF888000001000, "e": 7}


def test_ring_longer_than_max_len_is_reported_not_dropped():
    v = DictView()
    base = 0x10000
    v.poke(base, bytes(16))
    nodes = [0x20000 + 0x10 * i for i in range(10)]
    for n in nodes:
        v.poke(n, bytes(8))
    ring(v, nodes)
    v.poke_ptr(base, nodes[0])
    scan = find_list_cycles(v, 0x20000, 16, min_len=3, max_len=5, stride=8)
    flagged = [c for c in scan.candidates if c.get("ring_len_exceeds_max")]
    assert flagged and flagged[0]["offset"] == 0
