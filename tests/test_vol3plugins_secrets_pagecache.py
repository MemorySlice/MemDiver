"""vol3plugins/linux/secrets/pagecache.py on synthetic XArrays laid out in a fake kernel memory."""

import struct

import pytest

from memdiver.vol3plugins.linux.secrets import pagecache as pc

VMEMMAP = 0xFFFFEA0000000000
MAPPING = 0xFFFF888000100000
NODE_BASE = 0xFFFF888000200000
NODE_SIZE = 576  # sizeof(struct xa_node) on LP64


class FakeReader:
    """``SafeReader``-shaped reads over sparse little-endian memory."""

    pointer_size = 8

    def __init__(self):
        self.mem = {}

    def write(self, address, data):
        for i, byte in enumerate(data):
            self.mem[address + i] = byte

    def read(self, address, length):
        if any(address + i not in self.mem for i in range(length)):
            return None
        return bytes(self.mem[address + i] for i in range(length))

    def u8(self, address):
        data = self.read(address, 1)
        return None if data is None else data[0]

    def ptr(self, address):
        data = self.read(address, 8)
        return None if data is None else struct.unpack("<Q", data)[0]


def page(pfn):
    return VMEMMAP + pfn * 64


def to_phys(page_address):
    return (page_address - VMEMMAP) // 64 << 12


def node_entry(address):
    return address | 2


def sibling(offset):
    return (offset << 2) | 2


class Tree:
    def __init__(self):
        self.reader = FakeReader()
        self.next_node = NODE_BASE

    def own(self, entry, mapping=MAPPING):
        """Give a page entry's ``struct page`` its ``mapping`` (page.mapping at +24)."""
        if entry and not entry & 3:
            self.reader.write(entry + 24, struct.pack("<Q", mapping))

    def node(self, shift, slots):
        address, self.next_node = self.next_node, self.next_node + NODE_SIZE
        self.reader.write(address, bytes([shift]) + bytes(39) + bytes(512))
        for offset, entry in slots.items():
            self.reader.write(address + 40 + 8 * offset, struct.pack("<Q", entry))
            self.own(entry)
        return address

    def head(self, entry):
        self.reader.write(MAPPING, bytes(8) + struct.pack("<I", 0) + bytes(4) + struct.pack("<Q", entry))
        self.own(entry)
        return self

    def lookup(self, index, kl=None):
        return pc.mapping_page(self.reader, kl or {}, MAPPING, index, to_phys)

    def listing(self, limit=1 << 20, phys=True):
        return list(pc.iter_mapping_pages(self.reader, {}, MAPPING, limit, to_phys if phys else None))


def test_head_that_is_not_a_node_holds_index_0_only():
    tree = Tree().head(page(77))
    assert tree.lookup(0) == 77 << 12
    assert tree.lookup(1) is None
    assert tree.listing() == [(0, 77 << 12)]


def test_empty_and_value_heads_are_not_resident():
    assert Tree().head(0).lookup(0) is None
    assert Tree().head((1234 << 1) | 1).lookup(0) is None
    assert Tree().head(0).listing() == []
    assert Tree().listing() == []  # unreadable mapping


def test_single_level_node():
    tree = Tree()
    leaf = tree.node(0, {0: page(10), 1: page(11), 63: page(99)})
    tree.head(node_entry(leaf))
    assert [tree.lookup(i) for i in (0, 1, 63)] == [10 << 12, 11 << 12, 99 << 12]
    assert tree.lookup(2) is None      # missing index
    assert tree.lookup(64) is None     # beyond the root's span
    assert tree.lookup(-1) is None
    assert tree.listing() == [(0, 10 << 12), (1, 11 << 12), (63, 99 << 12)]


def test_two_levels():
    tree = Tree()
    low = tree.node(0, {0: page(1)})
    high = tree.node(0, {5: page(500), 6: page(501)})
    root = tree.node(6, {0: node_entry(low), 2: node_entry(high)})
    tree.head(node_entry(root))
    assert tree.lookup(0) == 1 << 12
    assert tree.lookup(2 * 64 + 5) == 500 << 12
    assert tree.lookup(2 * 64 + 6) == 501 << 12
    assert tree.lookup(64 + 5) is None   # no child at slot 1
    assert tree.lookup(4096) is None     # beyond 64 * 64
    assert [i for i, _ in tree.listing()] == [0, 133, 134]


def test_sibling_entries_of_a_small_large_folio_in_a_leaf():
    tree = Tree()
    leaf = tree.node(0, {4: page(1000), 5: sibling(4), 6: sibling(4), 7: sibling(4), 8: page(5)})
    tree.head(node_entry(leaf))
    for k in range(4):
        assert tree.lookup(4 + k) == (1000 + k) << 12
    assert tree.lookup(8) == 5 << 12
    assert tree.listing() == [(4 + k, (1000 + k) << 12) for k in range(4)] + [(8, 5 << 12)]
    assert tree.listing(phys=False)[:2] == [(4, page(1000)), (5, page(1001))]


def test_multi_slot_folio_stored_above_the_leaf():
    """An order-9 folio (512 pages) occupies 8 slots of a shift-6 node: canonical + 7 siblings."""
    tree = Tree()
    slots = {8: page(0x40000)}
    slots.update({8 + k: sibling(8) for k in range(1, 8)})
    root = tree.node(6, slots)
    tree.head(node_entry(root))
    assert tree.lookup(512) == 0x40000 << 12
    assert tree.lookup(812) == (0x40000 + 300) << 12  # slot 12 -> sibling of 8, 812 - 512 = 300
    assert tree.lookup(1023) == (0x40000 + 511) << 12
    assert tree.lookup(1024) is None
    listing = tree.listing()
    assert len(listing) == 512 and listing[0] == (512, 0x40000 << 12) and listing[-1] == (1023, (0x40000 + 511) << 12)
    assert len(tree.listing(limit=10)) == 10


def test_value_and_retry_entries_are_not_resident():
    tree = Tree()
    leaf = tree.node(0, {0: (0xABC << 1) | 1, 1: (256 << 2) | 2, 2: (257 << 2) | 2, 3: page(3)})
    tree.head(node_entry(leaf))
    assert [tree.lookup(i) for i in range(4)] == [None, None, None, 3 << 12]
    assert tree.listing() == [(3, 3 << 12)]


def test_inconsistent_child_shift_and_unreadable_nodes_give_none():
    tree = Tree()
    bad_child = tree.node(12, {0: page(1)})  # a child of a shift-6 node must have shift 0
    root = tree.node(6, {0: node_entry(bad_child), 1: node_entry(0xFFFF888000900000)})
    tree.head(node_entry(root))
    assert tree.lookup(0) is None
    assert tree.lookup(64) is None
    assert tree.listing() == []
    odd = Tree()
    odd.head(node_entry(odd.node(5, {0: page(1)})))  # shift not a multiple of 6
    assert odd.lookup(0) is None


def test_node_entry_in_a_leaf_is_rejected():
    tree = Tree()
    other = tree.node(0, {0: page(1)})
    leaf = tree.node(0, {0: node_entry(other)})
    tree.head(node_entry(leaf))
    assert tree.lookup(0) is None
    assert tree.listing() == []


def test_offsets_come_from_the_layout():
    tree = Tree()
    leaf = tree.node(0, {3: page(9)})
    tree.reader.write(MAPPING + 0x100 + 8, struct.pack("<Q", node_entry(leaf)))  # i_pages moved to 0x100
    kl = {"address_space.i_pages": 0x100}
    assert pc.mapping_page(tree.reader, kl, MAPPING, 3, to_phys) == 9 << 12
    assert pc.mapping_page(tree.reader, {}, MAPPING, 3, to_phys) is None  # default offset: nothing there


def test_unconvertible_page_is_none():
    tree = Tree().head(page(1))
    assert pc.mapping_page(tree.reader, {}, MAPPING, 0, lambda _: None) is None
    assert list(pc.iter_mapping_pages(tree.reader, {}, MAPPING, 10, lambda _: None)) == []


class VolPage:
    def __init__(self, paddr):
        self.paddr = paddr

    def to_paddr(self):
        if self.paddr is None:
            raise ValueError("unreadable")
        return self.paddr


def test_page_to_phys_prefers_to_paddr_then_vmemmap_arithmetic():
    assert pc.page_to_phys(VolPage(0x1234000)) == 0x1234000
    assert pc.page_to_phys(VolPage(None)) is None
    assert pc.page_to_phys(page(5), VMEMMAP) == 5 << 12
    assert pc.page_to_phys(page(5), VMEMMAP, sizeof_page=80) == ((5 * 64) // 80) << 12
    assert pc.page_to_phys(page(5)) is None              # no vmemmap base known
    assert pc.page_to_phys(VMEMMAP - 64, VMEMMAP) is None


def test_make_page_to_phys():
    arithmetic = pc.make_page_to_phys(VMEMMAP)
    assert arithmetic(page(7)) == 7 << 12
    via_object = pc.make_page_to_phys(VMEMMAP, page_object=lambda a: VolPage(0xABC000))
    assert via_object(page(7)) == 0xABC000

    def broken(_):
        raise RuntimeError("no such object")
    assert pc.make_page_to_phys(VMEMMAP, page_object=broken)(page(7)) == 7 << 12
    assert pc.make_page_to_phys(VMEMMAP, page_object=lambda a: object())(page(8)) == 8 << 12


@pytest.mark.parametrize("index", [0, 1, 63, 64, 4095, 4096, 2 ** 40, 2 ** 64 - 1])
def test_deep_tree_reaches_any_index(index):
    """A full-height path (shift 60 .. 0) for one index."""
    tree = Tree()
    entry = page(42)
    for shift in range(0, 66, 6):
        slot = (index >> shift) & 63
        entry = node_entry(tree.node(shift, {slot: entry}))
    tree.head(entry)
    assert tree.lookup(index) == 42 << 12
    assert tree.lookup(index ^ 1) is None
    assert tree.listing() == [(index, 42 << 12)]


def test_stale_slot_whose_page_belongs_to_another_file_is_skipped():
    """A live dump can hold a slot whose page was reused by another mapping."""
    tree = Tree()
    leaf = tree.node(0, {0: page(1), 1: page(2)})
    tree.own(page(2), mapping=0xFFFF888000777000)  # page 2 now belongs to another file
    tree.head(node_entry(leaf))
    assert tree.lookup(0) == 1 << 12
    assert tree.lookup(1) is None
    assert pc.mapping_page(tree.reader, {}, MAPPING, 1, to_phys, check_mapping=False) == 2 << 12
    assert tree.listing() == [(0, 1 << 12)]
    assert list(pc.iter_mapping_pages(tree.reader, {}, MAPPING, 10, to_phys, check_mapping=False)) == [
        (0, 1 << 12), (1, 2 << 12)]
    unreadable = Tree()
    unreadable.reader.write(MAPPING, bytes(16) + struct.pack("<Q", page(9)))  # struct page not readable
    assert unreadable.lookup(0) is None


def test_canonical_address_and_a_masked_mapping_argument():
    assert pc.canonical_address(0x8D366C750740) == 0xFFFF8D366C750740      # 4-level, vol3-masked
    assert pc.canonical_address(0x1FF8D366C750740) == 0xFFFF8D366C750740   # LA57, vol3-masked
    assert pc.canonical_address(0xFFFF8D366C750740) == 0xFFFF8D366C750740
    assert pc.canonical_address(0x1234000) == 0x1234000                     # user / physical
    tree = Tree()
    tree.head(node_entry(tree.node(0, {2: page(5)})))
    masked = MAPPING & ((1 << 48) - 1)   # what int(inode.i_mapping) gives in vol3
    tree.reader.write(masked + 16, struct.pack("<Q", node_entry(NODE_BASE)))  # the layer accepts both forms
    assert pc.mapping_page(tree.reader, {}, masked, 2, to_phys) == 5 << 12
