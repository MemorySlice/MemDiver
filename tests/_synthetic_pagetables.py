"""Synthetic x86_64 4-level page tables in a bytes buffer, driving a REAL vol3 Linux layer.

``PageTables`` allocates table frames from a bump allocator inside a physical buffer and
writes entries exactly as Linux does (PROT_NONE PFNs inverted, swap entries non-present
with bit 8 clear). ``layer()`` stacks a ``LinuxIntel32e`` (or plain ``Intel32e``) over a
``BufferDataLayer`` so tests exercise vol3's own ``_translate_entry``.
"""
import struct

P, RW, USER, ACCESSED, DIRTY, PSE, PROTNONE = 1, 2, 4, 0x20, 0x40, 0x80, 0x100
SAVED_DIRTY = 1 << 58
NX = 1 << 63
PFN_MASK = ((1 << 52) - 1) & ~0xFFF
TABLE = P | RW | USER | ACCESSED | DIRTY
PHYS_SIZE = 16 << 20  # 16 MiB of "RAM": tables from 1 MiB, data frames below / above
_SHIFTS = (39, 30, 21, 12)


def pte(pa, flags=P | USER | ACCESSED):
    return (pa & PFN_MASK) | flags


def protnone_pte(pa, flags=PROTNONE | USER | ACCESSED):
    """Linux pfn_pte() for a PROT_NONE page: the PFN field is stored inverted."""
    return (~pa & PFN_MASK) | flags


def swap_pte(swp_type=0, offset=0x1234):
    """x86_64 swap entry (pgtable_64.h): ~offset in bits 9-58, type in 59-63, P=0, bit8=0."""
    return (swp_type << 59) | ((~offset << 9) & (((1 << 59) - 1) & ~0x1FF))


class PhysMemory(object):
    """The physical buffer plus a bump allocator for page-table frames (from 1 MiB)."""

    def __init__(self):
        self.buf = bytearray(PHYS_SIZE)
        self._next_table = 0x100000

    def alloc_table(self):
        pa = self._next_table
        self._next_table += 0x1000
        return pa


class PageTables(object):
    """One address space; several may share one :class:`PhysMemory`."""

    def __init__(self, mem):
        self.mem = mem
        self.buf = mem.buf
        self.root = mem.alloc_table()

    def _slot(self, table, va, shift):
        return table + ((va >> shift) & 0x1FF) * 8

    def _get(self, slot):
        return struct.unpack_from("<Q", self.buf, slot)[0]

    def _put(self, slot, value):
        struct.pack_into("<Q", self.buf, slot, value & ((1 << 64) - 1))

    def _table_for(self, va, depth):
        """The table at ``depth`` (0 = PML4 ... 3 = PT) for ``va``, creating parents."""
        table = self.root
        for shift in _SHIFTS[:depth]:
            slot = self._slot(table, va, shift)
            entry = self._get(slot)
            if not entry & P:
                entry = self.mem.alloc_table() | TABLE
                self._put(slot, entry)
            table = entry & PFN_MASK
        return table

    def set_pte(self, va, entry):
        self._put(self._slot(self._table_for(va, 3), va, 12), entry)

    def set_pmd(self, va, entry):
        """A 2 MiB leaf (``entry`` should carry PSE) or a raw PMD value."""
        self._put(self._slot(self._table_for(va, 2), va, 21), entry)

    def map4k(self, va, pa, flags=P | USER | ACCESSED):
        self.set_pte(va, pte(pa, flags))


def layers(mem, tables_list, linux=True):
    """One vol3 context over ``mem``; one Intel32e layer per address space (CR3 = root)."""
    from volatility3.framework import contexts
    from volatility3.framework.layers import intel, physical

    ctx = contexts.Context()
    ctx.layers.add_layer(physical.BufferDataLayer(ctx, "phys", "phys", bytes(mem.buf)))
    cls = intel.LinuxIntel32e if linux else intel.Intel32e
    out = []
    for i, tables in enumerate(tables_list):
        name = "proc%d" % i
        ctx.config[name + ".memory_layer"] = "phys"
        ctx.config[name + ".page_map_offset"] = tables.root
        out.append(cls(ctx, name, name))
        ctx.layers.add_layer(out[-1])
    return out


def layer(mem, tables, linux=True):
    return layers(mem, [tables], linux)[0]
