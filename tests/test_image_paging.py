"""Tests for core/image/paging.py: 4-level vs LA57 kernel paging chosen by read-back.

The page tables are built by hand inside a vol3 ``BufferDataLayer`` (no image,
no ISF); the "symbol table" is a small fake exposing the vol3 surface that
``paging`` touches.
"""

import struct

import pytest
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import intel, physical

from memdiver.core.image import paging
from memdiver.core.image.paging import (
    START_KERNEL_MAP,
    KernelPaging,
    LinuxIntel5Level,
    choose_kernel_layer,
    kernel_dtb,
    read_la57_symbol,
)

PAGE = 0x1000
BANNER = b"Linux version test"
BANNER_VA = 0xFFFFFFFF82000000          # top 2 GiB (kernel image)
DIRECT_MAP_VA = 0xFF11000000001000      # 57-bit direct-map style address
DIRECT_MAP_VA_48 = 0xFFFF888000001000   # 48-bit direct-map style address
COMM_OFFSET = 0x20
INIT_TASK_OFFSET = 0x100
LA57_FLAG_PHYS = 0x20000
MEM_SIZE = 0x21000


def _indices(va, levels):
    shifts = [48, 39, 30, 21, 12][-levels:]
    return [(va >> s) & 0x1FF for s in shifts]


def build_memory(va, levels, payload_at_page_start=True):
    """Page-table memory mapping ``va``'s page; tables at 0x1000.. , data page after.

    Returns ``(buffer, dtb, data_phys)``. Also plants a ``swapper/0`` comm and the
    LA57 flag so ``choose_kernel_layer`` has everything to read back.
    """
    mem = bytearray(MEM_SIZE)
    idx = _indices(va, levels)
    table_addrs = [PAGE * (n + 1) for n in range(levels)]
    data_phys = PAGE * (levels + 1)
    targets = table_addrs[1:] + [data_phys]
    for table, index, target in zip(table_addrs, idx, targets):
        struct.pack_into("<Q", mem, table + index * 8, target | 0x3)
    page_off = va & 0xFFF
    mem[data_phys + page_off:data_phys + page_off + len(BANNER)] = BANNER
    comm = data_phys + page_off + INIT_TASK_OFFSET + COMM_OFFSET
    mem[comm:comm + 9] = b"swapper/0"
    struct.pack_into("<I", mem, LA57_FLAG_PHYS, 1 if levels == 5 else 0)
    return bytes(mem), table_addrs[0], data_phys


def make_ctx(buffer):
    ctx = contexts.Context()
    ctx.add_layer(physical.BufferDataLayer(ctx, "mem", "mem", buffer))
    return ctx


def add_layer(ctx, cls, dtb, name="virt"):
    ctx.config[f"{name}.memory_layer"] = "mem"
    ctx.config[f"{name}.page_map_offset"] = dtb
    ctx.add_layer(cls(ctx, name, name, metadata={"os": "Linux"}))
    return ctx.layers[name]


# ------------------------------------------------------------ fake symbol table

class _Sym:
    def __init__(self, address):
        self.address = address


class _Type:
    def relative_child_offset(self, name):
        assert name == "comm"
        return COMM_OFFSET


class FakeTable:
    def __init__(self, symbols, with_task=True):
        self.symbols = dict(symbols)
        self.types = {"task_struct": _Type()} if with_task else {}

    def get_symbol(self, name):
        return _Sym(self.symbols[name])

    def get_type(self, name):
        return self.types[name]


class CtxProxy:
    """Real context, but ``symbol_space`` is a plain dict of fake tables."""

    def __init__(self, ctx, table):
        self._ctx = ctx
        self.symbol_space = {"tbl": table}

    def __getattr__(self, name):
        return getattr(self._ctx, name)


def kernel_symbols(dtb, pgd="init_top_pgt", shift=0):
    return {pgd: START_KERNEL_MAP + dtb - shift, "linux_banner": BANNER_VA,
            "init_task": BANNER_VA + INIT_TASK_OFFSET,
            "__pgtable_l5_enabled": START_KERNEL_MAP + LA57_FLAG_PHYS}


def kernel_setup(levels, va=BANNER_VA, **table_kw):
    buffer, dtb, _ = build_memory(va, levels)
    ctx = make_ctx(buffer)
    return CtxProxy(ctx, FakeTable(kernel_symbols(dtb), **table_kw)), dtb


# ------------------------------------------------------------ layer translation

@pytest.mark.parametrize("va", [DIRECT_MAP_VA, BANNER_VA])
def test_five_level_layer_translates_la57_kernel_addresses(va):
    buffer, dtb, data_phys = build_memory(va, 5)
    ctx = make_ctx(buffer)
    layer = add_layer(ctx, LinuxIntel5Level, dtb)
    assert layer.read(va, len(BANNER), pad=False) == BANNER
    phys = layer.translate(va)[0]
    assert phys == data_phys + (va & 0xFFF)


@pytest.mark.parametrize("va", [DIRECT_MAP_VA, BANNER_VA])
def test_stock_four_level_layer_cannot_read_a_five_level_table(va):
    buffer, dtb, _ = build_memory(va, 5)
    layer = add_layer(make_ctx(buffer), intel.LinuxIntel32e, dtb)
    try:
        data = layer.read(va, len(BANNER), pad=False)
    except exceptions.InvalidAddressException:
        return
    assert data != BANNER


@pytest.mark.parametrize("va", [DIRECT_MAP_VA_48, BANNER_VA])
def test_four_level_layer_translates_a_four_level_table(va):
    buffer, dtb, _ = build_memory(va, 4)
    layer = add_layer(make_ctx(buffer), intel.LinuxIntel32e, dtb)
    assert layer.read(va, len(BANNER), pad=False) == BANNER


@pytest.mark.parametrize("va", [DIRECT_MAP_VA_48, BANNER_VA])
def test_five_level_layer_cannot_read_a_four_level_table(va):
    buffer, dtb, _ = build_memory(va, 4)
    layer = add_layer(make_ctx(buffer), LinuxIntel5Level, dtb)
    try:
        data = layer.read(va, len(BANNER), pad=False)
    except exceptions.InvalidAddressException:
        return
    assert data != BANNER


def test_five_level_layer_declares_57_bit_addresses_and_an_extra_level():
    assert LinuxIntel5Level._maxvirtaddr == 57
    assert len(LinuxIntel5Level._structure) == len(intel.Intel32e._structure) + 1
    assert LinuxIntel5Level._structure[0][1] == 9
    assert paging.LAYER_BY_VA_BITS == {48: intel.LinuxIntel32e, 57: LinuxIntel5Level}


# ------------------------------------------------------------ kernel_dtb

def test_kernel_dtb_prefers_init_top_pgt():
    table = FakeTable({"init_top_pgt": START_KERNEL_MAP + 0x1000,
                       "init_level4_pgt": START_KERNEL_MAP + 0x9000})
    assert kernel_dtb(table, 0) == 0x1000


def test_kernel_dtb_falls_back_to_init_level4_pgt():
    table = FakeTable({"init_level4_pgt": START_KERNEL_MAP + 0x9000})
    assert kernel_dtb(table, 0) == 0x9000


def test_kernel_dtb_applies_the_physical_kaslr_shift():
    table = FakeTable({"init_top_pgt": START_KERNEL_MAP + 0x1000})
    assert kernel_dtb(table, 0x200000) == 0x201000


def test_kernel_dtb_without_a_pgd_symbol_is_a_value_error():
    with pytest.raises(ValueError, match="init_top_pgt"):
        kernel_dtb(FakeTable({"linux_banner": 1}), 0)


# ------------------------------------------------------------ read_la57_symbol

def test_read_la57_symbol_reads_the_flag_from_physical_memory():
    for levels, expected in ((5, 1), (4, 0)):
        ctx, _ = kernel_setup(levels)
        assert read_la57_symbol(ctx, "mem", ctx.symbol_space["tbl"], 0) == expected


def test_read_la57_symbol_is_none_without_the_symbol_or_when_unreadable():
    ctx, _ = kernel_setup(5)
    assert read_la57_symbol(ctx, "mem", FakeTable({}), 0) is None
    far = FakeTable({"__pgtable_l5_enabled": START_KERNEL_MAP + MEM_SIZE * 4})
    assert read_la57_symbol(ctx, "mem", far, 0) is None


# ------------------------------------------------------------ _candidate_order

@pytest.mark.parametrize("hint, order", [(None, [57, 48]), (57, [57, 48]),
                                         (48, [48, 57]), (39, [57, 48])])
def test_candidate_order_puts_a_valid_hint_first(hint, order):
    assert paging._candidate_order(hint) == order


# ------------------------------------------------------------ choose_kernel_layer

def test_choose_picks_57_for_five_level_memory():
    ctx, dtb = kernel_setup(5)
    result = choose_kernel_layer(ctx, "mem", "tbl", 0, 0)
    assert isinstance(result, KernelPaging)
    assert (result.va_bits, result.dtb, result.rejected) == (57, dtb, ())
    assert result.la57_symbol == 1
    assert isinstance(ctx.layers[result.layer_name], LinuxIntel5Level)


def test_choose_picks_48_for_four_level_memory_and_rejects_57():
    ctx, dtb = kernel_setup(4)
    result = choose_kernel_layer(ctx, "mem", "tbl", 0, 0)
    assert (result.va_bits, result.dtb) == (48, dtb)
    assert len(result.rejected) == 1 and result.rejected[0].startswith("57-bit:")
    assert result.la57_symbol == 0
    assert type(ctx.layers[result.layer_name]) is intel.LinuxIntel32e


def test_a_wrong_hint_is_tried_first_but_still_rejected():
    ctx, _ = kernel_setup(5)
    result = choose_kernel_layer(ctx, "mem", "tbl", 0, 0, va_bits_hint=48)
    assert result.va_bits == 57
    assert len(result.rejected) == 1 and result.rejected[0].startswith("48-bit:")


def test_a_correct_hint_leaves_nothing_rejected():
    ctx, _ = kernel_setup(4)
    assert choose_kernel_layer(ctx, "mem", "tbl", 0, 0, va_bits_hint=48).rejected == ()


def test_rejected_candidates_are_removed_from_the_context():
    ctx, _ = kernel_setup(4)
    result = choose_kernel_layer(ctx, "mem", "tbl", 0, 0)
    assert [n for n in ctx.layers if n.startswith("kernel")] == [result.layer_name]


def test_choose_raises_when_neither_depth_reads_the_kernel():
    ctx, _ = kernel_setup(5)
    ctx.symbol_space["tbl"].symbols["linux_banner"] = 0xFFFFFFFF83000000  # unmapped
    with pytest.raises(ValueError, match="no paging depth"):
        choose_kernel_layer(ctx, "mem", "tbl", 0, 0)
    assert [n for n in ctx.layers if n.startswith("kernel")] == []


def test_choose_rejects_a_depth_that_translates_but_reads_wrong_bytes():
    ctx, _ = kernel_setup(5)
    ctx.symbol_space["tbl"].symbols["linux_banner"] = BANNER_VA + 1  # off by one
    with pytest.raises(ValueError, match="reads"):
        choose_kernel_layer(ctx, "mem", "tbl", 0, 0)


def test_choose_also_checks_init_task_comm():
    ctx, _ = kernel_setup(5)
    ctx.symbol_space["tbl"].symbols["init_task"] = BANNER_VA + 0x180  # no swapper there
    with pytest.raises(ValueError, match="init_task"):
        choose_kernel_layer(ctx, "mem", "tbl", 0, 0)


def test_choose_skips_init_task_check_when_the_profile_lacks_task_struct():
    ctx, _ = kernel_setup(5, with_task=False)
    ctx.symbol_space["tbl"].symbols["init_task"] = BANNER_VA + 0x180
    assert choose_kernel_layer(ctx, "mem", "tbl", 0, 0).va_bits == 57


def test_choose_honours_an_explicit_dtb_over_the_symbol():
    ctx, dtb = kernel_setup(5)
    ctx.symbol_space["tbl"].symbols["init_top_pgt"] = START_KERNEL_MAP + 0x9000  # wrong
    assert choose_kernel_layer(ctx, "mem", "tbl", 0, 0, dtb=dtb).dtb == dtb


def test_choose_applies_the_virtual_kaslr_shift():
    ctx, _ = kernel_setup(5)
    syms = ctx.symbol_space["tbl"].symbols
    syms["linux_banner"] -= 0x1000   # unshifted address is one page below the mapping
    syms["init_task"] -= 0x1000
    assert choose_kernel_layer(ctx, "mem", "tbl", 0, 0x1000).va_bits == 57


def test_kernel_paging_to_dict_lists_rejections():
    kp = KernelPaging("kernel57", 57, 0x1000, 0, 0, None, ("48-bit: x",))
    assert kp.to_dict() == {"layer": "kernel57", "va_bits": 57, "dtb": 0x1000,
                            "kaslr_shift": 0, "aslr_shift": 0, "la57_symbol": None,
                            "rejected": ["48-bit: x"]}
