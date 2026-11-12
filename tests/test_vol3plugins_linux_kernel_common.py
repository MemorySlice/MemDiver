"""``vol3plugins/linux/kernel_common.py``: the helpers every ``linux.*`` secret plugin shares."""

from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import exceptions  # noqa: E402

from memdiver.vol3plugins.linux import kernel_common as kc  # noqa: E402
from tests.test_vol3plugins_linux_dmcrypt import Mem  # noqa: E402

MASK = (1 << 48) - 1
CANONICAL = 0xFFFF000000000000


# --------------------------------------------------------------------------- small helpers


def test_nonzero_and_align_up():
    assert not kc.nonzero(None) and not kc.nonzero(b"") and not kc.nonzero(bytes(4))
    assert kc.nonzero(b"\0\1")
    assert kc.align_up(2560, 32) == 2560 and kc.align_up(2561, 64) == 2624
    assert kc.align_up(7, 1) == 7 and kc.align_up(7, 0) == 7


def test_safe_reader_reads_little_endian_and_never_raises():
    mem = Mem()
    address = mem.alloc(16)
    mem.u32(address, 0x11223344)
    reader = mem.reader()
    assert reader.u32(address) == 0x11223344 and reader.u8(address) == 0x44
    assert reader.read(0, 4) is None and reader.read(address, 0) is None
    assert reader.ptr(1 << 60) is None


# --------------------------------------------------------------------------- walks


def _ring(mem, count, member_offset=0, masked_head=False):
    """A ``list_head`` ring of ``count`` containers; returns (head as handed out, containers)."""
    head = mem.alloc(16)
    containers = [mem.alloc(64) for _ in range(count)]
    links = [c + member_offset for c in containers]
    for here, nxt in zip([head] + links, links + [head]):
        mem.ptr(here, nxt)
    return (head | CANONICAL if masked_head else head), containers


def test_is_list_head_matches_canonical_and_masked_forms():
    assert kc.is_list_head(0x1000, 0x1000)
    assert kc.is_list_head(0x1000 | CANONICAL, 0x1000) and kc.is_list_head(0x1000, 0x1000 | CANONICAL)
    assert not kc.is_list_head(0x1008, 0x1000)


def test_iter_list_yields_containers_and_excludes_the_head():
    mem = Mem()
    head, containers = _ring(mem, 3, member_offset=8)
    assert list(kc.iter_list(mem.reader(), head, 8, 16)) == containers


def test_iter_list_never_walks_a_head_in_its_other_address_form():
    mem = Mem()
    head, containers = _ring(mem, 2)

    class Canonical(kc.SafeReader):  # memory holds canonical pointers, the symbol is masked
        def ptr(self, address):
            value = super().ptr(address & MASK)
            return value | CANONICAL if value else value

    reader = Canonical(mem.reader().layer)
    assert [c & MASK for c in kc.iter_list(reader, head, 0, 16)] == containers


def test_iter_list_is_bounded_and_cycle_safe():
    mem = Mem()
    head, containers = _ring(mem, 4)
    mem.ptr(containers[-1], containers[1])  # a cycle that never returns to the head
    assert list(kc.iter_list(mem.reader(), head, 0, 100)) == containers
    assert len(list(kc.iter_list(mem.reader(), head, 0, 2))) == 2


def _tree(mem):
    """b(a, c) with rb_left at 16 and rb_right at 8 (the LP64 ``rb_node``)."""
    nodes = {name: mem.alloc(24) for name in "abc"}
    mem.ptr(nodes["b"] + 16, nodes["a"])
    mem.ptr(nodes["b"] + 8, nodes["c"])
    return nodes


def test_iter_rb_nodes_is_in_order():
    mem = Mem()
    nodes = _tree(mem)
    assert list(kc.iter_rb_nodes(mem.reader(), 16, 8, nodes["b"], 10)) == [nodes[n] for n in "abc"]


def test_iter_rb_nodes_stops_at_the_limit_and_on_a_cycle():
    mem = Mem()
    nodes = _tree(mem)
    assert list(kc.iter_rb_nodes(mem.reader(), 16, 8, nodes["b"], 1)) == [nodes["a"]]
    mem.ptr(nodes["a"] + 16, nodes["b"])  # a's left points back at the root
    assert list(kc.iter_rb_nodes(mem.reader(), 16, 8, nodes["b"], 10)) == [nodes[n] for n in "abc"]


# --------------------------------------------------------------------------- ISF resolver


def _template(members=None, size=8, **vol):
    """A vol3-shaped template: ``.vol`` mapping, ``relative_child_offset`` raising IndexError."""
    members = members or {}

    def relative_child_offset(member):
        if member not in members:
            raise IndexError(member)
        return members[member][0]

    return SimpleNamespace(vol=dict(vol, members=members), size=size,
                           relative_child_offset=relative_child_offset)


class FakeModule:
    def __init__(self, types):
        self.types = types

    def get_type(self, name):
        if name not in self.types:
            raise exceptions.SymbolError(name, "fake", "no %s" % name)
        return self.types[name]


def _module():
    qstr = _template({"name": (8, _template(size=8))}, size=16)
    union = _template({"d_alias": (0, _template(size=16)), "d_rcu": (0, _template(size=16))})
    dentry = _template({"d_name": (32, qstr), "unnamed_field_0": (176, union)}, size=192)
    key = _template({"serial": (4, _template(size=4)),
                     "unnamed_field_1": (184, _template({"payload": (0, _template(size=32))}))})
    secret = _template({"bytes": (12, _template(size=128))})
    return FakeModule({"dentry": dentry, "key": key, "fscrypt_inode_info": secret,
                       "char_array_holder": _template({"name": (0, _template(size=56, count=56))}, size=56)})


def test_isf_offset_direct_nested_union_and_missing():
    module = _module()
    assert kc.isf_offset(module, "key", "serial") == 4
    assert kc.isf_offset(module, "key", "payload") == 184  # inside an anonymous union
    assert kc.isf_offset(module, "dentry", "d_name.name") == 40  # nested path
    assert kc.isf_offset(module, "dentry", "d_alias") == 176
    assert kc.isf_offset(module, "dentry", "missing") is None
    assert kc.isf_offset(module, "no_such_type", "serial") is None


def test_isf_offset_type_and_member_aliases():
    module = _module()
    assert kc.isf_offset(module, ("fscrypt_info", "fscrypt_inode_info"), "raw", "bytes") == 12
    assert kc.isf_type(module, ("nope", "key")) is module.types["key"]
    assert kc.isf_type(module, "nope") is None


def test_isf_size_and_member_template():
    module = _module()
    assert kc.isf_size(module, "dentry") == 192 and kc.isf_size(module, "char_array_holder.name") == 56
    assert kc.isf_size(module, "dentry.missing") is None and kc.isf_size(module, "nope") is None
    assert kc.isf_member_template(module, "char_array_holder", "name").vol["count"] == 56
    assert kc.isf_member_template(module, "char_array_holder", "missing") is None


def test_find_member_tolerates_a_module_free_template():
    key = _module().types["key"]
    assert kc.find_member(None, key, "payload") == 184 and kc.find_member(None, key, "nope") is None


def test_isf_layout_resolve_records_isf_fallback_and_default():
    layout = kc.IsfLayout(offsets={"key.serial": 0, "key.table": 0, "key.guess": 99})
    layout.resolve(lambda key: 4 if key == "key.serial" else None,
                   lambda key: (12, "table") if key == "key.table" else None)
    assert layout["key.serial"] == 4 and layout.sources["key.serial"] == "isf"
    assert layout["key.table"] == 12 and layout.sources["key.table"] == "table"
    assert layout["key.guess"] == 99 and layout.defaulted() == ["key.guess"]
    assert kc.IsfLayout().defaulted() == []


# --------------------------------------------------------------------------- symbols and modules


class FakeVmlinux:
    offset = 0x1000
    symbol_table_name = "fake"

    def __init__(self, symbols=None, modules=()):
        self.symbols, self.modules = symbols or {}, list(modules)

    def get_symbol(self, name):
        if name not in self.symbols:
            raise exceptions.SymbolError(name, "fake", "no %s" % name)
        return SimpleNamespace(address=self.symbols[name])

    def object_from_symbol(self, name):
        assert name == "modules"
        return SimpleNamespace(to_list=lambda _type, _member: iter(self.modules))


def test_symbol_address_is_absolute_and_canonicalised_only_with_a_layer():
    vmlinux = FakeVmlinux({"super_blocks": 0x20})
    layer = SimpleNamespace(canonicalize=lambda address: address | CANONICAL)
    assert kc.symbol_address(vmlinux, "super_blocks") == 0x1020
    assert kc.symbol_address(vmlinux, "super_blocks", layer) == 0x1020 | CANONICAL
    assert kc.symbol_address(vmlinux, "missing") is None


def test_kernel_release_reads_linux_banner():
    mem = Mem()
    banner = mem.alloc(256)
    mem.put(banner, b"Linux version 6.8.0-136-generic (buildd@lcy02) ...\0")
    vmlinux = FakeVmlinux({"linux_banner": banner - FakeVmlinux.offset})
    assert kc.kernel_release(vmlinux, mem.reader()) == "6.8.0-136-generic"
    assert kc.kernel_release(FakeVmlinux(), mem.reader()) == ""


def test_find_module_and_module_symbol():
    wanted = SimpleNamespace(get_name=lambda: "wireguard", get_symbol=lambda n: {"device_list": 0xAB00}.get(n))
    other = SimpleNamespace(get_name=lambda: "xfs", get_symbol=lambda n: None)
    vmlinux = FakeVmlinux(modules=[other, wanted])
    assert kc.find_module(vmlinux, "wireguard") is wanted and kc.find_module(vmlinux, "dm_mod") is None
    assert kc.find_module(vmlinux, "wireguard", limit=0) is None  # the cap stops before the 2nd entry
    assert kc.module_symbol(wanted, "device_list") == 0xAB00 and kc.module_symbol(wanted, "nope") is None


def test_arch_of_reads_the_layer_class_names():
    class Intel32e:
        pass

    class AArch64:
        pass

    assert kc.arch_of(Intel32e()) == "x86_64" and kc.arch_of(AArch64()) == "aarch64"
    assert kc.arch_of(object()) == "unknown"
