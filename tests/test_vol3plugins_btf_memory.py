"""``secrets/btf_memory.py``: kernel-module struct layouts from in-memory (split) BTF.

Synthetic BTF blobs are built here (base + split, bitfields, anonymous members, typedef
chains, enums, hostile input), plus a fake kernel memory holding ``btf_vmlinux`` /
``btf_modules`` for the symbol walk and the signature scan.  The real-capture tests run
``linux.btf_layouts`` through stock ``vol`` and skip when the captures are absent.
"""

import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vol3plugins.linux.secrets import btf_memory as bm
from vol3plugins.linux.secrets import offsets as dm_offsets
from vol3plugins.linux.secrets import wg_offsets

REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- BTF builder


class BtfBuilder:
    """Minimal BTF writer: ``base`` (another builder) makes it split BTF."""

    def __init__(self, base=None, endian="<"):
        self.base, self.endian = base, endian
        self.strings = bytearray() if base else bytearray(b"\0")
        self.types = []
        self.start_id = base.next_id if base else 1
        self.start_str = len(base.strings) if base else 0

    @property
    def next_id(self):
        return self.start_id + len(self.types)

    def s(self, text):
        """String offset of ``text``, reusing a base string (split BTF dedup)."""
        if not text:
            return 0
        raw = text.encode() + b"\0"
        if self.base is not None:
            found = self.base.strings.find(b"\0" + raw)
            if found >= 0:
                return found + 1
        # A leading NUL so the section's first name (no NUL before it in a split blob) is found too;
        # name ``raw`` then starts at ``found`` in ``self.strings``.
        found = (b"\0" + bytes(self.strings)).find(b"\0" + raw)
        if found >= 0:
            return self.start_str + found
        offset = self.start_str + len(self.strings)
        self.strings += raw
        return offset

    def _add(self, name, kind, vlen, size_or_type, extra=b"", kind_flag=False):
        info = (kind << 24) | vlen | (1 << 31 if kind_flag else 0)
        self.types.append(struct.pack(self.endian + "III", self.s(name), info, size_or_type) + extra)
        return self.next_id - 1

    def int(self, name, size):
        return self._add(name, bm.KIND_INT, 0, size, struct.pack(self.endian + "I", size * 8))

    def ptr(self, target):
        return self._add("", bm.KIND_PTR, 0, target)

    def array(self, elem, nelems, index_type):
        return self._add("", bm.KIND_ARRAY, 0, 0, struct.pack(self.endian + "III", elem, index_type, nelems))

    def typedef(self, name, target):
        return self._add(name, bm.KIND_TYPEDEF, 0, target)

    def const(self, target):
        return self._add("", bm.KIND_CONST, 0, target)

    def fwd(self, name):
        return self._add(name, bm.KIND_FWD, 0, 0)

    def composite(self, name, size, members, union=False, bitfields=False):
        """``members``: ``(name, type, bit_offset[, bitfield_size])``."""
        extra = b""
        for member in members:
            member_name, type_id, bit_offset = member[:3]
            width = member[3] if len(member) > 3 else 0
            raw = (width << 24 | bit_offset) if bitfields else bit_offset
            extra += struct.pack(self.endian + "III", self.s(member_name), type_id, raw)
        kind = bm.KIND_UNION if union else bm.KIND_STRUCT
        return self._add(name, kind, len(members), size, extra, bitfields)

    def enum(self, name, values, signed=False):
        extra = b"".join(struct.pack(self.endian + ("Ii" if signed else "II"), self.s(n), v) for n, v in values)
        return self._add(name, bm.KIND_ENUM, len(values), 4, extra, signed)

    def enum64(self, name, values, signed=False):
        extra = b"".join(struct.pack(self.endian + "III", self.s(n), v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF)
                         for n, v in values)
        return self._add(name, bm.KIND_ENUM64, len(values), 8, extra, signed)

    def blob(self):
        types = b"".join(self.types)
        header = struct.pack(self.endian + "HBBIIIII", bm.BTF_MAGIC, 1, 0, 24, 0, len(types),
                             len(types), len(self.strings))
        return header + types + bytes(self.strings)


def _base():
    b = BtfBuilder()
    ids = {"int": b.int("int", 4), "u8": b.int("unsigned char", 1), "u64": b.int("long long unsigned int", 8)}
    ids["u8_t"] = b.typedef("u8", ids["u8"])
    ids["arr32"] = b.array(ids["u8_t"], 32, ids["int"])
    ids["list_head"] = b.composite("list_head", 16, [])
    b.types.pop()  # rebuild list_head with its self-pointer members
    lh = b.next_id
    ids["list_head"] = lh
    b.composite("list_head", 16, [("next", lh + 1, 0), ("prev", lh + 1, 64)])
    b.ptr(lh)
    ids["net_device"] = b.composite("net_device", 2544, [("name", ids["arr32"], 0)])
    b.s("cookie")  # a name the split BTF will reuse from the base, as on real kernels
    return b, ids


def _split(base, ids):
    m = BtfBuilder(base)
    out = {}
    u32 = m.typedef("u32", ids["int"])
    cu32 = m.const(u32)
    out["u32_chain"] = m.typedef("chained_u32", cu32)
    out["cookie"] = m.composite("cookie", 48, [("birthdate", ids["u64"], 0), ("is_valid", ids["u8"], 64),
                                               ("cookie_decryption_key", ids["arr32"], 8 * 10)])
    anon_inner = m.composite("", 8, [("a", ids["int"], 0), ("b", ids["int"], 32)])
    anon_union = m.composite("", 32, [("raw", ids["arr32"], 0), ("words", ids["u64"], 0)], union=True)
    named_inner = m.composite("inner", 4, [("x", ids["int"], 0)])
    peer_fwd = m.fwd("wg_peer")
    out["wg_peer"] = m.composite("wg_peer", 128, [
        ("device", m.ptr(ids["net_device"]), 0),
        ("", anon_inner, 64),
        ("", anon_union, 128),
        ("named", named_inner, 8 * 48),
        ("handshake_count", out["u32_chain"], 8 * 52),
        ("peer_list", ids["list_head"], 8 * 56),
        ("dev_embedded", ids["net_device"], 8 * 72),
        ("self", m.ptr(peer_fwd), 8 * 120),
    ])
    out["bits"] = m.composite("bits", 8, [("lo", ids["int"], 0, 3), ("hi", ids["int"], 3, 5),
                                           ("byte1", ids["u8"], 8), ("tail", ids["int"], 32, 0)], bitfields=True)
    out["flags"] = m.enum("flags", [("F_A", 0), ("F_B", 1), ("F_C", 5)])
    out["sflags"] = m.enum("sflags", [("NEG", -2)], signed=True)
    out["big"] = m.enum64("big", [("HUGE", 1 << 40), ("MINUS", -1)], signed=True)
    return m, out


@pytest.fixture(scope="module")
def parsed():
    base_builder, ids = _base()
    split_builder, out = _split(base_builder, ids)
    base = bm.parse_btf(base_builder.blob())
    split = bm.parse_btf(split_builder.blob(), base)
    return base, split, base_builder, split_builder


# --------------------------------------------------------------------------- parser


def test_base_and_split_counts_continue(parsed):
    base, split, base_builder, split_builder = parsed
    assert base.type_count == base_builder.next_id and base.start_id == 1
    assert split.start_id == base.type_count and split.start_str_off == base.str_len
    assert split.type_count == split_builder.next_id
    assert split.own_type_count == len(split_builder.types)


def test_split_struct_resolves_base_types_and_base_strings(parsed):
    _base_btf, split, *_ = parsed
    cookie = split.struct("cookie")
    assert cookie.size == 48 and cookie.kind == "struct"
    assert [(m.name, m.offset, m.size) for m in cookie.members] == [
        ("birthdate", 0, 8), ("is_valid", 8, 1), ("cookie_decryption_key", 10, 32)]
    assert cookie.member("cookie_decryption_key").type_name == "u8[32]"


def test_anonymous_members_are_flattened_named_ones_are_not(parsed):
    _base_btf, split, *_ = parsed
    peer = split.struct("wg_peer")
    by_name = {m.name: m for m in peer.members}
    assert (by_name["a"].offset, by_name["b"].offset) == (8, 12)
    assert (by_name["raw"].offset, by_name["words"].offset) == (16, 16)
    assert by_name["named"].offset == 48 and "x" not in by_name
    assert by_name["named"].type_name == "struct inner"
    assert by_name["device"].type_name == "struct net_device *" and by_name["device"].size == 8
    assert by_name["dev_embedded"].size == 2544 and by_name["peer_list"].size == 16
    assert by_name["self"].type_name == "struct wg_peer *"  # through a FWD


def test_typedef_const_chains_resolve_sizes(parsed):
    _base_btf, split, *_ = parsed
    member = split.struct("wg_peer").member("handshake_count")
    assert member.size == 4 and member.offset == 52 and member.type_name == "chained_u32"


def test_bitfields_from_kind_flag(parsed):
    _base_btf, split, *_ = parsed
    bits = {m.name: m for m in split.struct("bits").members}
    assert (bits["lo"].bit_offset, bits["lo"].bitfield_size, bits["lo"].offset) == (0, 3, 0)
    assert (bits["hi"].bit_offset, bits["hi"].bitfield_size, bits["hi"].size) == (3, 5, 1)
    assert (bits["byte1"].offset, bits["byte1"].bitfield_size, bits["byte1"].size) == (1, 0, 1)
    assert bits["tail"].offset == 4 and bits["tail"].size == 4
    flat = bm.flat_offsets([split.struct("bits")])
    assert "bits.lo" not in flat and flat["bits.byte1"] == 1 and flat["sizeof(bits)"] == 8
    document = bm.btf_offsets_document([split.struct("bits")])
    assert document["bits"]["members"]["hi"]["bitfield_size"] == 5


def test_flat_offsets_use_the_offset_table_key_format(parsed):
    _base_btf, split, *_ = parsed
    flat = bm.flat_offsets([split.struct("wg_peer"), split.struct("cookie")])
    assert flat["wg_peer.device"] == 0 and flat["sizeof(wg_peer)"] == 128
    assert flat["cookie.cookie_decryption_key"] == 10 and flat["wg_peer.a"] == 8


def test_document_is_accepted_by_the_wireguard_offsets_loader(parsed):
    _base_btf, split, *_ = parsed
    text = json.dumps({"btf_offsets": bm.btf_offsets_document([split.struct("cookie")])})
    base = wg_offsets.lookup_offsets("x86_64", "6.8.0-136-generic")
    loaded = wg_offsets.load_offsets_json(text, "memory", base)
    assert loaded.members["cookie.cookie_decryption_key"] == 10


def test_enums(parsed):
    _base_btf, split, *_ = parsed
    assert split.enum("flags") == {"F_A": 0, "F_B": 1, "F_C": 5}
    assert split.enum("sflags") == {"NEG": -2}
    assert split.enum("big") == {"HUGE": 1 << 40, "MINUS": -1}
    with pytest.raises(bm.BtfParseError):
        split.enum("nope")


def test_lookup_falls_back_to_base_and_lists_names(parsed):
    base, split, *_ = parsed
    assert split.struct("net_device").size == 2544
    assert "wg_peer" in split.struct_names() and "net_device" not in split.struct_names()
    with pytest.raises(bm.BtfParseError):
        split.struct("missing_struct")
    with pytest.raises(bm.BtfParseError):
        base.struct("wg_peer")


def test_big_endian_blob_parses():
    b = BtfBuilder(endian=">")
    i = b.int("int", 4)
    b.composite("be", 8, [("x", i, 32)])
    assert bm.parse_btf(b.blob()).struct("be").member("x").offset == 4


def test_split_endianness_must_match_base():
    base = BtfBuilder()
    base.int("int", 4)
    split = BtfBuilder(base, endian=">")
    split.int("x", 4)
    with pytest.raises(bm.BtfParseError):
        bm.parse_btf(split.blob(), bm.parse_btf(base.blob()))


def test_conflicting_duplicate_struct_definitions_are_refused():
    b = BtfBuilder()
    i = b.int("int", 4)
    b.composite("dup", 8, [("x", i, 0)])
    b.composite("dup", 8, [("x", i, 32)])
    with pytest.raises(bm.BtfParseError):
        bm.parse_btf(b.blob()).struct("dup")


# --------------------------------------------------------------------------- hostile input


def _valid_blob():
    base_builder, ids = _base()
    return base_builder.blob()


def _patch(blob, offset, fmt, value):
    data = bytearray(blob)
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


@pytest.mark.parametrize("mutate", [
    lambda b: b"",
    lambda b: b[:10],
    lambda b: b"\x00\x00" + b[2:],  # magic
    lambda b: _patch(b, 2, "<B", 2),  # version
    lambda b: _patch(b, 3, "<B", 1),  # flags
    lambda b: _patch(b, 4, "<I", 4096),  # hdr_len beyond data
    lambda b: _patch(b, 4, "<I", 12),  # hdr_len too short
    lambda b: _patch(b, 12, "<I", struct.unpack_from("<I", b, 12)[0] + 4),  # type_len overlaps strings
    lambda b: _patch(b, 16, "<I", struct.unpack_from("<I", b, 16)[0] + 4),  # gap before strings
    lambda b: b[:-1] + b"x",  # string section not NUL-terminated
    lambda b: b + b"\0\0\0\0",  # trailing unknown data
    lambda b: _patch(b, 24 + 4, "<I", 31 << 24),  # unknown kind
    lambda b: _patch(b, 24 + 4, "<I", (bm.KIND_ENUM << 24) | 0xFFFF),  # vlen overruns
], ids=["empty", "short", "magic", "version", "flags", "hdr_long", "hdr_short", "overlap", "gap",
        "str_nul", "trailing", "kind", "vlen"])
def test_hostile_headers_raise_only_btf_parse_error(mutate):
    with pytest.raises(bm.BtfParseError):
        bm.parse_btf(mutate(_valid_blob()))


def test_extended_header_must_be_zero():
    blob = _valid_blob()
    extended = _patch(blob[:4] + struct.pack("<I", 28) + blob[8:24] + b"\1\0\0\0" + blob[24:], 4, "<I", 28)
    with pytest.raises(bm.BtfParseError):
        bm.parse_btf(extended)
    assert bm.parse_btf(extended[:24] + b"\0\0\0\0" + extended[28:]).struct("net_device").size == 2544


def test_typedef_cycle_and_bad_ids_are_bounded():
    b = BtfBuilder()
    i = b.int("int", 4)
    first = b.next_id
    b.typedef("loop_a", first + 1)
    b.typedef("loop_b", first)
    b.composite("cyc", 8, [("x", first, 0), ("y", i, 32)])
    b.composite("dangling", 8, [("x", 999, 0)])
    btf = bm.parse_btf(b.blob())
    with pytest.raises(bm.BtfParseError):
        btf.struct("cyc")
    with pytest.raises(bm.BtfParseError):
        btf.struct("dangling")


def test_random_corruption_never_escapes_as_another_exception():
    rng = random.Random(1234)
    base_builder, ids = _base()
    split_builder, _ = _split(base_builder, ids)
    base = bm.parse_btf(base_builder.blob())
    pristine = split_builder.blob()
    for _ in range(1500):
        data = bytearray(pristine)
        for _flip in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            btf = bm.parse_btf(bytes(data), base)
            for lookup, name in (("struct", "wg_peer"), ("struct", "cookie"), ("struct", "bits"),
                                 ("enum", "big"), ("struct_names", None)):
                try:
                    getattr(btf, lookup)(*([name] if name else []))
                except bm.BtfParseError:
                    pass
        except bm.BtfParseError:
            pass


# --------------------------------------------------------------------------- fake kernel memory


LAYOUT = bm.KernelBtfLayout(
    offsets={"btf.data": 0, "btf.data_size": 80, "btf.base_btf": 136, "btf.start_id": 144,
             "btf.start_str_off": 148, "btf.nr_types": 72, "btf.hdr": 48, "btf_header.str_len": 20,
             "btf.name": 152, "btf_module.list": 0, "btf_module.module": 16, "btf_module.btf": 24,
             "module.name": 24},
    sizes={"btf.name": 56, "module.name": 56})


class FakeMemory:
    def __init__(self):
        self.pages = {}

    def write(self, address, data):
        for i, byte in enumerate(data):
            page = self.pages.setdefault((address + i) >> 12, bytearray(4096))
            page[(address + i) & 0xFFF] = byte

    def q(self, address, value):
        self.write(address, struct.pack("<Q", value))

    def i(self, address, value):
        self.write(address, struct.pack("<I", value))

    def read(self, address, length):
        out = bytearray()
        for position in range(address, address + length):
            page = self.pages.get(position >> 12)
            if page is None:
                return None
            out.append(page[position & 0xFFF])
        return bytes(out)

    def read_padded(self, address, length):
        return bytes(b for p in range(address, address + length)
                     for b in [self.pages.get(p >> 12, bytes(4096))[p & 0xFFF]])


def _write_btf(memory, address, data_address, blob, parsed, base_btf, name):
    memory.write(data_address, blob)
    memory.q(address + 0, data_address)
    memory.i(address + 80, len(blob))
    memory.q(address + 136, base_btf)
    memory.i(address + 144, parsed.start_id)
    memory.i(address + 148, parsed.start_str_off)
    memory.i(address + 72, parsed.type_count if parsed.base is None else parsed.own_type_count)
    memory.write(address + 48, blob[:24])
    memory.write(address + 152, name.encode() + b"\0")


def _kernel(module_name="wireguard", btf_name=None, base_pointer=None):
    """Fake image: btf_vmlinux, one btf_module, and a stray unrelated BTF header."""
    base_builder, ids = _base()
    split_builder, _ = _split(base_builder, ids)
    base_blob, split_blob = base_builder.blob(), split_builder.blob()
    base, split = bm.parse_btf(base_blob), None
    split = bm.parse_btf(split_blob, base)
    memory = FakeMemory()
    sym = {"btf_vmlinux": 0x1000, "btf_modules": 0x1100, "__start_BTF": 0x10000,
           "__stop_BTF": 0x10000 + len(base_blob)}
    vmlinux_btf, module_btf, btf_module, module = 0x2000, 0x3000, 0x4000, 0x5000
    memory.q(sym["btf_vmlinux"], vmlinux_btf)
    _write_btf(memory, vmlinux_btf, sym["__start_BTF"], base_blob, base, 0, "vmlinux")
    _write_btf(memory, module_btf, 0x40000, split_blob, split,
               vmlinux_btf if base_pointer is None else base_pointer, btf_name or module_name)
    memory.q(sym["btf_modules"], btf_module)
    memory.q(sym["btf_modules"] + 8, btf_module)
    memory.q(btf_module, sym["btf_modules"])
    memory.q(btf_module + 8, sym["btf_modules"])
    memory.q(btf_module + 16, module)
    memory.q(btf_module + 24, module_btf)
    memory.write(module + 24, module_name.encode() + b"\0")
    memory.write(0x60000, b"\x9f\xeb\x01\x00\x18\x00\x00\x00" + b"\xff" * 16)  # garbage header
    return memory, sym, split_blob


WANTED = ["wg_peer", "cookie"]


def test_symbol_walk_recovers_trusted_layouts():
    memory, sym, blob = _kernel()
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")
    assert got.method == "symbols" and got.trusted and not got.missing
    assert got.members["cookie.cookie_decryption_key"] == 10 and got.members["sizeof(wg_peer)"] == 128
    assert got.blob_sha256 == bm.hashlib.sha256(blob).hexdigest()
    assert any("== __start_BTF" in note for note in got.notes)


def test_walk_and_scan_agree_byte_for_byte():
    memory, sym, _ = _kernel()
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="both")
    assert got.method == "symbols+scan" and got.trusted
    assert any("byte-equals" in note for note in got.notes)


def test_scan_only_result_is_never_trusted():
    memory, sym, _ = _kernel()
    del sym["btf_modules"]
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="auto")
    assert got.method == "scan" and got.scan_blobs == 1 and not got.trusted
    assert got.members["cookie.cookie_decryption_key"] == 10  # still reported as information


def test_scan_with_two_conflicting_blobs_is_discarded():
    memory, sym, blob = _kernel()
    del sym["btf_modules"]
    base = bm.parse_btf(memory.read(sym["__start_BTF"], sym["__stop_BTF"] - sym["__start_BTF"]))
    other = bytearray(blob)
    split = bm.parse_btf(blob, base)
    record = split._types[split.find((bm.KIND_STRUCT,), "cookie")[0] - split.start_id]
    struct.pack_into("<I", other, record.extra + 12 + 8, 72)  # is_valid at bit 72 instead of 64
    memory.write(0x70000, bytes(other))
    with pytest.raises(bm.BtfParseError, match="no BTF"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                           scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="auto")


def test_identical_scan_copies_collapse_to_one_blob():
    memory, sym, blob = _kernel()
    del sym["btf_modules"]
    memory.write(0x70000, blob)
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)])
    assert got.scan_blobs == 1 and not got.trusted  # copies collapse; scan-only is never trusted


def test_partial_coverage_is_not_trusted():
    memory, sym, _ = _kernel()
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED + ["no_such_struct"],
                             method="symbols")
    assert got.missing == ("no_such_struct",) and not got.trusted


def test_module_name_mismatch_and_absent_module():
    memory, sym, _ = _kernel(btf_name="dm_crypt")
    with pytest.raises(bm.BtfParseError, match="btf->name"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")
    memory, sym, _ = _kernel()
    with pytest.raises(bm.BtfParseError, match="not on btf_modules"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "dm_crypt", ["crypt_config"], method="symbols")


def test_base_btf_pointer_must_be_btf_vmlinux_and_scan_fallback_is_untrusted():
    memory, sym, _ = _kernel(base_pointer=0xDEAD000)
    with pytest.raises(bm.BtfParseError, match="base_btf"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="auto")
    assert got.method == "scan" and any("base_btf" in note for note in got.notes)
    assert not got.trusted  # a walk that failed a check disqualifies trust; no scan fallback trust


def test_start_id_mismatch_is_refused():
    memory, sym, _ = _kernel()
    memory.i(0x3000 + 144, 7)
    with pytest.raises(bm.BtfParseError, match="start_id"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")


def test_base_falls_back_to_start_btf_and_vmlinux_module():
    memory, sym, _ = _kernel()
    memory.q(sym["btf_vmlinux"], 0)
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "vmlinux", ["net_device"], method="symbols")
    assert got.members["sizeof(net_device)"] == 2544 and got.trusted
    assert any("btf_vmlinux unset" in note for note in got.notes)


def test_cyclic_module_list_is_bounded():
    memory, sym, _ = _kernel()
    memory.q(0x4000, 0x4000)  # entry points to itself, never back to the head
    refs = bm.walk_btf_modules(memory.read, LAYOUT, sym["btf_modules"])
    assert len(refs) == 1


def test_missing_isf_offsets_are_never_guessed():
    memory, sym, _ = _kernel()
    layout = bm.KernelBtfLayout({k: v for k, v in LAYOUT.offsets.items() if k != "btf.base_btf"})
    with pytest.raises(bm.BtfParseError, match="ISF lacks btf.base_btf"):
        bm.recover_layouts(memory.read, layout, sym, "wireguard", WANTED, method="symbols")


def test_backend_contract():
    assert bm.backend() == "pure-python"


# --------------------------------------------------------------------------- review regressions


def test_planted_blob_behind_junk_signatures_is_never_trusted():
    """R1: a forged blob found only by the scan (after 4096 junk headers) never becomes trusted."""
    memory, sym, blob = _kernel()
    del sym["btf_modules"]
    for i in range(5000):
        memory.write(0x80000 + 32 * i, b"\x9f\xeb\x01\x00\x18\x00\x00\x00" + b"\xff" * 16)
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="scan")
    assert not got.trusted
    stats = {}
    bm.scan_btf_blobs(memory.read_padded, [(0x80000, 0x30000)], WANTED, max_candidates=100, stats=stats)
    assert stats["exhausted"] == 1 and stats["candidates"] == 100


def test_btf_vmlinux_data_not_start_btf_fails_the_walk():
    """R1: btf_vmlinux->data != __start_BTF is a failed check, not a note."""
    memory, sym, _ = _kernel()
    sym["__start_BTF"] += 8
    with pytest.raises(bm.BtfParseError, match="__start_BTF"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")


def test_both_mode_uses_the_scan_only_as_a_cross_check():
    memory, sym, _ = _kernel()
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="both")
    assert got.trusted and got.method == "symbols+scan"


def _anon_dag(depth, fan):
    base_builder, ids = _base()
    m = BtfBuilder(base_builder)
    m.composite("wg_peer", 8, [("", m.next_id + 1, 0)] * fan)
    for level in range(depth):
        nxt = m.next_id + 1
        m.composite("", 8, [("leaf", ids["int"], 0)] if level == depth - 1 else [("", nxt, 0)] * fan)
    return bm.parse_btf(base_builder.blob()), m.blob()


def test_anonymous_member_dag_is_linear_not_exponential():
    """R2: fan**depth = 1000**30 member paths, memoized -> one member, fast."""
    base, blob = _anon_dag(30, 1000)
    split = bm.parse_btf(blob, base)
    start = time.time()
    peer = split.struct("wg_peer")
    assert [m.name for m in peer.members] == ["leaf"] and time.time() - start < 5


def test_member_visit_budget_raises(monkeypatch):
    monkeypatch.setattr(bm, "_BTFM_MEMBER_BUDGET", 50)
    base, blob = _anon_dag(3, 40)
    with pytest.raises(bm.BtfParseError, match="budget"):
        bm.parse_btf(blob, base).struct("wg_peer")


def test_scan_ignores_oversized_candidates_and_caps_bytes_read():
    """R3: headers claiming huge blobs are not read; total candidate bytes are bounded."""
    memory, _sym, blob = _kernel()
    size = bm.MAX_SCAN_BLOB + 4096
    memory.write(0x90000, struct.pack("<HBBIIIII", bm.BTF_MAGIC, 1, 0, 24, 0, 0, 0, size))
    reads = []

    def counting(address, length):
        reads.append(length)
        return memory.read_padded(address, length)
    stats = {}
    bm.scan_btf_blobs(counting, [(0x90000, 0x1000)], WANTED, stats=stats)
    assert max(reads) < size and stats["read"] == 0
    stats = {}
    bm.scan_btf_blobs(memory.read_padded, [(0, 0x80000)], WANTED, stats=stats, max_read=len(blob) - 1)
    assert stats["exhausted"] == 1


def test_duplicate_struct_definitions_with_equal_layout_are_not_a_conflict():
    """R4a: dedup-failed duplicates (different member type ids, same layout) are one struct."""
    b = BtfBuilder()
    i1 = b.int("int", 4)
    i2 = b.typedef("s32", i1)
    b.composite("dup", 8, [("x", i1, 0), ("y", i1, 32)])
    b.composite("dup", 8, [("x", i2, 0), ("y", i2, 32)])
    assert bm.parse_btf(b.blob()).struct("dup").size == 8


def _with_layout_section(blob, extra_kinds=()):
    """Re-encode a 24-byte-header blob with a v7.1+ 32-byte header and a layout section
    (types, layout, strings), optionally sizing extra kinds."""
    _m, _v, _f, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", blob, 0)
    types, strings = blob[24:24 + type_len], blob[24 + str_off:24 + str_off + str_len]
    table = [(0, 0)] * 20
    for kind, sizes in bm._BTFM_EXTRA.items():
        table[kind] = sizes
    table += list(extra_kinds)
    layout = b"".join(struct.pack("<BBH", a, e, 0) for a, e in table)
    header = struct.pack("<HBBIIIIIII", bm.BTF_MAGIC, 1, 0, 32, 0, len(types), len(types) + len(layout),
                         len(strings), len(types), len(layout))
    return header + types + layout + strings


def test_layout_section_header_parses_and_sizes_unknown_kinds():
    """R4b: v7.1+ hdr_len 32 with layout_off/layout_len between types and strings."""
    base_builder, ids = _base()
    plain = base_builder.blob()
    assert bm.parse_btf(_with_layout_section(plain)).struct("net_device").size == 2544
    base_builder.types.append(struct.pack("<III", 0, (20 << 24) | 2, 0) + b"\0" * 8)  # kind 20, 2x4
    upgraded = _with_layout_section(base_builder.blob(), [(0, 4)])
    assert bm.parse_btf(upgraded).struct("net_device").size == 2544
    with pytest.raises(bm.BtfParseError, match="unknown BTF kind"):
        bm.parse_btf(base_builder.blob())
    wrong = bytearray(_with_layout_section(plain))
    type_len = struct.unpack_from("<I", wrong, 12)[0]
    wrong[32 + type_len + 4 * bm.KIND_STRUCT + 1] = 8  # struct members claimed 8 bytes
    with pytest.raises(bm.BtfParseError, match="layout"):
        bm.parse_btf(bytes(wrong))


def test_layout_header_blob_is_found_by_the_scan():
    memory, sym, blob = _kernel()
    base = bm.parse_btf(memory.read(sym["__start_BTF"], sym["__stop_BTF"] - sym["__start_BTF"]))
    memory.write(0x40000, b"\0" * len(blob))
    memory.write(0x70000, _with_layout_section(blob))
    hits = bm.scan_btf_blobs(memory.read_padded, [(0, 0x80000)], WANTED, base=base,
                             base_strings=b"\0" + base._strings)
    assert len(hits) == 1 and hits[0].btf.struct("cookie").size == 48


def test_scan_finds_a_wanted_name_that_is_the_first_split_string():
    """R5: the first string of the split section has no leading NUL in the blob."""
    base_builder, ids = _base()
    m = BtfBuilder(base_builder)
    m.s("firstname")  # make it the very first string of the split section
    m.composite("firstname", 4, [("x", ids["int"], 0)])
    blob = m.blob()
    type_len = struct.unpack_from("<I", blob, 12)[0]
    assert blob[24 + type_len:].startswith(b"firstname\0")  # no NUL before the first name
    memory = FakeMemory()
    memory.write(0x1000, blob)
    hits = bm.scan_btf_blobs(memory.read_padded, [(0, 0x10000)], ["firstname"])
    assert len(hits) == 1


def test_int_encoded_and_unaligned_bitfields_are_not_byte_offsets():
    """R6: no kind_flag, bitfield via the INT encoding (bits/offset) -> excluded from flat_offsets."""
    b = BtfBuilder()
    i = b.int("int", 4)
    narrow = b._add("int", bm.KIND_INT, 0, 4, struct.pack("<I", 3))  # 3-bit int
    shifted = b._add("int", bm.KIND_INT, 0, 4, struct.pack("<I", (4 << 16) | 8))  # 8 bits at +4
    b.composite("enc", 8, [("whole", i, 0), ("three", narrow, 32), ("moved", shifted, 40), ("odd", i, 36)])
    layout = bm.parse_btf(b.blob()).struct("enc")
    by = {m.name: m for m in layout.members}
    assert by["three"].bitfield_size == 3 and by["moved"].bit_offset == 44 and by["moved"].bitfield_size == 8
    flat = bm.flat_offsets([layout])
    assert flat == {"sizeof(enc)": 8, "enc.whole": 0}


def test_unreadable_btf_entry_is_skipped_unless_wanted():
    """R6: one unreadable struct btf on btf_modules does not abort the walk."""
    memory, sym, _ = _kernel()
    head, first = sym["btf_modules"], 0x4000
    extra, extra_module = 0x8000, 0x9000
    memory.q(first, extra)  # head -> first -> extra -> head
    memory.q(extra, head)
    memory.q(extra + 16, extra_module)
    memory.q(extra + 24, 0xBAD0000)  # struct btf pointer to unmapped memory
    memory.write(extra_module + 24, b"other\0")
    skipped = []
    refs = bm.walk_btf_modules(memory.read, LAYOUT, head, wanted="wireguard", skipped=skipped)
    assert [r.name for r in refs] == ["wireguard"] and skipped and skipped[0].startswith("other")
    with pytest.raises(bm.BtfParseError):
        bm.walk_btf_modules(memory.read, LAYOUT, head, wanted="other")
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")
    assert got.trusted and any("skipped unreadable" in note for note in got.notes)


def test_memory_error_in_lookup_becomes_btf_parse_error(monkeypatch):
    base, blob = _anon_dag(2, 2)
    split = bm.parse_btf(blob, base)

    def boom(*_args, **_kwargs):
        raise MemoryError
    monkeypatch.setattr(split, "_struct", boom)
    with pytest.raises(bm.BtfParseError):
        split.struct("wg_peer")


def test_nearest_derived_entry_uses_natural_version_order():
    """R7: 6.8.0-90 is nearest to 6.8.0-71 (not lexicographic 6.8.0-100); stays derived."""
    derived = wg_offsets.lookup_offsets("x86_64", "6.8.0-90-generic")
    assert "derived from x86_64 6.8.0-71-generic " in derived.source
    assert wg_offsets._version_key("6.8.0-100-generic") > wg_offsets._version_key("6.8.0-99-generic")
    assert set(derived.key_path_guessed()) == set(wg_offsets.KEY_PATH_KEYS)


def test_table_can_be_hidden_for_tests(monkeypatch):
    monkeypatch.setenv(wg_offsets.HIDE_TABLE_ENV, "1")
    assert "derived" in wg_offsets.lookup_offsets("x86_64", "6.8.0-136-generic").source
    assert dm_offsets.lookup_offsets("x86_64", "6.8.0-136-generic") is None


def test_btf_vmlinux_null_with_a_module_fails_the_walk():
    """Review 2 #4: without btf_vmlinux the module's base_btf cannot be checked -> no trust."""
    memory, sym, _ = _kernel()
    memory.q(sym["btf_vmlinux"], 0)
    with pytest.raises(bm.BtfParseError, match="btf_vmlinux is NULL"):
        bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols")
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="both")
    assert got.method == "scan" and not got.trusted


def test_both_with_a_failed_walk_is_untrusted():
    """Review 2 #6."""
    memory, sym, _ = _kernel()
    memory.i(0x3000 + 144, 7)  # start_id mismatch
    got = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED,
                             scan_read=memory.read_padded, scan_ranges=[(0, 0x80000)], method="both")
    assert got.method == "scan" and not got.trusted and any("start_id" in n for n in got.notes)


def test_own_only_enum_ignores_a_same_named_base_enum():
    """Review 2 #6: an ``enum flags`` in the base must not stand in for the module's."""
    base_builder, ids = _base()
    base_builder.enum("flags", [("VMLINUX_FLAG", 3)])
    m = BtfBuilder(base_builder)
    m.composite("crypt_config", 8, [("x", ids["int"], 0)])
    split = bm.parse_btf(m.blob(), bm.parse_btf(base_builder.blob()))
    assert split.enum("flags") == {"VMLINUX_FLAG": 3}
    assert split.enums("flags", own_only=True) == []
    with pytest.raises(bm.BtfParseError):
        split.enum("flags", own_only=True)


def test_base_cache_parses_vmlinux_once():
    memory, sym, _ = _kernel()
    cache = {}
    first = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols", base_cache=cache)
    memory.q(sym["btf_vmlinux"], 0x7777000)  # would now fail if the base were re-read
    second = bm.recover_layouts(memory.read, LAYOUT, sym, "wireguard", WANTED, method="symbols", base_cache=cache)
    assert first.members == second.members and "base" in cache


# Kernel-module corpus: <dir>/<uname>/{wireguard.ko, vmlinux.BTF.raw} (ELF .BTF + raw vmlinux BTF).
KO_CORPUS = Path(os.environ.get("MEMDIVER_WG_KO_CORPUS", "") or "/nonexistent")


def _elf_section(path, wanted):
    data = path.read_bytes()
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def header(index):
        return struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
    names = header(shstrndx)[4]
    for index in range(shnum):
        sh = header(index)
        if data[names + sh[0]:data.index(b"\0", names + sh[0])].decode() == wanted:
            return data[sh[4]:sh[4] + sh[5]]
    return None


def test_parser_equals_table_on_every_ko_corpus_kernel():
    """R4: every BTF-bearing wireguard.ko of the corpus parses to its table entry exactly."""
    if not KO_CORPUS.is_dir():
        pytest.skip("MEMDIVER_WG_KO_CORPUS not present")
    compared, failures = 0, []
    for kdir in sorted(KO_CORPUS.iterdir()):
        raw = _elf_section(kdir / "wireguard.ko", ".BTF") if (kdir / "wireguard.ko").is_file() else None
        entry = wg_offsets.WG_OFFSETS.get(("x86_64", kdir.name.split("~")[0]))
        if raw is None or entry is None:
            continue
        split = bm.parse_btf(raw, bm.parse_btf((kdir / "vmlinux.BTF.raw").read_bytes()))
        flat = bm.flat_offsets(split.struct(s) for s in wg_offsets.SIDECAR_STRUCTS)
        if any(flat.get(k) != entry.members[k] for k in wg_offsets.REQUIRED_KEYS):
            failures.append(kdir.name)
        compared += 1
    assert compared >= 60 and failures == []


# --------------------------------------------------------------------------- real captures (gated)

# Absolute path of the acquired-secrets capture directory (holds <stem>.lime/.isf.json/.secrets.json).
CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
X86_STEMS = ("ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic",
             "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic")


def _run_layouts(tmp_path, vol, stem, module):
    lime, isf = CAPTURE_DIR / (stem + ".lime"), CAPTURE_DIR / (stem + ".isf.json")
    symbols = tmp_path / "sym" / "linux"
    if not symbols.is_dir():
        symbols.mkdir(parents=True)
        (symbols / (stem + ".json")).symlink_to(isf)
        (tmp_path / "cache").mkdir()
    command = [vol, "-q", "-r", "json", "-s", str(tmp_path / "sym"), "-p", str(REPO / "vol3plugins"),
               "-f", str(lime), "--cache-path", str(tmp_path / "cache"), "-o", str(tmp_path),
               "linux.btf_layouts", "--module", module, "--method", "both", "--export"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path), timeout=1200)
    assert result.returncode == 0, result.stderr[-2000:]
    rows = json.loads(result.stdout)
    assert rows and all(row["Method"] == "symbols+scan" for row in rows)
    return json.loads((tmp_path / ("btf_offsets.%s.json" % module)).read_text())["btf_offsets"]


@pytest.mark.parametrize("stem", X86_STEMS)
def test_real_x86_capture_layouts_equal_table_and_pahole(tmp_path, stem):
    vol = shutil.which("vol") or str(Path(sys.executable).with_name("vol"))
    sidecar = CAPTURE_DIR / (stem + ".secrets.json")
    if not ((CAPTURE_DIR / (stem + ".lime")).is_file() and sidecar.is_file() and Path(vol).is_file()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture or stock `vol` not present")
    document = dict(_run_layouts(tmp_path, vol, stem, "wireguard"))
    document.update(_run_layouts(tmp_path, vol, stem, "dm_crypt"))
    assert set(document) == set(wg_offsets.SIDECAR_STRUCTS) | {"crypt_config"}
    loaded = wg_offsets.load_offsets_json(json.dumps(document), "memory",
                                          wg_offsets.lookup_offsets("x86_64", "6.8.0-136-generic"))
    assert loaded.members == wg_offsets.WG_OFFSETS[("x86_64", "6.8.0-136-generic")].members
    assert not loaded.missing_sidecar_structs()
    table = dm_offsets.DM_CRYPT_OFFSETS[("x86_64", "6.8.0-136-generic")].crypt_config
    assert {k: document["crypt_config"]["members"][k]["offset"] for k in table} == table
    pahole = json.loads(sidecar.read_text())["btf_offsets"]
    compared = 0
    for name, entry in pahole.items():
        if name not in document:
            continue
        assert document[name]["size"] == entry["size"], name
        for member, value in entry["members"].items():
            got = document[name]["members"][member]
            assert (got["offset"], got["size"]) == (value["offset"], value["size"]), (name, member)
            compared += 1
    assert compared >= 120
