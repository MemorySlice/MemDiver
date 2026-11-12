"""Struct layouts of kernel *modules*, recovered from the kernel's own BTF held in a memory image.

A vmlinux ISF never describes the structs of a loadable module (``wg_peer``, ``crypt_config``
...).  A BTF-enabled kernel (``CONFIG_DEBUG_INFO_BTF_MODULES``, v5.11+) keeps them anyway: on
``MODULE_STATE_COMING`` ``btf_module_notify()`` (``kernel/bpf/btf.c``) parses the module's
``.BTF`` section into a ``struct btf`` whose ``data`` is a ``kvmalloc``/``kvmemdup`` COPY and
links it on the static list ``btf_modules`` (``struct btf_module {list; module; btf; ...}``).
``mod->btf_data`` itself is NULLed in ``do_init_module()`` (``.BTF`` is not ``SHF_ALLOC``), so
that copy is the one that survives.  The vmlinux BTF is ``btf_vmlinux`` (``data`` =
``__start_BTF``, ``data_size`` = ``__stop_BTF - __start_BTF``).  Module BTF is SPLIT BTF on top
of it: type ids start at ``btf->start_id`` = the base's type count (VOID included) and string
offsets at ``btf->start_str_off`` = the base's ``hdr.str_len``.  From v6.12 a module may carry a
*distilled* base (``.BTF.base``); ``btf_parse_module()`` then relocates the copy IN PLACE onto
vmlinux (``btf_relocate()`` rewrites type ids and string offsets, ``btf_set_base_btf()``), so
the resident blob is again ordinary split BTF on vmlinux -- the same parser applies.

Two ways to the module blob (see ``recover_layouts``):

* ``symbols`` -- walk ``btf_modules`` with ``struct btf`` / ``struct btf_module`` / ``struct
  module`` offsets the CALLER takes from the vmlinux ISF (``KernelBtfLayout``; this module never
  guesses one), cross-checked against ``btf_vmlinux`` (``base_btf`` pointer, ``start_id``,
  ``start_str_off``, the parsed base's type count and string length, ``btf->hdr``).
* ``scan`` -- a signature scan (magic 0xEB9F, version 1, flags 0, hdr_len 24, contiguous
  sections, string section ending in NUL) for a blob whose string section names the wanted
  structs and that parses as split BTF on the vmlinux base.  Used when the walk fails; also run
  next to it as a cross-check.

Parsing is bounded: every count is checked against the bytes present, type chains are cut at
``_BTFM_MAX_DEPTH``, and the only exception that escapes a parse is ``BtfParseError``.

Self-contained (``secrets/__init__.py``): stdlib only, paste-safe, private names ``_btfm_``.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "BtfParseError",
    "BtfMember",
    "BtfStruct",
    "BtfData",
    "KernelBtfLayout",
    "KernelBtfRef",
    "BtfScanHit",
    "RecoveredLayouts",
    "LAYOUT_KEYS",
    "parse_btf",
    "flat_offsets",
    "btf_offsets_document",
    "read_kernel_btf",
    "walk_btf_modules",
    "load_vmlinux_btf",
    "scan_btf_blobs",
    "recover_layouts",
    "backend",
]

BTF_MAGIC = 0xEB9F
BTF_VERSION = 1
BTF_HEADER_LEN = 24
BTF_LAYOUT_HEADER_LEN = 32  # v7.1+: + layout_off, layout_len
MAX_BTF_SIZE = 64 << 20  # vmlinux BTF is ~6 MiB on distribution kernels
MAX_MODULES = 4096
MAX_SCAN_CANDIDATES = 4096

(KIND_UNKN, KIND_INT, KIND_PTR, KIND_ARRAY, KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_FWD,
 KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_FUNC, KIND_FUNC_PROTO, KIND_VAR,
 KIND_DATASEC, KIND_FLOAT, KIND_DECL_TAG, KIND_TYPE_TAG, KIND_ENUM64) = range(20)

_BTFM_MAX_DEPTH = 32  # typedef/const/array chains and anonymous-member nesting
_BTFM_MAX_NAME = 512  # KSYM_NAME_LEN
_BTFM_MEMBER_BUDGET = 1 << 20  # member visits per struct() lookup
_BTFM_MODIFIERS = frozenset({KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG})
_BTFM_SIZED = frozenset({KIND_INT, KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_ENUM64, KIND_FLOAT,
                         KIND_DATASEC})
# Bytes following the 12-byte ``struct btf_type``: fixed part and per-``vlen`` part.
_BTFM_EXTRA = {
    KIND_INT: (4, 0), KIND_ARRAY: (12, 0), KIND_STRUCT: (0, 12), KIND_UNION: (0, 12),
    KIND_ENUM: (0, 8), KIND_FUNC_PROTO: (0, 8), KIND_VAR: (4, 0), KIND_DATASEC: (0, 12),
    KIND_DECL_TAG: (4, 0), KIND_ENUM64: (0, 12),
}
_BTFM_KIND_WORD = {KIND_STRUCT: "struct", KIND_UNION: "union", KIND_ENUM: "enum",
                   KIND_ENUM64: "enum", KIND_FWD: "struct"}


def backend() -> str:
    """Always pure Python (no accelerator); present for the ``secrets/`` module contract."""
    return "pure-python"


class BtfParseError(ValueError):
    """The bytes are not (usable) BTF, or the kernel structures pointing to it are inconsistent."""


@dataclass(frozen=True)
class BtfMember:
    """One member as C code reaches it (anonymous struct/union members are flattened in)."""

    name: str
    offset: int  # bytes from the start of the outermost struct (bit offset // 8)
    bit_offset: int  # bits from the start of the outermost struct
    bitfield_size: int  # 0 = not a bitfield
    size: Optional[int]  # bytes (bitfield: storage is bitfield_size bits); None = unknown
    type_id: int
    type_name: str


@dataclass(frozen=True)
class BtfStruct:
    name: str
    kind: str  # "struct" | "union"
    size: int
    type_id: int
    members: Tuple[BtfMember, ...]

    def member(self, name: str) -> Optional[BtfMember]:
        return next((m for m in self.members if m.name == name), None)


@dataclass
class _BtfmType:
    kind: int
    name_off: int
    vlen: int
    kind_flag: bool
    size_or_type: int
    extra: int  # absolute offset of the bytes after the 12-byte btf_type
    blob: bytes  # the BTF blob holding this record (a base record lives in the base blob)


class BtfData:
    """A parsed BTF blob (base or split).  Type records are decoded lazily on demand."""

    def __init__(self, data: bytes, base: Optional["BtfData"], pointer_size: int) -> None:
        self.data = bytes(data)
        self.base = base
        self.pointer_size = pointer_size
        self.endian = _btfm_endian(self.data)
        if base is not None and base.endian != self.endian:
            raise BtfParseError("split BTF endianness differs from its base")
        (self.hdr_len, self.type_off, self.type_len, self.str_off, self.str_len, self.layout_off,
         self.layout_len) = _btfm_check_header(self.data, self.endian, base is not None)
        self.start_id = base.type_count if base else 1  # id 0 is VOID in the base
        self.start_str_off = base.total_str_len if base else 0
        self._strings = self.data[self.hdr_len + self.str_off:self.hdr_len + self.str_off + self.str_len]
        if base is None and self._strings[:1] != b"\0":
            raise BtfParseError("base string section must start with NUL")
        layout = _btfm_layout_table(self.data, self.hdr_len + self.layout_off, self.layout_len)
        self._types = _btfm_index_types(self.data, self.endian, self.hdr_len + self.type_off,
                                        self.type_len, layout)
        self._names: Optional[Dict[Tuple[int, str], List[int]]] = None
        self._flat_memo: Dict[Tuple[int, int], Tuple[BtfMember, ...]] = {}

    # ---------------------------------------------------------------- counts

    @property
    def type_count(self) -> int:
        """Types of this blob and its base, VOID included (= the kernel's ``btf_nr_types``)."""
        return self.start_id + len(self._types)

    @property
    def total_str_len(self) -> int:
        return self.start_str_off + self.str_len

    @property
    def own_type_count(self) -> int:
        return len(self._types)

    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    # ---------------------------------------------------------------- lookups

    def string(self, offset: int) -> str:
        if offset < self.start_str_off:
            if self.base is None:
                raise BtfParseError("string offset %d below the section" % offset)
            return self.base.string(offset)
        local = offset - self.start_str_off
        if local >= len(self._strings):
            raise BtfParseError("string offset %d out of range" % offset)
        end = self._strings.find(b"\0", local, local + _BTFM_MAX_NAME)
        if end < 0:
            raise BtfParseError("unterminated string at %d" % offset)
        return self._strings[local:end].decode("utf-8", "replace")

    def _type(self, type_id: int) -> Optional[_BtfmType]:
        if type_id < self.start_id:
            return self.base._type(type_id) if self.base is not None and type_id > 0 else None
        index = type_id - self.start_id
        if index >= len(self._types):
            raise BtfParseError("type id %d out of range" % type_id)
        return self._types[index]

    def _name_index(self) -> Dict[Tuple[int, str], List[int]]:
        if self._names is None:
            names: Dict[Tuple[int, str], List[int]] = {}
            for index, record in enumerate(self._types):
                if record.name_off and record.kind in (KIND_STRUCT, KIND_UNION, KIND_ENUM,
                                                       KIND_ENUM64, KIND_TYPEDEF):
                    names.setdefault((record.kind, self.string(record.name_off)), []).append(
                        self.start_id + index)
            self._names = names
        return self._names

    def find(self, kinds: Sequence[int], name: str, own_only: bool = False) -> List[int]:
        """Type ids named ``name`` of one of ``kinds``: this blob first, then (unless
        ``own_only``) its base."""
        found = [i for kind in kinds for i in self._name_index().get((kind, name), ())]
        if not found and self.base is not None and not own_only:
            found = self.base.find(kinds, name)
        return found

    def struct_names(self) -> List[str]:
        return _btfm_guard(self._struct_names)

    def _struct_names(self) -> List[str]:
        return sorted({name for (kind, name) in self._name_index() if kind in (KIND_STRUCT, KIND_UNION)})

    # ---------------------------------------------------------------- layouts

    def struct(self, name: str) -> BtfStruct:
        """Layout of ``struct name`` (or ``union name``); ``BtfParseError`` if absent/ambiguous."""
        return _btfm_guard(self._struct, name)

    def _struct(self, name: str) -> BtfStruct:
        ids = self.find((KIND_STRUCT,), name) or self.find((KIND_UNION,), name)
        if not ids:
            raise BtfParseError("no struct %s in BTF" % name)
        layouts = [self._struct_by_id(i) for i in ids]
        # Compare layout only: dedup-failed duplicates differ in member type ids, not in layout.
        shapes = {(s.size, tuple((m.name, m.bit_offset, m.bitfield_size, m.size) for m in s.members))
                  for s in layouts}
        if len(shapes) > 1:
            raise BtfParseError("struct %s has %d conflicting definitions" % (name, len(shapes)))
        return min(layouts, key=lambda s: s.type_id)

    def _struct_by_id(self, type_id: int) -> BtfStruct:
        record = self._type(type_id)
        if record is None or record.kind not in (KIND_STRUCT, KIND_UNION):
            raise BtfParseError("type %d is not a struct/union" % type_id)
        members = self._flat_members(record, [_BTFM_MEMBER_BUDGET], set(), 0)
        return BtfStruct(self.string(record.name_off), "struct" if record.kind == KIND_STRUCT else "union",
                         record.size_or_type, type_id, members)

    def _flat_members(self, record: _BtfmType, budget: List[int], active: set, depth: int
                      ) -> Tuple[BtfMember, ...]:
        """Members of ``record`` (anonymous struct/union members flattened in), offsets relative
        to ``record``.  Memoized per record and charged against ``budget`` (member visits), so a
        hostile DAG of anonymous members costs linear, not exponential, work."""
        key = (id(record.blob), record.extra)
        if key in self._flat_memo:
            return self._flat_memo[key]
        if key in active or depth > _BTFM_MAX_DEPTH:
            raise BtfParseError("anonymous member nesting cyclic or too deep")
        active.add(key)
        out: List[BtfMember] = []
        seen: set = set()
        for name_off, type_id, raw in self._members_of(record):
            _btfm_charge(budget)
            bits, width = (raw & 0xFFFFFF, raw >> 24) if record.kind_flag else (raw, 0)
            name = self.string(name_off) if name_off else ""
            if not name:
                inner = self._skip_modifiers(type_id)
                if inner is not None and inner.kind in (KIND_STRUCT, KIND_UNION):
                    for member in self._flat_members(inner, budget, active, depth + 1):
                        _btfm_charge(budget)
                        if member.name not in seen:
                            seen.add(member.name)
                            out.append(_btfm_shift(member, bits))
                continue
            if name in seen:
                continue
            seen.add(name)
            if not width:
                width, bits = self._int_bitfield(type_id, bits)
            size = (width + 7) // 8 if width else self.type_size(type_id)
            out.append(BtfMember(name, bits // 8, bits, width, size, type_id, self.type_name(type_id)))
        active.discard(key)
        self._flat_memo[key] = tuple(out)
        return self._flat_memo[key]

    def _int_bitfield(self, type_id: int, bits: int) -> Tuple[int, int]:
        """``(width, bit_offset)`` of a member whose INT encoding makes it a bitfield (no kind_flag)."""
        record = self._skip_modifiers(type_id)
        if record is None or record.kind != KIND_INT:
            return 0, bits
        encoding = struct.unpack_from(self.endian + "I", record.blob, record.extra)[0]
        nr_bits, int_offset = encoding & 0xFF, (encoding >> 16) & 0xFF
        if int_offset or nr_bits != record.size_or_type * 8:
            return nr_bits, bits + int_offset
        return 0, bits

    def _members_of(self, record: _BtfmType) -> Iterable[Tuple[int, int, int]]:
        fmt = self.endian + "III"
        for i in range(record.vlen):
            yield struct.unpack_from(fmt, record.blob, record.extra + 12 * i)

    def _skip_modifiers(self, type_id: int) -> Optional[_BtfmType]:
        record = self._type(type_id)
        for _ in range(_BTFM_MAX_DEPTH):
            if record is None or record.kind not in _BTFM_MODIFIERS:
                return record
            record = self._type(record.size_or_type)
        raise BtfParseError("type chain too long at %d" % type_id)

    def type_size(self, type_id: int) -> Optional[int]:
        """``sizeof`` the type (typedef/const/... resolved); None for void/fwd/func."""
        multiplier = 1
        for _ in range(_BTFM_MAX_DEPTH):
            record = self._type(type_id)
            if record is None:
                return None
            if record.kind in _BTFM_SIZED:
                return multiplier * record.size_or_type
            if record.kind == KIND_PTR:
                return multiplier * self.pointer_size
            if record.kind == KIND_ARRAY:
                elem, _index, nelems = struct.unpack_from(self.endian + "III", record.blob, record.extra)
                multiplier *= nelems
                type_id = elem
            elif record.kind in _BTFM_MODIFIERS:
                type_id = record.size_or_type
            else:
                return None
        raise BtfParseError("type chain too long at %d" % type_id)

    def type_name(self, type_id: int, depth: int = 0) -> str:
        """A readable C-ish name: ``struct net_device``, ``u8[32]``, ``struct wg_peer *``."""
        if depth > _BTFM_MAX_DEPTH:
            raise BtfParseError("type chain too long at %d" % type_id)
        record = self._type(type_id)
        if record is None:
            return "void"
        name = self.string(record.name_off) if record.name_off else ""
        if record.kind in _BTFM_KIND_WORD:
            return "%s %s" % (_BTFM_KIND_WORD[record.kind], name or "{anon}")
        if record.kind in (KIND_INT, KIND_FLOAT, KIND_TYPEDEF):
            return name
        if record.kind == KIND_PTR:
            return self.type_name(record.size_or_type, depth + 1) + " *"
        if record.kind == KIND_ARRAY:
            elem, _index, nelems = struct.unpack_from(self.endian + "III", record.blob, record.extra)
            return "%s[%d]" % (self.type_name(elem, depth + 1), nelems)
        if record.kind in (KIND_CONST, KIND_VOLATILE, KIND_RESTRICT):
            word = {KIND_CONST: "const", KIND_VOLATILE: "volatile", KIND_RESTRICT: "restrict"}[record.kind]
            return "%s %s" % (word, self.type_name(record.size_or_type, depth + 1))
        if record.kind == KIND_TYPE_TAG:
            return self.type_name(record.size_or_type, depth + 1)
        return "kind%d %s" % (record.kind, name)

    def enums(self, name: str, own_only: bool = False) -> List[Dict[str, int]]:
        """Every ``enum name`` (a generic name such as ``flags`` may name several enums)."""
        return _btfm_guard(self._enums, name, own_only)

    def _enums(self, name: str, own_only: bool) -> List[Dict[str, int]]:
        return [self._enum_values(self._type(i)) for i in self.find((KIND_ENUM, KIND_ENUM64), name, own_only)]

    def enum(self, name: str, own_only: bool = False) -> Dict[str, int]:
        """Enumerator values of ``enum name`` (ENUM or ENUM64).

        ``own_only`` skips the base: a generic name such as ``flags`` must come from the
        module itself, never from an unrelated vmlinux enum of the same name.
        """
        return _btfm_guard(self._enum, name, own_only)

    def _enum(self, name: str, own_only: bool = False) -> Dict[str, int]:
        ids = self.find((KIND_ENUM, KIND_ENUM64), name, own_only)
        if not ids:
            raise BtfParseError("no enum %s in BTF" % name)
        return self._enum_values(self._type(ids[0]))

    def _enum_values(self, record: _BtfmType) -> Dict[str, int]:
        values: Dict[str, int] = {}
        signed = record.kind_flag
        for i in range(record.vlen):
            if record.kind == KIND_ENUM:
                name_off, value = struct.unpack_from(self.endian + ("Ii" if signed else "II"),
                                                     record.blob, record.extra + 8 * i)
            else:
                name_off, low, high = struct.unpack_from(self.endian + "III", record.blob,
                                                         record.extra + 12 * i)
                value = (high << 32) | low
                if signed and value >= 1 << 63:
                    value -= 1 << 64
            values[self.string(name_off)] = value
        return values


# --------------------------------------------------------------------------- blob parsing


def _btfm_endian(data: bytes) -> str:
    if len(data) < BTF_HEADER_LEN:
        raise BtfParseError("BTF shorter than its header")
    if data[:2] == b"\x9f\xeb":
        return "<"
    if data[:2] == b"\xeb\x9f":
        return ">"
    raise BtfParseError("bad BTF magic %r" % data[:2])


def _btfm_check_header(data: bytes, endian: str, split: bool) -> Tuple[int, int, int, int, int, int, int]:
    """The kernel's ``btf_parse_hdr`` / ``btf_check_sec_info`` / ``btf_parse_str_sec`` rules.

    Returns ``(hdr_len, type_off, type_len, str_off, str_len, layout_off, layout_len)``.  A 32-byte
    header (v7.1+ ``include/uapi/linux/btf.h``) adds ``layout_off`` / ``layout_len``: a table of
    ``struct btf_layout {u8 info_sz; u8 elem_sz; u16 flags;}`` per kind; the three sections must
    then tile the data in any order, and the string section need not be last.
    """
    _magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        endian + "HBBIIIII", data, 0)
    if version != BTF_VERSION or flags:
        raise BtfParseError("unsupported BTF version %d / flags %d" % (version, flags))
    if hdr_len < BTF_HEADER_LEN or hdr_len > len(data) or len(data) > MAX_BTF_SIZE:
        raise BtfParseError("bad BTF hdr_len %d for %d bytes" % (hdr_len, len(data)))
    layout_off = layout_len = 0
    known_len = BTF_HEADER_LEN
    if hdr_len >= BTF_LAYOUT_HEADER_LEN:
        layout_off, layout_len = struct.unpack_from(endian + "II", data, BTF_HEADER_LEN)
        known_len = BTF_LAYOUT_HEADER_LEN
    if any(data[known_len:hdr_len]):
        raise BtfParseError("unsupported (non-zero) BTF header extension")
    total = len(data) - hdr_len
    sections = [(type_off, type_len), (str_off, str_len)] + ([(layout_off, layout_len)] if layout_len else [])
    position = 0
    for offset, length in sorted(sections):
        if offset != position or length > total - position:
            raise BtfParseError("BTF sections overlap, leave a gap or overrun the blob")
        position += length
    if position != total:
        raise BtfParseError("BTF has data outside its sections")
    if not layout_len and str_off + str_len != total:
        raise BtfParseError("BTF string section is not at the end")
    if type_off % 4 or type_len % 4 or layout_off % 4 or layout_len % 4:
        raise BtfParseError("BTF type/layout section misaligned")
    if not split and not total:
        raise BtfParseError("BTF has no data")
    if str_len and data[hdr_len + str_off + str_len - 1] != 0:
        raise BtfParseError("BTF string section does not end with NUL")
    if not str_len and not split:
        raise BtfParseError("BTF has no string section")
    return hdr_len, type_off, type_len, str_off, str_len, layout_off, layout_len


def _btfm_layout_table(data: bytes, start: int, length: int) -> List[Tuple[int, int]]:
    """``[(info_sz, elem_sz)]`` indexed by kind, from a BTF layout section."""
    return [(data[start + i], data[start + i + 1]) for i in range(0, length, 4)]


def _btfm_record_extra(kind: int, layout: Sequence[Tuple[int, int]]) -> Tuple[int, int]:
    """``(fixed, per-vlen)`` bytes after the 12-byte ``btf_type`` of ``kind``."""
    if KIND_UNKN < kind <= KIND_ENUM64:
        sizes = _BTFM_EXTRA.get(kind, (0, 0))
        if kind < len(layout) and layout[kind] != sizes:
            raise BtfParseError("BTF layout section disagrees for kind %d" % kind)
        return sizes
    if KIND_UNKN < kind < len(layout):  # a newer kind: sized by the blob's own layout section
        return layout[kind]
    raise BtfParseError("unknown BTF kind %d" % kind)


def _btfm_index_types(data: bytes, endian: str, start: int, length: int,
                      layout: Sequence[Tuple[int, int]] = ()) -> List[_BtfmType]:
    types: List[_BtfmType] = []
    position, end = start, start + length
    fmt = endian + "III"
    while position < end:
        if end - position < 12:
            raise BtfParseError("truncated btf_type at %d" % position)
        name_off, info, size_or_type = struct.unpack_from(fmt, data, position)
        kind, vlen = (info >> 24) & 0x7F, info & 0xFFFFFF  # v7.1+ widths; older kernels keep the
        fixed, per_member = _btfm_record_extra(kind, layout)  # extra bits zero
        extra = position + 12
        position = extra + fixed + per_member * vlen
        if position > end:
            raise BtfParseError("btf_type at %d overruns the type section" % (extra - 12))
        types.append(_BtfmType(kind, name_off, vlen, bool(info >> 31), size_or_type, extra, data))
    return types


def parse_btf(data: bytes, base: Optional[BtfData] = None, pointer_size: int = 8) -> BtfData:
    """Parse a BTF blob; ``base`` makes it split BTF.  Raises only ``BtfParseError``."""
    try:
        return BtfData(data, base, pointer_size)
    except BtfParseError:
        raise
    except (struct.error, IndexError, TypeError, ValueError, OverflowError, MemoryError) as error:
        raise BtfParseError("malformed BTF: %s" % error) from None


def _btfm_guard(function: Callable, *args):
    """Run a lazy lookup on parsed BTF; any decoding failure becomes ``BtfParseError``."""
    try:
        return function(*args)
    except BtfParseError:
        raise
    except (struct.error, IndexError, TypeError, ValueError, OverflowError, RecursionError,
            MemoryError) as error:
        raise BtfParseError("malformed BTF: %s" % error) from None


def _btfm_charge(budget: List[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0:
        raise BtfParseError("member visit budget exhausted (hostile anonymous-member graph?)")


def _btfm_shift(member: BtfMember, bits: int) -> BtfMember:
    bit_offset = member.bit_offset + bits
    return BtfMember(member.name, bit_offset // 8, bit_offset, member.bitfield_size, member.size,
                     member.type_id, member.type_name)


# --------------------------------------------------------------------------- output formats


def flat_offsets(structs: Iterable[BtfStruct]) -> Dict[str, int]:
    """``{"type.member": offset, "sizeof(type)": size}`` -- the key format of the offset tables.

    Bitfield (kind_flag or INT-encoded) and non-byte-aligned members are left out: a byte
    offset does not describe them.
    """
    flat: Dict[str, int] = {}
    for layout in structs:
        flat["sizeof(%s)" % layout.name] = layout.size
        for member in layout.members:
            if not member.bitfield_size and not member.bit_offset % 8:
                flat["%s.%s" % (layout.name, member.name)] = member.offset
    return flat


def btf_offsets_document(structs: Iterable[BtfStruct], source: str = "btf-memory") -> Dict[str, Dict]:
    """The capture sidecar's ``btf_offsets`` shape: ``{struct: {size, source, members: {m: {offset, size}}}}``.

    Accepted as-is by the ``--offsets`` loaders of ``linux.wireguard`` and ``linux.dmcrypt``.
    """
    document: Dict[str, Dict] = {}
    for layout in structs:
        members = {}
        for m in layout.members:
            entry = {"offset": m.offset, "size": m.size, "decl": m.type_name}
            if m.bitfield_size:
                entry.update(bit_offset=m.bit_offset, bitfield_size=m.bitfield_size)
            members[m.name] = entry
        document[layout.name] = {"size": layout.size, "source": source, "members": members}
    return document


# --------------------------------------------------------------------------- kernel structures


# ``KernelBtfLayout.offsets`` keys, all taken from the vmlinux ISF by the caller.
LAYOUT_KEYS = (
    "btf.data", "btf.data_size", "btf.base_btf", "btf.start_id", "btf.start_str_off",
    "btf.nr_types", "btf.hdr", "btf_header.str_len", "btf_module.list", "btf_module.module",
    "btf_module.btf", "module.name",
)


@dataclass(frozen=True)
class KernelBtfLayout:
    """ISF offsets of ``struct btf`` / ``btf_module`` / ``module`` plus the char-array sizes.

    ``offsets`` must hold every ``LAYOUT_KEYS`` entry; ``btf.name`` (offset) and ``sizes``
    (``"btf.name"``, ``"module.name"``) are optional.
    """

    offsets: Dict[str, int]
    sizes: Dict[str, int] = field(default_factory=dict)
    pointer_size: int = 8
    byteorder: str = "little"

    def missing(self) -> Tuple[str, ...]:
        return tuple(k for k in LAYOUT_KEYS if k not in self.offsets)


@dataclass(frozen=True)
class KernelBtfRef:
    """One ``struct btf`` as read from memory."""

    name: str  # module name (``module->name``; ``btf->name`` when no module)
    btf_address: int
    data_address: int
    data_size: int
    base_btf: int
    start_id: int
    start_str_off: int
    nr_types: int
    str_len: int  # btf->hdr.str_len
    btf_name: str = ""  # btf->name (5.11+), cross-checked against ``name``


Reader = Callable[[int, int], Optional[bytes]]


def _btfm_int(read: Reader, address: int, size: int, layout: KernelBtfLayout) -> int:
    data = read(address, size) if address else None
    if data is None or len(data) != size:
        raise BtfParseError("unreadable kernel memory at 0x%x" % address)
    return int.from_bytes(data, layout.byteorder)


def _btfm_cstring(read: Reader, address: int, size: int) -> str:
    data = read(address, size) if address else None
    if not data:
        return ""
    raw = data.split(b"\0", 1)[0]
    return raw.decode("ascii", "replace") if all(0x20 <= b < 0x7F for b in raw) else ""


def read_kernel_btf(read: Reader, layout: KernelBtfLayout, btf_address: int, name: str = "") -> KernelBtfRef:
    """Fields of the ``struct btf`` at ``btf_address`` (offsets from ``layout``)."""
    if layout.missing():
        raise BtfParseError("ISF lacks %s" % ", ".join(layout.missing()))
    off, ptr = layout.offsets, layout.pointer_size

    def u32(key: str) -> int:
        return _btfm_int(read, btf_address + off[key], 4, layout)

    btf_name = ""
    if "btf.name" in off:
        btf_name = _btfm_cstring(read, btf_address + off["btf.name"], layout.sizes.get("btf.name", 56))
    return KernelBtfRef(
        name=name or btf_name, btf_address=btf_address,
        data_address=_btfm_int(read, btf_address + off["btf.data"], ptr, layout),
        data_size=u32("btf.data_size"),
        base_btf=_btfm_int(read, btf_address + off["btf.base_btf"], ptr, layout),
        start_id=u32("btf.start_id"), start_str_off=u32("btf.start_str_off"),
        nr_types=u32("btf.nr_types"),
        str_len=_btfm_int(read, btf_address + off["btf.hdr"] + off["btf_header.str_len"], 4, layout),
        btf_name=btf_name)


def walk_btf_modules(read: Reader, layout: KernelBtfLayout, btf_modules_address: int,
                     limit: int = MAX_MODULES, wanted: Optional[str] = None,
                     skipped: Optional[List[str]] = None) -> List[KernelBtfRef]:
    """Every ``btf_module`` on the ``btf_modules`` list (bounded, cycle-safe).

    An entry whose ``struct btf`` is unreadable is skipped (named in ``skipped``) unless it is
    the ``wanted`` module; an unreadable list link ends the walk with ``BtfParseError``.
    """
    off, ptr = layout.offsets, layout.pointer_size
    refs: List[KernelBtfRef] = []
    seen = {btf_modules_address}
    entry = _btfm_int(read, btf_modules_address, ptr, layout)
    while entry not in seen and len(refs) + len(skipped or ()) < limit:
        seen.add(entry)
        node = entry - off["btf_module.list"]
        name = ""
        try:
            module = _btfm_int(read, node + off["btf_module.module"], ptr, layout)
            name = _btfm_cstring(read, module + off["module.name"], layout.sizes.get("module.name", 56))
            btf_address = _btfm_int(read, node + off["btf_module.btf"], ptr, layout)
            refs.append(read_kernel_btf(read, layout, btf_address, name))
        except BtfParseError as error:
            if wanted is not None and name == wanted:
                raise
            if skipped is not None:
                skipped.append("%s (%s)" % (name or "0x%x" % node, error))
        entry = _btfm_int(read, entry, ptr, layout)
    if entry not in seen:
        raise BtfParseError("btf_modules list longer than %d entries" % limit)
    return refs


def _btfm_read_blob(read: Reader, address: int, size: int) -> bytes:
    if not address or not 0 < size <= MAX_BTF_SIZE:
        raise BtfParseError("implausible BTF blob 0x%x+%d" % (address, size))
    chunks, position = [], address
    while position < address + size:
        step = min(address + size - position, (1 << 20) - (position & 0xFFFFF))
        chunk = read(position, step)
        if chunk is None or len(chunk) != step:
            raise BtfParseError("BTF blob unreadable at 0x%x" % position)
        chunks.append(chunk)
        position += step
    return b"".join(chunks)


def load_vmlinux_btf(read: Reader, layout: KernelBtfLayout, btf_vmlinux_ptr: Optional[int],
                     start_btf: Optional[int] = None, stop_btf: Optional[int] = None
                     ) -> Tuple[BtfData, Optional[KernelBtfRef], List[str]]:
    """The base BTF: via ``btf_vmlinux`` when set, else ``__start_BTF..__stop_BTF``.

    Returns ``(parsed, ref or None, notes)``.  ``btf_vmlinux->data`` / ``data_size`` that differ
    from ``__start_BTF`` / ``__stop_BTF`` are a failed consistency check (``BtfParseError``).
    """
    notes: List[str] = []
    ref = None
    pointer = _btfm_int(read, btf_vmlinux_ptr, layout.pointer_size, layout) if btf_vmlinux_ptr else 0
    if pointer:
        ref = read_kernel_btf(read, layout, pointer, "vmlinux")
        address, size = ref.data_address, ref.data_size
        if start_btf and stop_btf:
            if (address, size) != (start_btf, stop_btf - start_btf):
                raise BtfParseError("btf_vmlinux->data 0x%x+%d != __start_BTF 0x%x+%d" % (
                    address, size, start_btf, stop_btf - start_btf))
            notes.append("btf_vmlinux->data 0x%x+%d == __start_BTF" % (address, size))
    elif start_btf and stop_btf:
        address, size = start_btf, stop_btf - start_btf
        notes.append("btf_vmlinux unset; base from __start_BTF..__stop_BTF")
    else:
        raise BtfParseError("no btf_vmlinux and no __start_BTF/__stop_BTF symbols")
    base = parse_btf(_btfm_read_blob(read, address, size), None, layout.pointer_size)
    if ref is not None and (base.type_count, base.str_len) != (ref.nr_types, ref.str_len):
        raise BtfParseError("vmlinux BTF disagrees with btf_vmlinux (types %d/%d, strings %d/%d)" % (
            base.type_count, ref.nr_types, base.str_len, ref.str_len))
    return base, ref, notes


def _btfm_load_split(read: Reader, ref: KernelBtfRef, base: BtfData, vmlinux_ref: Optional[KernelBtfRef],
                     pointer_size: int) -> BtfData:
    if vmlinux_ref is not None and ref.base_btf != vmlinux_ref.btf_address:
        raise BtfParseError("%s: base_btf 0x%x is not btf_vmlinux" % (ref.name, ref.base_btf))
    if (ref.start_id, ref.start_str_off) != (base.type_count, base.str_len):
        raise BtfParseError("%s: start_id/start_str_off %d/%d do not continue the base (%d/%d)" % (
            ref.name, ref.start_id, ref.start_str_off, base.type_count, base.str_len))
    split = parse_btf(_btfm_read_blob(read, ref.data_address, ref.data_size), base, pointer_size)
    if (split.own_type_count, split.str_len) != (ref.nr_types, ref.str_len):  # split nr_types: own only
        raise BtfParseError("%s: blob disagrees with struct btf (types %d, strings %d/%d)" % (
            ref.name, split.own_type_count, split.str_len, ref.str_len))
    return split


# --------------------------------------------------------------------------- signature scan


# magic, version 1, flags 0, hdr_len 24 or 32 (v7.1+ layout section), both byte orders
_BTFM_SIGNATURES = (b"\x9f\xeb\x01\x00\x18\x00\x00\x00", b"\x9f\xeb\x01\x00\x20\x00\x00\x00",
                    b"\xeb\x9f\x01\x00\x00\x00\x00\x18", b"\xeb\x9f\x01\x00\x00\x00\x00\x20")
MAX_SCAN_BLOB = 4 << 20  # a module's BTF; vmlinux-sized candidates are not module BTF
MAX_SCAN_READ = 256 << 20  # candidate bytes read per scan


@dataclass(frozen=True)
class BtfScanHit:
    address: int
    data: bytes
    btf: Optional[BtfData] = None  # parsed against the base when the scan was given one

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def _btfm_candidate_extent(header: bytes, max_blob: int) -> Optional[Tuple[int, int, int]]:
    """``(size, str_start, str_len)`` of a candidate from its header, or None when implausible."""
    endian = "<" if header[:2] == b"\x9f\xeb" else ">"
    _m, _v, _f, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        endian + "HBBIIIII", header, 0)
    sections = [(type_off, type_len), (str_off, str_len)]
    if hdr_len == BTF_LAYOUT_HEADER_LEN:
        sections.append(struct.unpack_from(endian + "II", header, BTF_HEADER_LEN))
    if not str_len or any(off % 4 for off, _length in sections[:1]):
        return None
    size = hdr_len + max(off + length for off, length in sections)
    return (size, hdr_len + str_off, str_len) if size <= max_blob else None


def scan_btf_blobs(read: Reader, ranges: Iterable[Tuple[int, int]], wanted_names: Sequence[str],
                   chunk_size: int = 16 << 20, max_candidates: int = MAX_SCAN_CANDIDATES,
                   base_strings: bytes = b"", stats: Optional[Dict[str, int]] = None,
                   base: Optional[BtfData] = None, pointer_size: int = 8,
                   max_blob: int = MAX_SCAN_BLOB, max_read: int = MAX_SCAN_READ) -> List[BtfScanHit]:
    """Distinct BTF blobs in ``ranges`` whose strings name every ``wanted_names`` entry.

    Split BTF deduplicates its strings against the base, so a name may live only in
    ``base_strings`` (e.g. ``cookie`` on vmlinux); at least one wanted name must be in the
    candidate's own string section.  With ``base``, each candidate is parsed at once and kept
    only when every wanted struct parses (``hit.btf``).  Candidates larger than ``max_blob`` are
    ignored and at most ``max_read`` candidate bytes are read.  ``stats`` receives
    ``candidates``, ``bytes``, ``read``, ``name_hits`` and ``exhausted`` (1 when a cap stopped
    the scan early).  A scan hit is information, never proof of which module it belongs to.
    """
    needles = [b"\0" + n.encode("ascii") + b"\0" for n in wanted_names]
    in_base = [needle in base_strings for needle in needles]  # searched once, not per candidate
    hits: Dict[str, BtfScanHit] = {}
    tally = {"candidates": 0, "bytes": 0, "read": 0, "name_hits": 0, "exhausted": 0}
    for start, length in ranges:
        position = start
        while position < start + length and not tally["exhausted"]:
            step = min(chunk_size, start + length - position)
            buffer = read(position, step + BTF_LAYOUT_HEADER_LEN) or read(position, step) or b""
            for signature in _BTFM_SIGNATURES:
                index = buffer.find(signature)
                while 0 <= index < step and not tally["exhausted"]:
                    _btfm_scan_candidate(read, position + index, buffer[index:index + BTF_LAYOUT_HEADER_LEN],
                                         needles, in_base, base, pointer_size, wanted_names,
                                         max_blob, max_read, max_candidates, tally, hits)
                    index = buffer.find(signature, index + 1)
            position += step
            tally["bytes"] += step
    if stats is not None:
        stats.update(tally)
    return list(hits.values())


def _btfm_scan_candidate(read: Reader, address: int, header: bytes, needles: Sequence[bytes],
                         in_base: Sequence[bool], base: Optional[BtfData], pointer_size: int,
                         wanted_names: Sequence[str], max_blob: int, max_read: int, max_candidates: int,
                         tally: Dict[str, int], hits: Dict[str, BtfScanHit]) -> None:
    tally["candidates"] += 1
    if tally["candidates"] >= max_candidates:
        tally["exhausted"] = 1
    if len(header) < BTF_LAYOUT_HEADER_LEN:
        header = read(address, BTF_LAYOUT_HEADER_LEN) or b""
        if len(header) < BTF_LAYOUT_HEADER_LEN:
            return
    extent = _btfm_candidate_extent(header, max_blob)
    if extent is None:
        return
    size, str_start, str_len = extent
    if tally["read"] + size > max_read:
        tally["exhausted"] = 1
        return
    tally["read"] += size
    data = read(address, size)
    if data is None or len(data) != size:
        return
    strings = b"\0" + data[str_start:str_start + str_len]  # the section's first name has no leading NUL
    own = [needle in strings for needle in needles]
    if needles and not any(own):
        return
    if not all(o or b for o, b in zip(own, in_base)):
        return
    tally["name_hits"] += 1
    digest = hashlib.sha256(data).hexdigest()
    if digest in hits:
        return
    if base is None:
        hits[digest] = BtfScanHit(address, data)
        return
    try:
        split = parse_btf(data, base, pointer_size)
        if not _btfm_layouts(split, wanted_names)[1]:
            hits[digest] = BtfScanHit(address, data, split)
    except BtfParseError:
        return


# --------------------------------------------------------------------------- one-call recovery


@dataclass
class RecoveredLayouts:
    """Struct layouts of one module, recovered from memory BTF.

    ``members`` uses the offset-table key format (``"wg_peer.handshake"``,
    ``"sizeof(wg_peer)"``).  ``method`` is ``symbols``, ``scan`` or ``symbols+scan`` (both found
    the same layouts); ``source`` is a human-readable provenance line.
    """

    module: str
    structs: Dict[str, BtfStruct]
    members: Dict[str, int]
    method: str
    source: str
    blob_sha256: str
    missing: Tuple[str, ...] = ()
    notes: List[str] = field(default_factory=list)
    btf: Optional[BtfData] = None
    scan_blobs: int = 0  # distinct scan blobs that parsed with every wanted struct
    scan_exhausted: bool = False

    @property
    def trusted(self) -> bool:
        """True when these offsets may be trusted like a built-in BTF table entry.

        Only the symbol walk binds a blob to the module (``module->name`` / ``btf->name``,
        ``base_btf == btf_vmlinux``, ``btf_vmlinux->data == __start_BTF``, ``start_id`` /
        ``start_str_off`` / ``nr_types`` / ``hdr.str_len`` consistent) -- a walk that failed any
        check yields no ``symbols`` result.  A scan-only result is NEVER trusted (a planted or
        stale blob can match); in ``both`` mode the scan is only an agreement cross-check.
        Every wanted struct must be present.
        """
        return bool(self.structs) and not self.missing and "symbols" in self.method.split("+")

    def document(self) -> Dict[str, Dict]:
        return btf_offsets_document(self.structs.values(), "btf-memory:%s" % self.module)


def _btfm_layouts(btf: BtfData, wanted: Sequence[str]) -> Tuple[Dict[str, BtfStruct], Tuple[str, ...]]:
    found: Dict[str, BtfStruct] = {}
    missing = []
    for name in wanted:
        try:
            found[name] = btf.struct(name)
        except BtfParseError:
            missing.append(name)
    return found, tuple(missing)


def _btfm_by_symbols(read: Reader, layout: KernelBtfLayout, symbols: Dict[str, int], module: str,
                     base: BtfData, vmlinux_ref: Optional[KernelBtfRef], notes: List[str]) -> Optional[BtfData]:
    if module == "vmlinux":
        return base
    if vmlinux_ref is None:  # base_btf of the module cannot be checked against btf_vmlinux
        raise BtfParseError("btf_vmlinux is NULL: module BTF cannot be bound to the vmlinux base")
    if not symbols.get("btf_modules"):
        notes.append("symbols: no btf_modules symbol")
        return None
    skipped: List[str] = []
    refs = walk_btf_modules(read, layout, symbols["btf_modules"], wanted=module, skipped=skipped)
    matches = [r for r in refs if r.name == module]
    notes.append("symbols: btf_modules has %d entries%s" % (
        len(refs), "; skipped unreadable: %s" % ", ".join(skipped) if skipped else ""))
    if not matches:
        notes.append("symbols: module %s not on btf_modules" % module)
        return None
    if len(matches) > 1:
        raise BtfParseError("module %s is on btf_modules %d times" % (module, len(matches)))
    ref = matches[0]
    if ref.btf_name and ref.btf_name != module:
        raise BtfParseError("btf->name %r != module->name %r" % (ref.btf_name, module))
    return _btfm_load_split(read, ref, base, vmlinux_ref, layout.pointer_size)


def _btfm_by_scan(read: Reader, ranges: Iterable[Tuple[int, int]], wanted: Sequence[str], base: BtfData,
                  pointer_size: int, notes: List[str]) -> Tuple[Optional[BtfData], int, bool]:
    stats: Dict[str, int] = {}
    hits = scan_btf_blobs(read, ranges, wanted, base_strings=b"\0" + base._strings, stats=stats,
                          base=base, pointer_size=pointer_size)
    parsed = {hit.sha256: hit.btf for hit in hits if hit.btf is not None}
    exhausted = bool(stats.get("exhausted"))
    notes.append("scan: %d MiB, %d header candidates, %d name hits, %d distinct blobs parse as split "
                 "BTF with every struct%s" % (stats.get("bytes", 0) >> 20, stats.get("candidates", 0),
                                              stats.get("name_hits", 0), len(parsed),
                                              " (a scan cap was hit: incomplete)" if exhausted else ""))
    shapes = {tuple(sorted(flat_offsets(_btfm_layouts(b, wanted)[0].values()).items())) for b in parsed.values()}
    if len(shapes) > 1:
        notes.append("scan: %d blobs with conflicting layouts -- scan result discarded" % len(shapes))
        return None, len(parsed), exhausted
    return next(iter(parsed.values()), None), len(parsed), exhausted


def recover_layouts(read: Reader, layout: KernelBtfLayout, symbols: Dict[str, int], module: str,
                    wanted: Sequence[str], scan_read: Optional[Reader] = None,
                    scan_ranges: Optional[Iterable[Tuple[int, int]]] = None,
                    method: str = "auto", base_cache: Optional[Dict[str, object]] = None) -> RecoveredLayouts:
    """Layouts of ``wanted`` structs from ``module``'s memory BTF (``"vmlinux"`` for the base).

    ``read`` reads kernel virtual memory; ``symbols`` maps ``btf_modules``, ``btf_vmlinux``,
    ``__start_BTF`` and ``__stop_BTF`` to absolute addresses (missing ones may be absent).
    ``method``: ``symbols`` (walk only), ``scan`` (signature scan of ``scan_ranges`` through
    ``scan_read``), ``auto`` (walk, scan when the walk fails) or ``both`` (both; their layouts
    must agree).  Raises ``BtfParseError`` when no source yields the structs or sources conflict.
    Only a walk result can be ``trusted``.
    """
    notes: List[str] = []
    if base_cache is not None and "base" in base_cache:  # one image, several modules: parse vmlinux once
        base, vmlinux_ref, base_notes = base_cache["base"]  # type: ignore[misc]
    else:
        base, vmlinux_ref, base_notes = load_vmlinux_btf(
            read, layout, symbols.get("btf_vmlinux"), symbols.get("__start_BTF"), symbols.get("__stop_BTF"))
        if base_cache is not None:
            base_cache["base"] = (base, vmlinux_ref, base_notes)
    notes.extend(base_notes)
    results: Dict[str, BtfData] = {}
    if method in ("symbols", "auto", "both"):
        try:
            found = _btfm_by_symbols(read, layout, symbols, module, base, vmlinux_ref, notes)
            if found is not None:
                results["symbols"] = found
        except BtfParseError as error:
            notes.append("symbols: %s (btf_modules 0x%x)" % (error, symbols.get("btf_modules") or 0))
    scan_blobs, exhausted = 0, False
    if module != "vmlinux" and scan_ranges is not None and (
            method in ("scan", "both") or (method == "auto" and "symbols" not in results)):
        found, scan_blobs, exhausted = _btfm_by_scan(scan_read or read, scan_ranges, list(wanted), base,
                                                     layout.pointer_size, notes)
        if found is not None:
            results["scan"] = found
    if not results:
        raise BtfParseError("no BTF for %s (%s)" % (module, "; ".join(notes)))
    recovered = _btfm_combine(module, wanted, results, base, notes)
    recovered.scan_blobs, recovered.scan_exhausted = scan_blobs, exhausted
    return recovered


def _btfm_combine(module: str, wanted: Sequence[str], results: Dict[str, BtfData], base: BtfData,
                  notes: List[str]) -> RecoveredLayouts:
    layouts = {how: _btfm_layouts(btf, wanted) for how, btf in results.items()}
    flats = {how: flat_offsets(found.values()) for how, (found, _missing) in layouts.items()}
    if len(flats) == 2 and flats["symbols"] != flats["scan"]:
        raise BtfParseError("symbol walk and signature scan disagree for %s" % module)
    how = "symbols" if "symbols" in results else "scan"
    method = "+".join(k for k in ("symbols", "scan") if k in results)
    if len(results) == 2:
        same = results["symbols"].sha256() == results["scan"].sha256()
        notes.append("cross-check: scan blob %s the walked blob" % ("byte-equals" if same else "differs from (same layouts)"))
    btf = results[how]
    structs, missing = layouts[how]
    source = "btf-memory:%s via %s (blob sha256 %s, %d types on a %d-type base)" % (
        module, method, btf.sha256()[:16], btf.own_type_count if btf is not base else 0, base.type_count)
    return RecoveredLayouts(module, structs, flats[how], method, source, btf.sha256(), missing, notes, btf)
