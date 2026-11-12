"""Shared kernel-plugin helpers for the ``linux.*`` secret plugins (not a plugin itself).

``linux.dmcrypt``, ``linux.keyring``, ``linux.fscrypt``, ``linux.ecryptfs``, ``linux.wireguard``
and ``linux.btf_layouts`` all read the vmlinux ISF the same way and walk the same kernel lists:

* ``SafeReader``: bounded, exception-free reads with the kernel's pointer size/endianness;
* ``kernel_reader`` / ``symbol_address`` / ``kernel_release``: the per-plugin setup;
* ``isf_offset`` / ``isf_size`` / ``isf_member_template``: one ISF member resolver (type and
  member aliases, nested ``outer.inner`` paths, anonymous unions descended);
* ``IsfLayout``: ``"type.member" -> offset`` with a provenance per key (``isf`` | ... |
  ``default``); ``defaulted()`` lists the keys that are only the built-in guess;
* ``iter_list`` / ``iter_rb_nodes``: bounded, cycle-safe ``list_head`` / rb-tree walks;
* ``find_module`` / ``module_symbol``: a loaded module and its kallsyms.

Module-level imports: standard library and ``volatility3`` only (``vol3plugins`` import rules).
"""

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from volatility3.framework import constants, exceptions

vollog = logging.getLogger(__name__)

DEFAULT = "default"  # provenance of an offset that is only the built-in guess
ISF = "isf"
MAX_MODULES = 4096
MAX_UNION_DEPTH = 4
# Every lookup failure an ISF type/member query can raise (missing type, member, template shape).
_ISF_ERRORS = (exceptions.SymbolError, AttributeError, KeyError, IndexError, ValueError, TypeError)
_LOW48 = (1 << 48) - 1


# --------------------------------------------------------------------------- safe reader


class SafeReader:
    """Bounded, exception-free reads of one layer with the kernel's pointer size/endianness."""

    def __init__(self, layer: Any, pointer_size: int = 8, byteorder: str = "little") -> None:
        self.layer = layer
        self.pointer_size = pointer_size
        self.byteorder = byteorder
        self._prefix = "<" if byteorder == "little" else ">"

    def read(self, address: int, length: int) -> Optional[bytes]:
        if not address or length <= 0:
            return None
        try:
            return bytes(self.layer.read(address, length, pad=False))
        except (exceptions.InvalidAddressException, ValueError, OverflowError):
            return None

    def _unpack(self, fmt: str, address: int) -> Optional[int]:
        data = self.read(address, struct.calcsize(fmt))
        return None if data is None else struct.unpack(self._prefix + fmt, data)[0]

    def u8(self, address: int) -> Optional[int]:
        return self._unpack("B", address)

    def u16(self, address: int) -> Optional[int]:
        return self._unpack("H", address)

    def u32(self, address: int) -> Optional[int]:
        return self._unpack("I", address)

    def u64(self, address: int) -> Optional[int]:
        return self._unpack("Q", address)

    def ptr(self, address: int) -> Optional[int]:
        return self._unpack("Q" if self.pointer_size == 8 else "I", address)

    def cstring(self, address: Optional[int], limit: int = 256) -> Optional[str]:
        """NUL-terminated printable ASCII at ``address`` (pointer target) or None."""
        data = self.read(address or 0, limit) if address else None
        if data is None and address:
            data = self.read(address, 16)  # string near a page end
        if data is None or b"\0" not in data:
            return None
        raw = data.split(b"\0", 1)[0]
        if not raw or any(b < 0x20 or b > 0x7E for b in raw):
            return None
        return raw.decode("ascii")

    def inline_string(self, address: int, size: int) -> Optional[str]:
        """A ``char name[size]`` member (may be empty)."""
        data = self.read(address, size)
        if data is None:
            return None
        raw = data.split(b"\0", 1)[0]
        return raw.decode("ascii", "replace")


def nonzero(data: Optional[bytes]) -> bool:
    return bool(data) and any(data)


def align_up(value: int, alignment: int) -> int:
    return value if alignment <= 1 else (value + alignment - 1) & ~(alignment - 1)


# --------------------------------------------------------------------------- plugin setup


def kernel_reader(context: Any, kernel_module_name: str) -> Tuple[Any, Any, SafeReader]:
    """``(vmlinux, kernel virtual layer, SafeReader)`` with the ISF's pointer size and byte order."""
    vmlinux = context.modules[kernel_module_name]
    layer = context.layers[vmlinux.layer_name]
    pointer = vmlinux.get_type("pointer")
    data_format = getattr(getattr(pointer, "vol", None), "data_format", None)
    byteorder = getattr(data_format, "byteorder", None) or "little"
    return vmlinux, layer, SafeReader(layer, pointer.size, byteorder)


def arch_of(layer: Any) -> str:
    names = {cls.__name__ for cls in type(layer).__mro__}
    if any("AArch64" in n or "Arm" in n for n in names):
        return "aarch64"
    if any("Intel32e" in n or "Intel64" in n for n in names):
        return "x86_64"
    return "i386" if any("Intel" in n for n in names) else "unknown"


def symbol_address(vmlinux: Any, name: str, layer: Any = None) -> Optional[int]:
    """Absolute address of vmlinux symbol ``name``, or None.

    With ``layer`` it is canonicalised (comparable with pointers read from memory: vol3 hands
    out symbol addresses masked to the virtual-address width).
    """
    try:
        address = vmlinux.offset + vmlinux.get_symbol(name).address
    except (exceptions.SymbolError, AttributeError):
        return None
    return getattr(layer, "canonicalize", lambda value: value)(address) if layer is not None else address


def kernel_release(vmlinux: Any, reader: SafeReader) -> str:
    """``uname -r`` from ``linux_banner`` ('' when unreadable)."""
    address = symbol_address(vmlinux, "linux_banner")
    match = re.search(rb"Linux version (\S+)", reader.read(address, 256) or b"") if address else None
    return match.group(1).decode("ascii", "replace") if match else ""


def find_module(vmlinux: Any, name: str, limit: int = MAX_MODULES) -> Optional[Any]:
    """The loaded kernel module ``name`` (``modules`` list walk, at most ``limit`` entries)."""
    try:
        head = vmlinux.object_from_symbol("modules")
        module_type = vmlinux.symbol_table_name + constants.BANG + "module"
        for count, module in enumerate(head.to_list(module_type, "list")):
            if count > limit:
                break
            if module.get_name() == name:
                return module
    except (exceptions.SymbolError, exceptions.InvalidAddressException, AttributeError, ValueError):
        vollog.debug("module list walk failed", exc_info=True)
    return None


def module_symbol(module: Any, name: str) -> Optional[int]:
    """Address of ``name`` in a loaded module's kallsyms, or None."""
    try:
        address = module.get_symbol(name)
    except (exceptions.SymbolError, exceptions.InvalidAddressException, AttributeError, ValueError):
        return None
    return int(address) if address else None


# --------------------------------------------------------------------------- ISF resolver


Names = Union[str, Sequence[str]]


def _names(names: Names) -> Sequence[str]:
    return (names,) if isinstance(names, str) else names


def isf_type(module: Any, type_names: Names) -> Optional[Any]:
    """The first of ``type_names`` (renamed types are aliases) the ISF has, else None."""
    for name in _names(type_names):
        try:
            return module.get_type(name)
        except _ISF_ERRORS:
            continue
    return None


def _vol(template: Any, key: str) -> Any:
    """``template.vol[key]`` (vol3 templates) or ``template.<key>`` (plain objects), else None."""
    vol = getattr(template, "vol", None)
    found = vol.get(key) if hasattr(vol, "get") else getattr(vol, key, None)
    return found if found is not None else getattr(template, key, None)


def _members(module: Any, template: Any) -> Dict[str, Tuple[int, Any]]:
    members = _vol(template, "members")
    type_name = _vol(template, "type_name")
    if members is None and type_name:  # a reference to a named type
        members = _vol(module.get_type(type_name.split("!")[-1]), "members")
    return dict(members or {})


def _find(module: Any, template: Any, member: str, depth: int = 0) -> Optional[Tuple[int, Any]]:
    """``(offset, member template)`` of ``member``; anonymous unions/structs searched (depth <= 4)."""
    members = _members(module, template)
    try:
        return template.relative_child_offset(member), members.get(member, (0, None))[1]
    except _ISF_ERRORS:
        pass
    if member in members:
        return members[member]
    for name, (offset, sub) in members.items():
        if name.startswith("unnamed_field") and depth < MAX_UNION_DEPTH:
            inner = _find(module, sub, member, depth + 1)
            if inner is not None:
                return offset + inner[0], inner[1]
    return None


def find_member(module: Any, template: Any, member: str) -> Optional[int]:
    """Offset of ``member`` in ``template``, searching anonymous unions/structs (depth <= 4)."""
    try:
        found = _find(module, template, member)
    except _ISF_ERRORS:
        return None
    return None if found is None else found[0]


def _path_offset(module: Any, template: Any, path: str) -> Optional[int]:
    total = 0
    for member in path.split("."):
        found = _find(module, template, member)
        if found is None:
            return None
        total, template = total + found[0], found[1]
    return total


def isf_offset(module: Any, type_names: Names, *paths: str) -> Optional[int]:
    """Offset of the first of ``paths`` (``member`` or nested ``outer.inner``; renamed members
    are aliases) in the ISF type, or None when the ISF lacks the type or every path."""
    template = isf_type(module, type_names)
    for path in paths if template is not None else ():
        try:
            offset = _path_offset(module, template, path)
        except _ISF_ERRORS:
            continue
        if offset is not None:
            return offset
    return None


def isf_member_template(module: Any, type_names: Names, member: str) -> Optional[Any]:
    """The template of a direct member of the ISF type, or None."""
    template = isf_type(module, type_names)
    try:
        return _members(module, template)[member][1] if template is not None else None
    except _ISF_ERRORS:
        return None


def isf_size(module: Any, key: str) -> Optional[int]:
    """``sizeof(type)`` for ``"type"``, ``sizeof(type.member)`` for ``"type.member"``; None if absent."""
    type_name, _dot, member = key.partition(".")
    template = isf_member_template(module, type_name, member) if member else isf_type(module, type_name)
    try:
        return template.size if template is not None else None
    except _ISF_ERRORS:
        return None


# --------------------------------------------------------------------------- layouts


@dataclass
class IsfLayout:
    """Offsets (``"type.member" -> offset``) and sizes, with a provenance per offset.

    ``sources[key]`` is ``isf``, a fallback's own source (``table``, ``btf-memory`` ...) or
    ``default`` (the built-in guess).  A bare layout (unit tests) has no sources and counts as
    fully known.
    """

    offsets: Dict[str, int] = field(default_factory=dict)
    sizes: Dict[str, int] = field(default_factory=dict)
    sources: Dict[str, str] = field(default_factory=dict)

    def __getitem__(self, key: str) -> int:
        return self.offsets[key]

    def resolve(self, lookup: Callable[[str], Optional[int]],
                fallback: Optional[Callable[[str], Optional[Tuple[int, str]]]] = None) -> None:
        """Fill every offset from ``lookup`` (``isf``), else ``fallback`` -> (offset, source), else
        keep the built-in value as ``default``."""
        for key in list(self.offsets):
            offset = lookup(key)
            found = (offset, ISF) if offset is not None else (fallback(key) if fallback else None)
            if found is None:
                self.sources[key] = DEFAULT
            else:
                self.offsets[key], self.sources[key] = found

    def defaulted(self) -> List[str]:
        """Every offset that is only the built-in guess."""
        return sorted(k for k, v in self.sources.items() if v == DEFAULT)


# --------------------------------------------------------------------------- walks


def is_list_head(node: int, head: int) -> bool:
    """``node`` is ``head`` in its canonical or its width-masked form.

    vol3 hands out symbol addresses masked to the virtual-address width while pointers read
    from memory are canonical (sign-extended); comparing the low 48 bits makes the head match
    in either form, so it is never walked as a node.
    """
    return node == head or (node & _LOW48) == (head & _LOW48)


def iter_list(reader: SafeReader, head: int, member_offset: int = 0, limit: int = 1 << 20) -> Iterator[int]:
    """Containers (``node - member_offset``) of a ``list_head`` ring after ``head`` (``head``
    itself excluded, in either address form); bounded and cycle-safe."""
    seen = {head}
    node = reader.ptr(head)
    while node and node not in seen and not is_list_head(node, head) and len(seen) <= limit:
        seen.add(node)
        yield node - member_offset
        node = reader.ptr(node)


def iter_rb_nodes(reader: SafeReader, rb_left: int, rb_right: int, root_node: Optional[int],
                  limit: int) -> Iterator[int]:
    """In-order rb-tree walk from ``root_node`` (``rb_left``/``rb_right`` = member offsets):
    iterative, cycle-safe, it stops once more than ``limit`` nodes have been seen."""
    stack: List[int] = []
    node, seen = root_node, set()
    while (stack or node) and len(seen) <= limit:
        while node and node not in seen and len(seen) <= limit:
            seen.add(node)
            stack.append(node)
            node = reader.ptr(node + rb_left)
        if not stack:
            break
        node = stack.pop()
        yield node
        node = reader.ptr(node + rb_right)


def write_text(plugin: Any, name: str, text: str) -> None:
    """Write ``text`` (UTF-8) to the plugin's output file ``name`` (shared by the kernel and process plugins)."""
    with plugin.open(name) as handle:
        handle.write(text.encode("utf-8"))
