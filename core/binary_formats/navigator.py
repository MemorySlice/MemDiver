"""Navigation tree builder for binary format headers."""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NavNode:
    """A node in the format navigation tree."""

    label: str
    offset: int
    size: int
    node_type: str  # "header", "section", "segment", "load_command"
    children: list[NavNode] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "offset": self.offset,
            "size": self.size,
            "node_type": self.node_type,
            "children": [c.to_dict() for c in self.children],
        }


def build_nav_tree(data: bytes, format_name: str) -> Optional[NavNode]:
    """Parse format headers and build navigation tree."""
    builders = {
        "elf64": lambda d: _build_elf_tree(d, 64),
        "elf32": lambda d: _build_elf_tree(d, 32),
        "pe32": _build_pe_tree,
        "pe64": _build_pe_tree,
        "macho64_le": lambda d: _build_macho_tree(d, 64),
        "macho32_le": lambda d: _build_macho_tree(d, 32),
        "msl": _build_msl_tree,
    }
    builder = builders.get(format_name)
    if builder is None:
        return None
    try:
        return builder(data)
    except (struct.error, IndexError, ValueError):
        # Return minimal header node so format badge still appears
        return NavNode(format_name.upper(), 0, min(len(data), 64), "header")


def _build_elf_tree(data: bytes, bits: int) -> Optional[NavNode]:
    """Build ELF navigation tree for 32 or 64 bit."""
    if bits == 64:
        hdr_size, fmt, label = 64, "<Q", "ELF-64 Header"
        ph_off, sh_off = 32, 40
        ph_ent_off, ph_num_off = 54, 56
        sh_ent_off, sh_num_off = 58, 60
        min_phent, min_shent = 56, 64
    else:
        hdr_size, fmt, label = 52, "<I", "ELF-32 Header"
        ph_off, sh_off = 28, 32
        ph_ent_off, ph_num_off = 42, 44
        sh_ent_off, sh_num_off = 46, 48
        min_phent, min_shent = 32, 40

    if len(data) < hdr_size:
        return None
    root = NavNode(label, 0, hdr_size, "header")

    try:
        e_phoff = struct.unpack_from(fmt, data, ph_off)[0]
        e_shoff = struct.unpack_from(fmt, data, sh_off)[0]
        e_phentsize = struct.unpack_from("<H", data, ph_ent_off)[0]
        e_phnum = struct.unpack_from("<H", data, ph_num_off)[0]
        e_shentsize = struct.unpack_from("<H", data, sh_ent_off)[0]
        e_shnum = struct.unpack_from("<H", data, sh_num_off)[0]
    except (struct.error, IndexError):
        return root  # Return header-only node on truncated data

    if e_phoff > 0 and e_phnum > 0 and e_phentsize >= min_phent:
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if off + 4 > len(data):
                break
            p_type = struct.unpack_from("<I", data, off)[0]
            root.children.append(
                NavNode(f"PHDR[{i}] {_elf_phdr_type(p_type)}", off, e_phentsize, "segment"),
            )

    if e_shoff > 0 and e_shnum > 0 and e_shentsize >= min_shent:
        for i in range(min(e_shnum, 128)):
            off = e_shoff + i * e_shentsize
            if off + 4 > len(data):
                break
            root.children.append(
                NavNode(f"Section[{i}]", off, e_shentsize, "section"),
            )

    return root


def _build_pe_tree(data: bytes) -> Optional[NavNode]:
    if len(data) < 64:
        return None
    root = NavNode("DOS Header", 0, 64, "header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        return root

    pe_node = NavNode("PE Signature", e_lfanew, 4, "header")
    root.children.append(pe_node)

    coff_off = e_lfanew + 4
    coff_node = NavNode("COFF Header", coff_off, 20, "header")
    root.children.append(coff_node)

    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff_off + 16)[0]

    opt_off = coff_off + 20
    if opt_size > 0 and opt_off + opt_size <= len(data):
        root.children.append(
            NavNode("Optional Header", opt_off, opt_size, "header"),
        )

    sec_off = opt_off + opt_size
    for i in range(min(num_sections, 96)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name_bytes = data[off : off + 8].rstrip(b"\x00")
        name = name_bytes.decode("ascii", errors="replace")
        root.children.append(
            NavNode(f"Section: {name}", off, 40, "section"),
        )

    return root


def _build_macho_tree(data: bytes, bits: int) -> Optional[NavNode]:
    """Build Mach-O navigation tree for 32 or 64 bit."""
    hdr_size = 32 if bits == 64 else 28
    label = f"Mach-O {bits} Header"
    if len(data) < hdr_size:
        return None
    root = NavNode(label, 0, hdr_size, "header")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = hdr_size
    for i in range(min(ncmds, 128)):
        if off + 8 > len(data):
            break
        cmd = struct.unpack_from("<I", data, off)[0]
        cmdsize = struct.unpack_from("<I", data, off + 4)[0]
        if cmdsize < 8:
            break
        root.children.append(
            NavNode(f"LC[{i}] {_macho_cmd_name(cmd)}", off, cmdsize, "load_command"),
        )
        off += cmdsize
    return root


def _build_msl_tree(data: bytes) -> Optional[NavNode]:
    """Build MSL navigation tree: file header + MSLC block list."""
    if len(data) < 64 or data[0:8] != b"MEMSLICE":
        return None

    root = NavNode("MSL File Header", 0, 64, "header")

    endianness = data[8] if len(data) > 8 else 0x01
    fmt = ">I" if endianness == 0x02 else "<I"

    off = 64
    idx = 0
    max_children = 1024
    while off + 8 <= len(data):
        if data[off:off + 4] != b"MSLC":
            break
        try:
            block_length = struct.unpack_from(fmt, data, off + 8)[0]
        except (struct.error, IndexError):
            break
        if block_length < 80 or off + block_length > len(data):
            break
        if idx >= max_children:
            root.children.append(
                NavNode("...truncated", off, 0, "section"),
            )
            break
        bt_fmt = ">H" if endianness == 0x02 else "<H"
        try:
            bt_raw = struct.unpack_from(bt_fmt, data, off + 4)[0]
        except (struct.error, IndexError):
            break
        label = f"Block[{idx}] {_msl_block_type_name(bt_raw)}"
        root.children.append(
            NavNode(label, off, block_length, "section"),
        )
        off += block_length
        idx += 1

    return root


def _msl_block_type_name(bt_raw: int) -> str:
    from msl.enums import BlockType
    try:
        return BlockType(bt_raw).name
    except ValueError:
        return f"0x{bt_raw:04X}"


_ELF_PHDR = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
              6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME",
              0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}

_MACHO_CMD = {0x01: "SEGMENT", 0x19: "SEGMENT_64", 0x02: "SYMTAB",
              0x0B: "DYSYMTAB", 0x0C: "LOAD_DYLIB", 0x0D: "ID_DYLIB",
              0x0E: "LOAD_DYLINKER", 0x1B: "UUID", 0x26: "FUNCTION_STARTS",
              0x2A: "SOURCE_VERSION", 0x32: "BUILD_VERSION"}


def _elf_phdr_type(p_type: int) -> str:
    return _ELF_PHDR.get(p_type, f"0x{p_type:x}")


def _macho_cmd_name(cmd: int) -> str:
    return _MACHO_CMD.get(cmd & 0x7FFFFFFF, f"0x{cmd:x}")
