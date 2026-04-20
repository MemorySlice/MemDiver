"""Pre-compiled Kaitai Struct parser for ELF binary format.

Supports ELF32 and ELF64, little-endian and big-endian.
Tracks field positions via _debug dicts for hex overlay mapping.
"""

from enum import IntEnum

from kaitaistruct import KaitaiStream, KaitaiStruct, BytesIO


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class OsAbi(IntEnum):
    SYSTEM_V = 0
    HP_UX = 1
    NETBSD = 2
    GNU = 3
    SOLARIS = 6
    AIX = 7
    IRIX = 8
    FREEBSD = 9
    TRU64 = 10
    MODESTO = 11
    OPENBSD = 12
    ARM_AEABI = 64
    ARM = 97
    STANDALONE = 255


class ObjType(IntEnum):
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4


class Machine(IntEnum):
    EM_NONE = 0
    EM_SPARC = 2
    EM_386 = 3
    EM_MIPS = 8
    EM_POWERPC = 20
    EM_ARM = 40
    EM_SUPERH = 42
    EM_IA_64 = 50
    EM_X86_64 = 62
    EM_AARCH64 = 183


class PhType(IntEnum):
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7


class ShType(IntEnum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_DYNSYM = 11


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_enum(enum_cls, raw):
    """Return enum member if valid, otherwise the raw int."""
    try:
        return enum_cls(raw)
    except ValueError:
        return raw


def _read_debug(io, reader, name, debug):
    """Read a field, record its position span in *debug*, return value."""
    start = io.pos()
    value = reader()
    debug[name] = {"start": start, "end": io.pos()}
    return value


# ---------------------------------------------------------------------------
# SectionHeader
# ---------------------------------------------------------------------------

class SectionHeader(KaitaiStruct):
    def __init__(self, bits, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._bits = bits
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        u4 = io.read_u4le if not hasattr(self, '_be') else io.read_u4be
        is64 = self._bits == 2

        # Inherit endianness from parent stream (set by EndianElf)
        be = getattr(self._parent, '_is_be', False)
        u2 = io.read_u2be if be else io.read_u2le
        u4 = io.read_u4be if be else io.read_u4le
        u8 = io.read_u8be if be else io.read_u8le
        uw = u8 if is64 else u4

        self.ofs_name = rd(u4, "ofs_name")
        raw_type = rd(u4, "type")
        self.type = _safe_enum(ShType, raw_type)
        self.flags = rd(uw, "flags")
        self.addr = rd(uw, "addr")
        self.ofs_body = rd(uw, "ofs_body")
        self.len_body = rd(uw, "len_body")
        self.linked_section_idx = rd(u4, "linked_section_idx")
        self.info = rd(u4, "info")
        self.align = rd(uw, "align")
        self.entry_size = rd(uw, "entry_size")


# ---------------------------------------------------------------------------
# ProgramHeader
# ---------------------------------------------------------------------------

class ProgramHeader(KaitaiStruct):
    def __init__(self, bits, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._bits = bits
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        is64 = self._bits == 2

        be = getattr(self._parent, '_is_be', False)
        u4 = io.read_u4be if be else io.read_u4le
        u8 = io.read_u8be if be else io.read_u8le
        uw = u8 if is64 else u4

        raw_type = rd(u4, "type")
        self.type = _safe_enum(PhType, raw_type)

        if is64:
            self.flags64 = rd(u4, "flags64")

        self.offset = rd(uw, "offset")
        self.vaddr = rd(uw, "vaddr")
        self.paddr = rd(uw, "paddr")
        self.filesz = rd(uw, "filesz")
        self.memsz = rd(uw, "memsz")

        if not is64:
            self.flags32 = rd(u4, "flags32")

        self.align = rd(uw, "align")

    @property
    def flags(self):
        """Unified flags accessor for both 32-bit and 64-bit."""
        return self.flags64 if self._bits == 2 else self.flags32


# ---------------------------------------------------------------------------
# EndianElf (inner header — endian-aware)
# ---------------------------------------------------------------------------

class EndianElf(KaitaiStruct):
    def __init__(self, bits, is_be, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._bits = bits
        self._is_be = is_be
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        is64 = self._bits == 2
        be = self._is_be

        u2 = io.read_u2be if be else io.read_u2le
        u4 = io.read_u4be if be else io.read_u4le
        u8 = io.read_u8be if be else io.read_u8le
        uw = u8 if is64 else u4

        raw_type = rd(u2, "e_type")
        self.e_type = _safe_enum(ObjType, raw_type)

        raw_machine = rd(u2, "machine")
        self.machine = _safe_enum(Machine, raw_machine)

        self.e_version = rd(u4, "e_version")
        self.entry_point = rd(uw, "entry_point")
        self.program_header_offset = rd(uw, "program_header_offset")
        self.section_header_offset = rd(uw, "section_header_offset")
        self.flags = rd(u4, "flags")
        self.e_ehsize = rd(u2, "e_ehsize")
        self.program_header_entry_size = rd(u2, "program_header_entry_size")
        self.qty_program_header = rd(u2, "qty_program_header")
        self.section_header_entry_size = rd(u2, "section_header_entry_size")
        self.qty_section_header = rd(u2, "qty_section_header")
        self.section_names_idx = rd(u2, "section_names_idx")

        # Parse program headers
        self.program_headers = []
        try:
            if self.program_header_offset > 0 and self.qty_program_header > 0:
                ph_start = io.pos()
                io.seek(self.program_header_offset)
                for i in range(self.qty_program_header):
                    ph = ProgramHeader(self._bits, io, self, self._root)
                    self.program_headers.append(ph)
                d["program_headers"] = {"start": self.program_header_offset,
                                        "end": io.pos()}
        except Exception:
            pass  # partial parse is acceptable

        # Parse section headers
        self.section_headers = []
        try:
            if self.section_header_offset > 0 and self.qty_section_header > 0:
                io.seek(self.section_header_offset)
                for i in range(self.qty_section_header):
                    sh = SectionHeader(self._bits, io, self, self._root)
                    self.section_headers.append(sh)
                d["section_headers"] = {"start": self.section_header_offset,
                                        "end": io.pos()}
        except Exception:
            pass  # partial parse is acceptable


# ---------------------------------------------------------------------------
# Elf (top-level)
# ---------------------------------------------------------------------------

class Elf(KaitaiStruct):
    """ELF binary format parser (ELF32 + ELF64, LE + BE).

    Follows Kaitai Struct runtime conventions with _debug position tracking.
    """

    # Re-export enums as class attributes for convenient access
    OsAbi = OsAbi
    ObjType = ObjType
    Machine = Machine
    PhType = PhType
    ShType = ShType
    EndianElf = EndianElf
    ProgramHeader = ProgramHeader
    SectionHeader = SectionHeader

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)

        self.magic = rd(lambda: io.read_bytes(4), "magic")
        if self.magic != b'\x7fELF':
            raise ValueError(
                f"Expected ELF magic '\\x7fELF', got {self.magic!r}")

        self.bits = rd(io.read_u1, "bits")
        self.endian = rd(io.read_u1, "endian")
        self.ei_version = rd(io.read_u1, "ei_version")

        raw_abi = rd(io.read_u1, "abi")
        self.abi = _safe_enum(OsAbi, raw_abi)

        self.abi_version = rd(io.read_u1, "abi_version")
        self.pad = rd(lambda: io.read_bytes(7), "pad")

        # Parse endian-aware header
        self._header = None
        try:
            is_be = self.endian == 2
            self._header = EndianElf(
                self.bits, is_be, io, self, self._root)
            d["header"] = {"start": 16, "end": io.pos()}
        except Exception:
            pass  # partial parse — header fields up to failure are kept

    @property
    def header(self):
        """The endian-aware ELF header (EndianElf instance)."""
        return self._header

    @classmethod
    def from_file(cls, filename):
        """Parse an ELF file from a filesystem path."""
        with open(filename, "rb") as f:
            return cls(KaitaiStream(f))

    @classmethod
    def from_bytes(cls, buf):
        """Parse ELF from an in-memory bytes buffer."""
        return cls(KaitaiStream(BytesIO(buf)))
