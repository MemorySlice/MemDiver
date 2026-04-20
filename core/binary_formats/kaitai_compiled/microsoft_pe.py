"""Pre-compiled Kaitai Struct parser for Microsoft PE binary format.

Supports PE32 and PE32+ (64-bit), little-endian only.
Tracks field positions via _debug dicts for hex overlay mapping.
"""

from enum import IntEnum

from kaitaistruct import KaitaiStream, KaitaiStruct, BytesIO


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PeMachine(IntEnum):
    UNKNOWN = 0x0
    I386 = 0x14C
    R4000 = 0x166
    WCEMIPSV2 = 0x169
    ALPHA = 0x184
    SH3 = 0x1A2
    SH4 = 0x1A6
    ARM = 0x1C0
    THUMB = 0x1C2
    ARMNT = 0x1C4
    AM33 = 0x1D3
    POWERPC = 0x1F0
    IA64 = 0x200
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    EBC = 0xEBC
    AMD64 = 0x8664
    ARM64 = 0xAA64
    RISCV32 = 0x5032
    RISCV64 = 0x5064


class PeOptionalHeaderMagic(IntEnum):
    PE32 = 0x10B
    PE32_PLUS = 0x20B
    ROM = 0x107


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
# DosHeader
# ---------------------------------------------------------------------------

class DosHeader(KaitaiStruct):
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

        self.magic = rd(lambda: io.read_bytes(2), "magic")
        if self.magic != b'MZ':
            raise ValueError(
                f"Expected DOS magic 'MZ', got {self.magic!r}")

        # Skip to e_lfanew at offset 0x3C (skip 58 bytes of DOS header)
        self.rest_of_dos_header = rd(
            lambda: io.read_bytes(58), "rest_of_dos_header")
        self.ofs_pe = rd(io.read_u4le, "ofs_pe")


# ---------------------------------------------------------------------------
# CoffHeader
# ---------------------------------------------------------------------------

class CoffHeader(KaitaiStruct):
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

        raw_machine = rd(io.read_u2le, "machine")
        self.machine = _safe_enum(PeMachine, raw_machine)
        self.number_of_sections = rd(io.read_u2le, "number_of_sections")
        self.time_date_stamp = rd(io.read_u4le, "time_date_stamp")
        self.pointer_to_symbol_table = rd(
            io.read_u4le, "pointer_to_symbol_table")
        self.number_of_symbols = rd(io.read_u4le, "number_of_symbols")
        self.size_of_optional_header = rd(
            io.read_u2le, "size_of_optional_header")
        self.characteristics = rd(io.read_u2le, "characteristics")


# ---------------------------------------------------------------------------
# OptionalHeader
# ---------------------------------------------------------------------------

class OptionalHeader(KaitaiStruct):
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

        raw_magic = rd(io.read_u2le, "magic")
        self.magic = _safe_enum(PeOptionalHeaderMagic, raw_magic)
        self.is_pe32_plus = (raw_magic == 0x20B)

        self.major_linker_version = rd(io.read_u1, "major_linker_version")
        self.minor_linker_version = rd(io.read_u1, "minor_linker_version")
        self.size_of_code = rd(io.read_u4le, "size_of_code")
        self.size_of_initialized_data = rd(
            io.read_u4le, "size_of_initialized_data")
        self.size_of_uninitialized_data = rd(
            io.read_u4le, "size_of_uninitialized_data")
        self.address_of_entry_point = rd(
            io.read_u4le, "address_of_entry_point")
        self.base_of_code = rd(io.read_u4le, "base_of_code")

        if self.is_pe32_plus:
            self.image_base = rd(io.read_u8le, "image_base")
        else:
            self.base_of_data = rd(io.read_u4le, "base_of_data")
            self.image_base = rd(io.read_u4le, "image_base")

        self.section_alignment = rd(io.read_u4le, "section_alignment")
        self.file_alignment = rd(io.read_u4le, "file_alignment")
        self.major_os_version = rd(io.read_u2le, "major_os_version")
        self.minor_os_version = rd(io.read_u2le, "minor_os_version")
        self.major_image_version = rd(io.read_u2le, "major_image_version")
        self.minor_image_version = rd(io.read_u2le, "minor_image_version")
        self.major_subsystem_version = rd(
            io.read_u2le, "major_subsystem_version")
        self.minor_subsystem_version = rd(
            io.read_u2le, "minor_subsystem_version")
        self.win32_version_value = rd(io.read_u4le, "win32_version_value")
        self.size_of_image = rd(io.read_u4le, "size_of_image")
        self.size_of_headers = rd(io.read_u4le, "size_of_headers")
        self.checksum = rd(io.read_u4le, "checksum")
        self.subsystem = rd(io.read_u2le, "subsystem")
        self.dll_characteristics = rd(io.read_u2le, "dll_characteristics")

        if self.is_pe32_plus:
            self.size_of_stack_reserve = rd(
                io.read_u8le, "size_of_stack_reserve")
            self.size_of_stack_commit = rd(
                io.read_u8le, "size_of_stack_commit")
            self.size_of_heap_reserve = rd(
                io.read_u8le, "size_of_heap_reserve")
            self.size_of_heap_commit = rd(
                io.read_u8le, "size_of_heap_commit")
        else:
            self.size_of_stack_reserve = rd(
                io.read_u4le, "size_of_stack_reserve")
            self.size_of_stack_commit = rd(
                io.read_u4le, "size_of_stack_commit")
            self.size_of_heap_reserve = rd(
                io.read_u4le, "size_of_heap_reserve")
            self.size_of_heap_commit = rd(
                io.read_u4le, "size_of_heap_commit")

        self.loader_flags = rd(io.read_u4le, "loader_flags")
        self.number_of_rva_and_sizes = rd(
            io.read_u4le, "number_of_rva_and_sizes")


# ---------------------------------------------------------------------------
# SectionHeader
# ---------------------------------------------------------------------------

class PeSectionHeader(KaitaiStruct):
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

        self.name = rd(lambda: io.read_bytes(8), "name")
        self.virtual_size = rd(io.read_u4le, "virtual_size")
        self.virtual_address = rd(io.read_u4le, "virtual_address")
        self.size_of_raw_data = rd(io.read_u4le, "size_of_raw_data")
        self.pointer_to_raw_data = rd(io.read_u4le, "pointer_to_raw_data")
        self.pointer_to_relocations = rd(
            io.read_u4le, "pointer_to_relocations")
        self.pointer_to_line_numbers = rd(
            io.read_u4le, "pointer_to_line_numbers")
        self.number_of_relocations = rd(
            io.read_u2le, "number_of_relocations")
        self.number_of_line_numbers = rd(
            io.read_u2le, "number_of_line_numbers")
        self.characteristics = rd(io.read_u4le, "characteristics")

    @property
    def name_str(self):
        """Section name as a stripped UTF-8 string."""
        return self.name.rstrip(b'\x00').decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# MicrosoftPe (top-level)
# ---------------------------------------------------------------------------

class MicrosoftPe(KaitaiStruct):
    """Microsoft PE (Portable Executable) binary format parser.

    Supports PE32 and PE32+ (64-bit), little-endian.
    Follows Kaitai Struct runtime conventions with _debug position tracking.
    """

    # Re-export enums and sub-types as class attributes
    PeMachine = PeMachine
    PeOptionalHeaderMagic = PeOptionalHeaderMagic
    DosHeader = DosHeader
    CoffHeader = CoffHeader
    OptionalHeader = OptionalHeader
    PeSectionHeader = PeSectionHeader

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._read()

    def _read(self):
        d = self._debug
        io = self._io

        # --- DOS Header (64 bytes) ---
        dos_start = io.pos()
        self.dos_header = DosHeader(io, self, self._root)
        d["dos_header"] = {"start": dos_start, "end": io.pos()}

        # --- PE Signature (at e_lfanew offset) ---
        try:
            io.seek(self.dos_header.ofs_pe)
            sig_start = io.pos()
            self.pe_signature = io.read_bytes(4)
            d["pe_signature"] = {"start": sig_start, "end": io.pos()}
            if self.pe_signature != b'PE\x00\x00':
                raise ValueError(
                    f"Expected PE signature 'PE\\x00\\x00', "
                    f"got {self.pe_signature!r}")
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            self.pe_signature = None
            return

        # --- COFF Header (20 bytes) ---
        try:
            coff_start = io.pos()
            self.coff_header = CoffHeader(io, self, self._root)
            d["coff_header"] = {"start": coff_start, "end": io.pos()}
        except Exception:
            self.coff_header = None
            return

        # --- Optional Header (variable size) ---
        self.optional_header = None
        try:
            if self.coff_header.size_of_optional_header > 0:
                opt_start = io.pos()
                self.optional_header = OptionalHeader(
                    io, self, self._root)
                d["optional_header"] = {
                    "start": opt_start, "end": io.pos()}
                # Skip any remaining optional header bytes (data directories)
                opt_end = opt_start + self.coff_header.size_of_optional_header
                if io.pos() < opt_end:
                    io.seek(opt_end)
        except Exception:
            pass  # partial parse is acceptable

        # --- Section Headers ---
        self.sections = []
        try:
            num = self.coff_header.number_of_sections
            if num > 0:
                sections_start = io.pos()
                for _ in range(num):
                    sh = PeSectionHeader(io, self, self._root)
                    self.sections.append(sh)
                d["sections"] = {
                    "start": sections_start, "end": io.pos()}
        except Exception:
            pass  # partial parse is acceptable

    @classmethod
    def from_file(cls, filename):
        """Parse a PE file from a filesystem path."""
        with open(filename, "rb") as f:
            return cls(KaitaiStream(f))

    @classmethod
    def from_bytes(cls, buf):
        """Parse PE from an in-memory bytes buffer."""
        return cls(KaitaiStream(BytesIO(buf)))
