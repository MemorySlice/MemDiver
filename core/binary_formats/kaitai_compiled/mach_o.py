"""Pre-compiled Kaitai Struct parser for Mach-O binary format.

Supports 32-bit and 64-bit, little-endian and big-endian.
Tracks field positions via _debug dicts for hex overlay mapping.
"""

from enum import IntEnum

from kaitaistruct import KaitaiStream, KaitaiStruct, BytesIO


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CpuType(IntEnum):
    X86 = 7
    X86_64 = 0x01000007
    ARM = 12
    ARM64 = 0x0100000C
    POWERPC = 18
    POWERPC64 = 0x01000012


class FileType(IntEnum):
    OBJECT = 1
    EXECUTE = 2
    FVMLIB = 3
    CORE = 4
    PRELOAD = 5
    DYLIB = 6
    DYLINKER = 7
    BUNDLE = 8
    DSYM = 10


class LoadCommandType(IntEnum):
    SEGMENT = 1
    SYMTAB = 2
    THREAD = 4
    UNIXTHREAD = 5
    DYSYMTAB = 11
    LOAD_DYLIB = 12
    ID_DYLIB = 13
    LOAD_DYLINKER = 14
    SEGMENT_64 = 0x19
    UUID = 0x1B
    RPATH = 0x8000001C
    CODE_SIGNATURE = 0x1D
    FUNCTION_STARTS = 0x26
    MAIN = 0x80000028
    SOURCE_VERSION = 0x2A
    BUILD_VERSION = 0x32


# ---------------------------------------------------------------------------
# Magic constants
# ---------------------------------------------------------------------------

MAGIC_32_LE = 0xFEEDFACE
MAGIC_32_BE = 0xCEFAEDFE
MAGIC_64_LE = 0xFEEDFACF
MAGIC_64_BE = 0xCFFAEDFE

FAT_MAGIC_BE = 0xCAFEBABE
FAT_MAGIC_LE = 0xBEBAFECA

_VALID_MAGICS = {MAGIC_32_LE, MAGIC_32_BE, MAGIC_64_LE, MAGIC_64_BE}


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


def _strip_null(bs: bytes) -> str:
    """Decode null-padded C string."""
    return bs.split(b'\x00', 1)[0].decode("ascii", errors="replace")


def _unwrap_fat(buf: bytes) -> bytes:
    """If *buf* is a fat/universal binary, return the first Mach-O slice."""
    import struct
    if len(buf) < 8:
        return buf
    magic = struct.unpack('<I', buf[:4])[0]
    if magic not in (FAT_MAGIC_LE, FAT_MAGIC_BE):
        return buf
    # Fat header is always big-endian
    nfat = struct.unpack('>I', buf[4:8])[0]
    if nfat < 1 or len(buf) < 8 + 20:
        return buf
    # First fat_arch entry: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
    offset = struct.unpack('>I', buf[16:20])[0]
    size = struct.unpack('>I', buf[20:24])[0]
    if offset + size <= len(buf):
        return buf[offset:offset + size]
    return buf


# ---------------------------------------------------------------------------
# Section
# ---------------------------------------------------------------------------

class Section(KaitaiStruct):
    def __init__(self, is64, is_be, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._is64 = is64
        self._is_be = is_be
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        be = self._is_be
        u4 = io.read_u4be if be else io.read_u4le
        u8 = io.read_u8be if be else io.read_u8le
        uw = u8 if self._is64 else u4

        raw_sect = rd(lambda: io.read_bytes(16), "sectname")
        self.sectname = _strip_null(raw_sect)
        raw_seg = rd(lambda: io.read_bytes(16), "segname")
        self.segname = _strip_null(raw_seg)
        self.addr = rd(uw, "addr")
        self.size = rd(uw, "size")
        self.offset = rd(u4, "offset")
        self.align = rd(u4, "align")
        self.reloff = rd(u4, "reloff")
        self.nreloc = rd(u4, "nreloc")
        self.flags = rd(u4, "flags")
        self.reserved1 = rd(u4, "reserved1")
        self.reserved2 = rd(u4, "reserved2")
        if self._is64:
            self.reserved3 = rd(u4, "reserved3")


# ---------------------------------------------------------------------------
# LoadCommand
# ---------------------------------------------------------------------------

class LoadCommand(KaitaiStruct):
    def __init__(self, is64, is_be, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._is64 = is64
        self._is_be = is_be
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        be = self._is_be
        u4 = io.read_u4be if be else io.read_u4le
        u8 = io.read_u8be if be else io.read_u8le
        uw = u8 if self._is64 else u4

        cmd_start = io.pos()
        raw_type = rd(u4, "type")
        self.type = _safe_enum(LoadCommandType, raw_type)
        self.size = rd(u4, "size")

        self.sections = []
        self.body = None

        try:
            raw_cmd = raw_type if isinstance(raw_type, int) else int(raw_type)
            is_segment = raw_cmd in (
                LoadCommandType.SEGMENT, LoadCommandType.SEGMENT_64)

            if is_segment:
                raw_seg = rd(lambda: io.read_bytes(16), "segname")
                self.segname = _strip_null(raw_seg)
                self.vmaddr = rd(uw, "vmaddr")
                self.vmsize = rd(uw, "vmsize")
                self.fileoff = rd(uw, "fileoff")
                self.filesize = rd(uw, "filesize")
                self.maxprot = rd(u4, "maxprot")
                self.initprot = rd(u4, "initprot")
                self.nsects = rd(u4, "nsects")
                self.flags = rd(u4, "flags")

                for i in range(self.nsects):
                    sect = Section(
                        self._is64, self._is_be, io, self, self._root)
                    self.sections.append(sect)
                d["sections"] = {"start": d.get("flags", {}).get("end", 0),
                                 "end": io.pos()}
            elif raw_cmd == LoadCommandType.UUID:
                self.uuid = rd(lambda: io.read_bytes(16), "uuid")
            else:
                # Skip remaining bytes of this load command
                consumed = io.pos() - cmd_start
                remaining = self.size - consumed
                if remaining > 0:
                    self.body = rd(
                        lambda: io.read_bytes(remaining), "body")
        except Exception:
            pass  # partial parse is acceptable

        # Ensure stream is positioned at end of this command
        try:
            io.seek(cmd_start + self.size)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# MachO (top-level)
# ---------------------------------------------------------------------------

class MachO(KaitaiStruct):
    """Mach-O binary format parser (32+64 bit, LE+BE).

    Follows Kaitai Struct runtime conventions with _debug position tracking.
    """

    # Re-export enums and sub-types as class attributes
    CpuType = CpuType
    FileType = FileType
    LoadCommandType = LoadCommandType
    LoadCommand = LoadCommand
    Section = Section

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

        # Read magic as little-endian u4 to detect endianness
        raw_magic = rd(io.read_u4le, "magic")

        if raw_magic not in _VALID_MAGICS:
            raise ValueError(
                f"Expected Mach-O magic, got 0x{raw_magic:08X}")

        is_be = raw_magic in (MAGIC_32_BE, MAGIC_64_BE)
        is64 = raw_magic in (MAGIC_64_LE, MAGIC_64_BE)
        self._is_be = is_be
        self._is64 = is64

        # Canonical magic value (always native byte order)
        self.magic = MAGIC_64_LE if is64 else MAGIC_32_LE

        u4 = io.read_u4be if is_be else io.read_u4le

        raw_cpu = rd(u4, "cputype")
        self.cputype = _safe_enum(CpuType, raw_cpu)
        self.cpusubtype = rd(u4, "cpusubtype")

        raw_ft = rd(u4, "filetype")
        self.filetype = _safe_enum(FileType, raw_ft)

        self.ncmds = rd(u4, "ncmds")
        self.sizeofcmds = rd(u4, "sizeofcmds")
        self.flags = rd(u4, "flags")

        if is64:
            self.reserved = rd(u4, "reserved")

        # Parse load commands
        self.load_commands = []
        try:
            cmds_start = io.pos()
            for _ in range(self.ncmds):
                lc = LoadCommand(is64, is_be, io, self, self._root)
                self.load_commands.append(lc)
            d["load_commands"] = {"start": cmds_start, "end": io.pos()}
        except Exception:
            pass  # partial parse is acceptable

    @classmethod
    def from_file(cls, filename):
        """Parse a Mach-O file from a filesystem path.

        Automatically unwraps fat/universal binaries (uses first slice).
        """
        with open(filename, "rb") as f:
            buf = _unwrap_fat(f.read())
        return cls(KaitaiStream(BytesIO(buf)))

    @classmethod
    def from_bytes(cls, buf):
        """Parse Mach-O from an in-memory bytes buffer.

        Automatically unwraps fat/universal binaries (uses first slice).
        """
        return cls(KaitaiStream(BytesIO(_unwrap_fat(buf))))
