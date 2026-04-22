"""Hand-rolled Kaitai Struct parser for Memory Slice (.msl) files.

Implements the Memory Slice v1.1.0 container format (see
``docs/file_formats/msl_v1_1_0.md``) as a pair of ``KaitaiStruct``
classes.  Tracks field positions via ``_debug`` dicts so
``KaitaiOverlayAdapter`` can emit hex-viewer overlays identical to the
compiled Kaitai parsers used for ELF / PE / Mach-O.
"""

from enum import IntEnum

from kaitaistruct import KaitaiStream, KaitaiStruct, BytesIO

from msl.enums import BLOCK_MAGIC, BlockType, FILE_HEADER_SIZE, FILE_MAGIC

_MAX_BLOCKS = 10_000
_BLOCK_HEADER_SIZE = 80
_ENCRYPTED_FLAG_BIT = 1 << 2


class BlockTypeId(IntEnum):
    """Mirror of :class:`msl.enums.BlockType` for overlay rendering."""
    INVALID = 0x0000
    MEMORY_REGION = 0x0001
    MODULE_ENTRY = 0x0002
    MODULE_LIST_INDEX = 0x0010
    THREAD_CONTEXT = 0x0011
    FILE_DESCRIPTOR = 0x0012
    NETWORK_CONNECTION = 0x0013
    ENVIRONMENT_BLOCK = 0x0014
    SECURITY_TOKEN = 0x0015
    KEY_HINT = 0x0020
    IMPORT_PROVENANCE = 0x0030
    PROCESS_IDENTITY = 0x0040
    RELATED_DUMP = 0x0041
    SYSTEM_CONTEXT = 0x0050
    PROCESS_TABLE = 0x0051
    CONNECTION_TABLE = 0x0052
    HANDLE_TABLE = 0x0053
    CONNECTIVITY_TABLE = 0x0055
    END_OF_CAPTURE = 0x0FFF
    VAS_MAP = 0x1001
    POINTER_GRAPH = 0x1003


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


def _endian_readers(io, is_be):
    """Return (u2, u4, u8) readers for the requested endianness."""
    if is_be:
        return io.read_u2be, io.read_u4be, io.read_u8be
    return io.read_u2le, io.read_u4le, io.read_u8le


class FileHeader(KaitaiStruct):
    """Top-of-file 64-byte header (spec §3.1)."""

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

        self.magic = rd(lambda: io.read_bytes(8), "magic")
        if self.magic != FILE_MAGIC:
            raise ValueError(f"Bad MSL magic: {self.magic!r}")

        self.endianness = rd(io.read_u1, "endianness")
        self.header_size = rd(io.read_u1, "header_size")

        is_be = self.endianness == 2
        u2, u4, u8 = _endian_readers(io, is_be)
        self._is_be = is_be

        self.version = rd(u2, "version")
        self.flags = rd(u4, "flags")
        if self.flags & _ENCRYPTED_FLAG_BIT:
            raise ValueError("Encrypted MSL not supported")

        self.cap_bitmap = rd(u8, "cap_bitmap")
        self.dump_uuid = rd(lambda: io.read_bytes(16), "dump_uuid")
        self.timestamp_ns = rd(u8, "timestamp_ns")
        self.os_type = rd(u2, "os_type")
        self.arch_type = rd(u2, "arch_type")
        self.pid = rd(u4, "pid")
        self.clock_source = rd(io.read_u1, "clock_source")

        reserved_len = max(0, int(self.header_size) - 57)
        self.reserved = rd(
            lambda: io.read_bytes(reserved_len), "reserved",
        )

    @property
    def version_major(self):
        return (int(self.version) >> 8) & 0xFF

    @property
    def version_minor(self):
        return int(self.version) & 0xFF


class Block(KaitaiStruct):
    """An 80-byte MSLC block header plus raw payload bytes."""

    def __init__(self, is_be, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._is_be = is_be
        self._read()

    def _read(self):
        d = self._debug
        io = self._io
        rd = lambda r, n: _read_debug(io, r, n, d)
        u2, u4, _u8 = _endian_readers(io, self._is_be)

        self.magic = rd(lambda: io.read_bytes(4), "magic")
        if self.magic != BLOCK_MAGIC:
            raise ValueError(f"Bad MSLC magic: {self.magic!r}")

        raw_type = rd(u2, "block_type")
        self.block_type = _safe_enum(BlockTypeId, raw_type)
        self.flags = rd(u2, "flags")
        self.block_length = rd(u4, "block_length")
        self.payload_version = rd(u2, "payload_version")
        self.padding = rd(lambda: io.read_bytes(2), "padding")
        self.block_uuid = rd(lambda: io.read_bytes(16), "block_uuid")
        self.parent_uuid = rd(lambda: io.read_bytes(16), "parent_uuid")
        self.prev_hash = rd(lambda: io.read_bytes(32), "prev_hash")

        payload_len = max(0, int(self.block_length) - _BLOCK_HEADER_SIZE)
        remaining = io.size() - io.pos()
        if payload_len > remaining:
            payload_len = remaining
        self.payload = rd(
            lambda: io.read_bytes(payload_len), "payload",
        )


class MslV1(KaitaiStruct):
    """Top-level Memory Slice v1 container."""

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        self._debug = {}
        self._read()

    def _read(self):
        d = self._debug
        io = self._io

        hdr_start = io.pos()
        self.file_header = FileHeader(io, _parent=self, _root=self._root)
        d["file_header"] = {"start": hdr_start, "end": io.pos()}

        is_be = getattr(self.file_header, "_is_be", False)
        self.blocks = self._read_blocks(io, is_be)

        if self.blocks:
            d["blocks"] = {
                "start": FILE_HEADER_SIZE,
                "end": io.pos(),
            }

    def _read_blocks(self, io, is_be):
        blocks = []
        while not io.is_eof() and len(blocks) < _MAX_BLOCKS:
            try:
                block = Block(is_be, io, _parent=self, _root=self._root)
            except (ValueError, EOFError):
                break
            blocks.append(block)
        return blocks
