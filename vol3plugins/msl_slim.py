"""A slim, standard-library-only Memory Slice (``.msl``) reader.

``msl_layer`` opens captures through MemDiver (``memdiver.open_dump``) whenever MemDiver is
importable; that stays the preferred path. This module is its fallback for a Python that has
stock Volatility 3 but no MemDiver: it reads exactly what ``msl_layer.MslSlice`` needs, with
the same answers as MemDiver's ``msl.reader.MslReader`` (``tests/test_vol3plugins_msl_slim.py``
compares both readers region by region and byte by byte on real captures).

Supported (MSL spec v1.1.0, newest ``Memory_Slice_Specification-N.pdf``):

* plaintext containers, format major version 1, little-endian (the only legal byte order);
* uncompressed MEMORY_REGION (0x0001) blocks with the four page states of section 7:
  Captured, Failed, Unmapped, NotResident;
* PROCESS_IDENTITY (0x0040) and capture-segment VAS_MAP (0x1001) blocks, continuation
  blocks merged the way MemDiver merges them;
* MODULE_ENTRY (0x0002), MODULE_LIST_INDEX (0x0010), THREAD_CONTEXT (0x0011), KEY_HINT
  (0x0020), IMPORT_PROVENANCE (0x0030) and END_OF_CAPTURE (0x0FFF) blocks, decoded lazily
  (a compressed one raises :class:`MslSlimUnsupported` only when asked for, so it never
  stops a capture from stacking); the decoded objects carry the same attribute names as
  MemDiver's (``tests/test_vol3plugins_msl_slim.py`` compares them block by block);
* the capture-segment hash chain and the extension segments (spec 4.6) of a plaintext
  container: :func:`verify_container` checks them with ``hashlib`` for SHA-256 and
  SHA-512/256 and raises :class:`MslSlimHashUnavailable` for BLAKE3, the default, unless the
  caller hands it a ``blake3`` module;
* every other block type is skipped unread.

Not supported, each failing with :class:`MslSlimUnsupported` whose message says to
``pip install memdiver``:

* encrypted containers (header flag Encrypted): AES-256-GCM / XChaCha20-Poly1305 under
  Argon2id, X25519 or ML-KEM and HKDF-BLAKE3 (spec 10). None of these is in the standard
  library;
* compressed region, identity or VAS-map blocks: the spec defines zstd and lz4 only
  (``CompAlgo`` in the block flags), neither of which the standard library decodes.

Integrity: opening a capture does NOT verify the PrevHash chain or the End-of-Capture
FileHash (MemDiver's layer path does not either); call :func:`verify_container` for that.
Extension segments after the End-of-Capture block (spec 4.6) are not read for data;
MemDiver takes a VAS map from a *verified* segment, so a file carrying one can show a
different ``region_map`` here (logged once).

Import rule: module level imports the standard library only (no ``volatility3`` either), and
the module never reads ``__file__``, so it can be imported on its own or pasted elsewhere.
"""

import hashlib
import logging
import mmap
import os
import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import (Any, BinaryIO, Callable, Dict, Iterator, List, NamedTuple, Optional,
                    Tuple)

vollog = logging.getLogger(__name__)

FILE_MAGIC = b"MEMSLICE"
BLOCK_MAGIC = b"MSLC"
FILE_HEADER_SIZE = 64
BLOCK_HEADER_SIZE = 80
REGION_HEADER_SIZE = 0x20
SUPPORTED_MAJOR_VERSION = 1
LITTLE_ENDIAN = 0x01

HEADER_FLAG_IMPORTED = 1 << 0
HEADER_FLAG_ENCRYPTED = 1 << 2
CAPBIT_PAGE_STATES_INFERRED = 1 << 15
BLOCK_FLAG_COMPRESSED = 1 << 0
BLOCK_FLAG_HAS_CHILDREN = 1 << 4
BLOCK_FLAG_CONTINUATION = 1 << 5

MEMORY_REGION = 0x0001
MODULE_ENTRY = 0x0002
MODULE_LIST_INDEX = 0x0010
THREAD_CONTEXT = 0x0011
KEY_HINT = 0x0020
IMPORT_PROVENANCE = 0x0030
PROCESS_IDENTITY = 0x0040
END_OF_EXTENSION = 0x0FFE
END_OF_CAPTURE = 0x0FFF
VAS_MAP = 0x1001
#: Block types ``open()`` refuses when compressed: the ones ``msl_layer`` needs. The other
#: decoded types fail only when their collector runs (see ``MslSlimReader._collect``).
DECODED_BLOCK_TYPES = (MEMORY_REGION, PROCESS_IDENTITY, VAS_MAP)
ZERO_HASH = b"\x00" * 32

CAPTURED, FAILED, UNMAPPED, NOT_RESIDENT = 0b00, 0b01, 0b10, 0b11

INSTALL_HINT = "pip install memdiver (MemDiver's reader opens it)"


class OSType(IntEnum):
    """Header ``OSType`` codes (spec Table 3), names as MemDiver's ``msl.enums``."""

    WINDOWS = 0x0000
    LINUX = 0x0001
    MACOS = 0x0002
    ANDROID = 0x0003
    IOS = 0x0004
    FREEBSD = 0x0005
    UNKNOWN = 0xFFFF


class ArchType(IntEnum):
    """Header ``ArchType`` codes (spec Table 3), names as MemDiver's ``msl.enums``."""

    X86 = 0x0000
    X86_64 = 0x0001
    ARM64 = 0x0002
    ARM32 = 0x0003
    UNKNOWN = 0xFFFF


class PageState(IntEnum):
    """Page states (spec Table 35); names and codes as MemDiver's ``msl.enums.PageState``."""

    CAPTURED = 0b00
    FAILED = 0b01
    UNMAPPED = 0b10
    NOT_RESIDENT = 0b11


class RegionType(IntEnum):
    """Region types (spec Table 15), as MemDiver's ``msl.enums.RegionType``."""

    UNKNOWN = 0x00
    HEAP = 0x01
    STACK = 0x02
    IMAGE = 0x03
    MAPPED_FILE = 0x04
    ANONYMOUS = 0x05
    SHARED_MEM = 0x06
    OTHER = 0xFF


class KeyType(IntEnum):
    """Key types (spec Table 21), as MemDiver's ``msl.enums.MslKeyType``."""

    UNKNOWN = 0x0000
    PRE_MASTER_SECRET = 0x0001
    MASTER_SECRET = 0x0002
    SESSION_KEY = 0x0003
    HANDSHAKE_SECRET = 0x0004
    APP_TRAFFIC_SECRET = 0x0005
    RSA_PRIVATE_KEY = 0x0006
    ECDH_PRIVATE_KEY = 0x0007
    IKE_SA_KEY = 0x0008
    ESP_AH_KEY = 0x0009
    SSH_SESSION_KEY = 0x000A
    WIREGUARD_KEY = 0x000B
    ML_KEM_PRIVATE_KEY = 0x000C
    OTHER = 0xFFFF


class Protocol(IntEnum):
    """Protocol codes (spec Table 21), as MemDiver's ``msl.enums.MslProtocol``."""

    UNKNOWN = 0x0000
    TLS_12 = 0x0001
    TLS_13 = 0x0002
    DTLS_12 = 0x0003
    DTLS_13 = 0x0004
    QUIC = 0x0005
    IKEV2_IPSEC = 0x0006
    SSH = 0x0007
    WIREGUARD = 0x0008
    PQ_TLS = 0x0009
    OTHER = 0xFFFF


class Confidence(IntEnum):
    SPECULATIVE = 0x00
    HEURISTIC = 0x01
    CONFIRMED = 0x02


class KeyState(IntEnum):
    UNKNOWN = 0x00
    ACTIVE = 0x01
    EXPIRED = 0x02


class ThreadState(IntEnum):
    """Thread scheduler state (spec Table 22), as MemDiver's ``msl.enums.ThreadState``."""

    UNKNOWN = 0x00
    RUNNING = 0x01
    SLEEPING = 0x02
    STOPPED = 0x03
    WAITING = 0x04
    UNINTERRUPTIBLE = 0x05
    HALTED = 0x06
    ZOMBIE = 0x07


class CompAlgo(IntEnum):
    NONE = 0
    ZSTD = 1
    LZ4 = 2


class HashAlgo(IntEnum):
    """Integrity hash selector (header 0x3D, spec Table 12), as MemDiver's ``HashAlgo``."""

    BLAKE3 = 0x00
    SHA256 = 0x01
    SHA512_256 = 0x02
    OTHER = 0xFF


class SourceFormat(IntEnum):
    """IMPORT_PROVENANCE source formats, as MemDiver's ``msl.enums.SourceFormat``."""

    RAW_DUMP = 0x01
    ELF_CORE = 0x02
    MINIDUMP = 0x03
    MSL = 0x04
    REGIONED_RAW = 0x05
    OTHER = 0xFFFF


class MslSlimError(ValueError):
    """A file this reader cannot parse (not an MSL file, corrupt, truncated)."""


class MslSlimUnsupported(MslSlimError):
    """A valid MSL feature the standard library cannot serve (encryption, zstd/lz4)."""


class FileHeader(NamedTuple):
    """The 64-byte file header (spec 3.1), fields named as MemDiver's ``MslFileHeader``."""

    endianness: int
    header_size: int
    version_major: int
    version_minor: int
    flags: int
    cap_bitmap: int
    dump_uuid: uuid.UUID
    timestamp_ns: int
    os_type: int
    arch_type: int
    pid: int
    clock_source: int
    block_count: int
    hash_algo: int

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & HEADER_FLAG_ENCRYPTED)

    @property
    def imported(self) -> bool:
        return bool(self.flags & HEADER_FLAG_IMPORTED)

    @property
    def page_states_inferred(self) -> bool:
        return bool(self.cap_bitmap & CAPBIT_PAGE_STATES_INFERRED)


class BlockHeader(NamedTuple):
    """An 80-byte block header (spec 4.1); offsets are absolute file offsets."""

    block_type: int
    flags: int
    block_length: int
    payload_version: int
    block_uuid: uuid.UUID
    parent_uuid: uuid.UUID
    file_offset: int
    payload_offset: int
    prev_hash: bytes = ZERO_HASH

    @property
    def payload_length(self) -> int:
        return self.block_length - BLOCK_HEADER_SIZE

    @property
    def compressed(self) -> bool:
        return bool(self.flags & BLOCK_FLAG_COMPRESSED)

    @property
    def comp_algo(self) -> CompAlgo:
        code = (self.flags >> 1) & 0x03
        return CompAlgo(code) if code in set(CompAlgo) else CompAlgo.NONE


@dataclass(frozen=True)
class PageInterval:
    """A run of ``count`` pages from ``start_page`` in one page ``state`` (as MemDiver's)."""

    start_page: int
    count: int
    state: int


class MemoryRegion(NamedTuple):
    """A decoded MEMORY_REGION header and page-state map (spec Table 11)."""

    block_header: BlockHeader
    base_addr: int
    region_size: int
    protection: int
    region_type: int
    page_size_log2: int
    timestamp_ns: int
    page_intervals: Tuple[PageInterval, ...]

    @property
    def page_size(self) -> int:
        return 1 << self.page_size_log2

    @property
    def num_pages(self) -> int:
        return self.region_size // self.page_size

    @property
    def captured_pages(self) -> int:
        return sum(iv.count for iv in self.page_intervals if iv.state == CAPTURED)


class CapturedRun(NamedTuple):
    """One run of CAPTURED pages (as MemDiver's ``msl.reader.CapturedRun``).

    ``block`` is always ``None`` here: compressed regions are unsupported, so ``buf_offset``
    is a file offset.
    """

    va_start: int
    length: int
    buf_offset: int
    avail: int
    vas_offset: int
    block: Optional[BlockHeader] = None


class CapturedRunIndex(NamedTuple):
    """Runs in vas-stream order and in VA order, with their bisect keys."""

    runs: Tuple[CapturedRun, ...]
    by_va: Tuple[CapturedRun, ...]
    va_starts: Tuple[int, ...]
    vas_starts: Tuple[int, ...]


class ProcessIdentity(NamedTuple):
    """A PROCESS_IDENTITY block (spec Table 14)."""

    ppid: int
    session_id: int
    start_time_ns: int
    exe_path: str
    cmd_line: str


class VasEntry(NamedTuple):
    """One VAS_MAP entry (spec 5.8)."""

    base_addr: int
    region_size: int
    protection: int
    region_type: int
    mapped_path: str
    name_source: int


class VasMap(NamedTuple):
    entries: Tuple[VasEntry, ...]


class ModuleEntry(NamedTuple):
    """A MODULE_ENTRY block (spec Table 16); ``native_blob`` is not decoded."""

    block_header: BlockHeader
    base_addr: int
    module_size: int
    path: str
    version: str
    disk_hash: bytes


class ModuleIndexEntry(NamedTuple):
    module_uuid: uuid.UUID
    base_addr: int
    module_size: int
    path: str


class ModuleListIndex(NamedTuple):
    """A MODULE_LIST_INDEX block (spec Table 17); manifest-only ones have no entries."""

    block_header: BlockHeader
    entry_count: int
    entries: Tuple[ModuleIndexEntry, ...]


class KeyHint(NamedTuple):
    """A KEY_HINT block (spec Table 20); ``region_offset`` indexes the region's PageData."""

    block_header: BlockHeader
    region_uuid: uuid.UUID
    region_offset: int
    key_length: int
    key_type: int
    protocol: int
    confidence: int
    key_state: int
    note: str


class ThreadRegister(NamedTuple):
    """One register of a THREAD_CONTEXT block (spec Table 23); ``value`` is raw bytes."""

    name: str
    width: int
    flags: int
    value: bytes

    @property
    def is_pc(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def is_sp(self) -> bool:
        return bool(self.flags & 0x0002)


class ThreadContext(NamedTuple):
    """A THREAD_CONTEXT block (spec Table 22)."""

    block_header: BlockHeader
    thread_id: int
    start_time_ns: int
    flags: int
    state: int
    arch: int
    name: str
    registers: Tuple[ThreadRegister, ...]

    @property
    def current(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def crashed(self) -> bool:
        return bool(self.flags & 0x0002)

    @property
    def suspended(self) -> bool:
        return bool(self.flags & 0x0004)

    @property
    def partial(self) -> bool:
        return bool(self.flags & 0x0008)

    def register(self, name: str) -> Optional[ThreadRegister]:
        wanted = name.lower()
        for reg in self.registers:
            if reg.name == wanted:
                return reg
        return None


class GenericBlock(NamedTuple):
    """A THREAD_CONTEXT too malformed to decode, as MemDiver's ``MslGenericBlock``."""

    block_header: BlockHeader
    payload: bytes


class ImportProvenance(NamedTuple):
    """An IMPORT_PROVENANCE block (spec Table 40)."""

    block_header: BlockHeader
    source_format: int
    tool_name: str
    import_time_ns: int
    orig_file_size: int
    note: str
    source_hash: bytes


class EndOfCapture(NamedTuple):
    """The END_OF_CAPTURE block (spec Table 10)."""

    block_header: BlockHeader
    file_hash: bytes
    acq_end_ns: int
    block_count: int


# ------------------------------------------------------------------------- decoding


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _padded_str(buf: bytes, offset: int, length: int) -> str:
    if length <= 0:
        return ""
    return buf[offset:offset + length].split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _require(payload: bytes, end: int, what: str) -> None:
    if end > len(payload):
        raise MslSlimError(f"truncated {what}: needs {end} bytes, payload has {len(payload)}")


def decode_page_intervals(data: bytes, num_pages: int) -> Tuple[PageInterval, ...]:
    """Run-length page states from a 2-bit-per-page map (MSB first, spec section 7).

    Pages past the end of ``data`` are Failed, as in MemDiver. Works byte by byte and
    jumps over the missing tail in one step, so a huge ``RegionSize`` cannot stall it.
    A byte whose four pages all continue the current run (``state * 0x55``: 0x00,
    0x55, 0xAA, 0xFF) is skipped without decoding its slots.
    """
    intervals: List[PageInterval] = []
    state, start = -1, 0
    covered = min(num_pages, len(data) * 4)
    for page in range(0, covered, 4):
        byte = data[page // 4]
        if byte == state * 0x55:
            continue
        for slot in range(min(4, covered - page)):
            bits = (byte >> (6 - 2 * slot)) & 0x03
            if bits != state:
                if state >= 0:
                    intervals.append(PageInterval(start, page + slot - start, state))
                state, start = bits, page + slot
    if covered < num_pages and state != FAILED:
        if state >= 0:
            intervals.append(PageInterval(start, covered - start, state))
        state, start = FAILED, covered
    if state >= 0:
        intervals.append(PageInterval(start, num_pages - start, state))
    return tuple(intervals)


def decode_memory_region(hdr: BlockHeader, head: bytes) -> MemoryRegion:
    """A region from its fixed header plus page-state map (no page data needed)."""
    _require(head, REGION_HEADER_SIZE, "MEMORY_REGION header")
    base_addr, region_size = struct.unpack_from("<QQ", head, 0)
    protection, region_type, page_size_log2 = head[0x10], head[0x11], head[0x12]
    if not 10 <= page_size_log2 <= 40:
        raise MslSlimError(f"page_size_log2={page_size_log2} out of spec range [10, 40]")
    timestamp_ns = struct.unpack_from("<Q", head, 0x18)[0]
    num_pages = region_size >> page_size_log2
    map_data = head[REGION_HEADER_SIZE:REGION_HEADER_SIZE + _pad8((num_pages + 3) // 4)]
    return MemoryRegion(hdr, base_addr, region_size, protection, region_type, page_size_log2,
                        timestamp_ns, decode_page_intervals(map_data, num_pages))


def decode_process_identity(payload: bytes) -> ProcessIdentity:
    ppid, session_id, start_time = struct.unpack_from("<IIQ", payload, 0)
    exe_len, cmd_len = struct.unpack_from("<HH", payload, 0x10)
    exe_path = _padded_str(payload, 0x18, exe_len)
    cmd_line = _padded_str(payload, 0x18 + _pad8(exe_len), cmd_len)
    return ProcessIdentity(ppid, session_id, start_time, exe_path, cmd_line)


def decode_vas_map(payload: bytes) -> VasMap:
    _require(payload, 8, "VAS_MAP header")
    entry_count, entry_size = struct.unpack_from("<II", payload, 0)
    entries = []
    offset = 8
    for index in range(entry_count):
        _require(payload, offset + 0x18, f"VAS_MAP entry {index}")
        base_addr, region_size = struct.unpack_from("<QQ", payload, offset)
        path_len = struct.unpack_from("<H", payload, offset + 0x12)[0]
        _require(payload, offset + 0x18 + path_len, f"VAS_MAP entry {index} path")
        entries.append(VasEntry(base_addr, region_size, payload[offset + 0x10],
                                payload[offset + 0x11],
                                _padded_str(payload, offset + 0x18, path_len),
                                payload[offset + 0x14]))
        offset += entry_size if entry_size > 0 else 0x18 + _pad8(path_len)
    return VasMap(tuple(entries))


def decode_module_entry(hdr: BlockHeader, payload: bytes) -> ModuleEntry:
    _require(payload, 0x18, "MODULE_ENTRY header")
    base_addr, module_size = struct.unpack_from("<QQ", payload, 0)
    path_len, version_len = struct.unpack_from("<HH", payload, 0x10)
    offset = 0x18
    path = _padded_str(payload, offset, path_len)
    offset += _pad8(path_len)
    version = _padded_str(payload, offset, version_len)
    offset += _pad8(version_len)
    return ModuleEntry(hdr, base_addr, module_size, path, version,
                       bytes(payload[offset:offset + 32]))


def _advance_str(raw_len: int) -> int:
    """Bytes a string field of raw length ``raw_len`` consumes: none when empty, else pad8."""
    return 0 if raw_len == 0 else _pad8(raw_len)


def decode_module_list_index(hdr: BlockHeader, payload: bytes) -> ModuleListIndex:
    """Inline (spec Variant A) or manifest-only (8-byte payload) module list index."""
    _require(payload, 8, "MODULE_LIST_INDEX header")
    entry_count = struct.unpack_from("<I", payload, 0)[0]
    if len(payload) == 8:
        return ModuleListIndex(hdr, entry_count, ())
    entries, offset = [], 8
    for index in range(entry_count):
        _require(payload, offset + 0x28, f"MODULE_LIST_INDEX entry {index}")
        module_uuid = uuid.UUID(bytes=bytes(payload[offset:offset + 16]))
        base_addr, module_size = struct.unpack_from("<QQ", payload, offset + 0x10)
        path_len = struct.unpack_from("<H", payload, offset + 0x20)[0]
        str_offset = offset + 0x28
        _require(payload, str_offset + _advance_str(path_len),
                 f"MODULE_LIST_INDEX entry {index} path")
        entries.append(ModuleIndexEntry(module_uuid, base_addr, module_size,
                                        _padded_str(payload, str_offset, path_len)))
        offset = str_offset + _advance_str(path_len)
    return ModuleListIndex(hdr, entry_count, tuple(entries))


def decode_key_hint(hdr: BlockHeader, payload: bytes) -> KeyHint:
    _require(payload, 0x28, "KEY_HINT header")
    region_offset, key_length, key_type, protocol = struct.unpack_from("<QIHH", payload, 0x10)
    note_len = struct.unpack_from("<I", payload, 0x24)[0]
    note = _padded_str(payload, 0x2C, note_len) if note_len > 0 else ""
    return KeyHint(hdr, uuid.UUID(bytes=bytes(payload[0:16])), region_offset, key_length,
                   key_type, protocol, payload[0x20], payload[0x21], note)


THREAD_CONTEXT_HEAD_SIZE = 0x20
THREAD_REGISTER_HEAD_SIZE = 0x08


def decode_thread_context(hdr: BlockHeader, payload: bytes) -> Any:
    """A :class:`ThreadContext`, or a :class:`GenericBlock` when the payload is malformed."""
    try:
        return _decode_thread_context_strict(hdr, payload)
    except (MslSlimError, struct.error, IndexError, UnicodeDecodeError):
        return GenericBlock(hdr, bytes(payload))


def _decode_thread_context_strict(hdr: BlockHeader, payload: bytes) -> ThreadContext:
    _require(payload, THREAD_CONTEXT_HEAD_SIZE, "THREAD_CONTEXT head")
    tid, start_ns, flags, state, arch, reg_count, name_len = struct.unpack_from(
        "<QQHBBIH", payload, 0)
    offset = THREAD_CONTEXT_HEAD_SIZE
    _require(payload, offset + name_len, "THREAD_CONTEXT name")
    name = _padded_str(payload, offset, name_len)
    offset += _pad8(name_len)
    registers = []
    for _ in range(reg_count):
        register, offset = _decode_thread_register(payload, offset)
        registers.append(register)
    return ThreadContext(hdr, tid, start_ns, flags, state, arch, name, tuple(registers))


def _decode_thread_register(payload: bytes, offset: int) -> Tuple[ThreadRegister, int]:
    _require(payload, offset + THREAD_REGISTER_HEAD_SIZE, "THREAD_CONTEXT register")
    name_len, width, flags = struct.unpack_from("<BBH", payload, offset)
    offset += THREAD_REGISTER_HEAD_SIZE
    _require(payload, offset + name_len, "THREAD_CONTEXT register name")
    name = _padded_str(payload, offset, name_len)
    offset += _pad8(name_len)
    _require(payload, offset + width, "THREAD_CONTEXT register value")
    value = bytes(payload[offset:offset + width])
    return ThreadRegister(name, width, flags, value), offset + _pad8(width)


def decode_import_provenance(hdr: BlockHeader, payload: bytes) -> ImportProvenance:
    _require(payload, 0x20, "IMPORT_PROVENANCE header")
    source_format = struct.unpack_from("<H", payload, 0)[0]
    tool_name_len = struct.unpack_from("<I", payload, 4)[0]
    import_time, orig_size = struct.unpack_from("<QQ", payload, 8)
    note_len = struct.unpack_from("<I", payload, 0x18)[0]
    offset = 0x20
    tool_name = _padded_str(payload, offset, tool_name_len)
    offset += _pad8(tool_name_len)
    note = _padded_str(payload, offset, note_len) if note_len > 0 else ""
    hash_offset = offset + (_pad8(note_len) if note_len > 0 else 0)
    source_hash = (bytes(payload[hash_offset:hash_offset + 32])
                   if len(payload) >= hash_offset + 32 else ZERO_HASH)
    return ImportProvenance(hdr, source_format, tool_name, import_time, orig_size, note,
                            source_hash)


def decode_end_of_capture(hdr: BlockHeader, payload: bytes) -> EndOfCapture:
    """FileHash(32) AcqEnd(8) BlockCount(4); the legacy 40-byte form has no count."""
    _require(payload, 0x28, "END_OF_CAPTURE")
    acq_end = struct.unpack_from("<Q", payload, 0x20)[0]
    block_count = struct.unpack_from("<I", payload, 0x28)[0] if len(payload) >= 0x2C else 0
    return EndOfCapture(hdr, bytes(payload[0:32]), acq_end, block_count)


def parse_file_header(raw: bytes) -> FileHeader:
    """The file header, rejecting what MemDiver's reader rejects (spec 3.1, 3.4)."""
    if len(raw) < FILE_HEADER_SIZE:
        raise MslSlimError(f"file too small for an MSL header: {len(raw)} bytes")
    if raw[:8] != FILE_MAGIC:
        raise MslSlimError(f"bad magic {raw[:8]!r}: not a Memory Slice (.msl) file")
    if raw[8] != LITTLE_ENDIAN:
        raise MslSlimError(f"invalid Endianness 0x{raw[8]:02X} (spec 3.1 requires 0x01)")
    version = struct.unpack_from("<H", raw, 0x0A)[0]
    if version >> 8 != SUPPORTED_MAJOR_VERSION:
        raise MslSlimError(f"unsupported MSL major version {version >> 8}")
    flags, cap_bitmap = struct.unpack_from("<IQ", raw, 0x0C)
    timestamp_ns, os_type, arch_type, pid = struct.unpack_from("<QHHI", raw, 0x28)
    return FileHeader(
        endianness=raw[8], header_size=raw[9], version_major=version >> 8,
        version_minor=version & 0xFF, flags=flags, cap_bitmap=cap_bitmap,
        dump_uuid=uuid.UUID(bytes=bytes(raw[0x18:0x28])), timestamp_ns=timestamp_ns,
        os_type=os_type, arch_type=arch_type, pid=pid, clock_source=raw[0x38],
        block_count=struct.unpack_from("<I", raw, 0x39)[0], hash_algo=raw[0x3D])


def parse_block_header(raw: bytes, offset: int) -> BlockHeader:
    block_type, flags, block_length, payload_version = struct.unpack_from("<HHIH", raw, 4)
    return BlockHeader(block_type, flags, block_length, payload_version,
                       uuid.UUID(bytes=bytes(raw[0x10:0x20])),
                       uuid.UUID(bytes=bytes(raw[0x20:0x30])),
                       offset, offset + BLOCK_HEADER_SIZE, bytes(raw[0x30:0x50]))


def merge_order(headers: List[BlockHeader]) -> List[BlockHeader]:
    """Parent headers in the order MemDiver's ``merge_continuations`` emits them.

    A HAS_CHILDREN parent is held back until the end of the stream (or until a later
    parent reuses its uuid); its continuations are absorbed; orphaned continuations and
    leaf blocks pass through where they occur.
    """
    out: List[BlockHeader] = []
    pending: Dict[uuid.UUID, BlockHeader] = {}
    for hdr in headers:
        if hdr.flags & BLOCK_FLAG_CONTINUATION:
            if hdr.parent_uuid not in pending:
                out.append(hdr)
        elif hdr.flags & BLOCK_FLAG_HAS_CHILDREN:
            if hdr.block_uuid in pending:
                out.append(pending.pop(hdr.block_uuid))
            pending[hdr.block_uuid] = hdr
        else:
            out.append(hdr)
    out.extend(pending.values())
    return out


def merged_payloads(headers: List[BlockHeader],
                    read: Callable[[BlockHeader], bytes]) -> Iterator[Tuple[BlockHeader, bytes]]:
    """``(parent header, payload with its continuations appended)`` in merge order."""
    pending: Dict[uuid.UUID, Tuple[BlockHeader, List[bytes]]] = {}
    for hdr in headers:
        if hdr.flags & BLOCK_FLAG_CONTINUATION and hdr.parent_uuid in pending:
            pending[hdr.parent_uuid][1].append(read(hdr))
        elif hdr.flags & BLOCK_FLAG_HAS_CHILDREN and not hdr.flags & BLOCK_FLAG_CONTINUATION:
            if hdr.block_uuid in pending:
                parent, parts = pending.pop(hdr.block_uuid)
                yield parent, b"".join(parts)
            pending[hdr.block_uuid] = (hdr, [read(hdr)])
        else:
            yield hdr, read(hdr)
    for parent, parts in pending.values():
        yield parent, b"".join(parts)


# --------------------------------------------------------------------------- reader


class MslSlimReader:
    """Read-only view of one plaintext ``.msl`` (a subset of MemDiver's ``MslReader`` API).

    ``open()`` maps the file, parses the header and walks the capture-segment block chain
    once, raising :class:`MslSlimError` / :class:`MslSlimUnsupported` for anything it
    cannot serve. All later calls are pure lookups or bounded slices of the map.
    """

    def __init__(self, path: str, allow_compressed: bool = False) -> None:
        """``allow_compressed`` skips the open-time refusal of compressed blocks, for callers
        that never decode them (:func:`verify_container` hashes the bytes as stored)."""
        self.path = path
        self._allow_compressed = allow_compressed
        self._file: Optional[BinaryIO] = None
        self._mmap: Optional[mmap.mmap] = None
        self._header: Optional[FileHeader] = None
        self._blocks: List[BlockHeader] = []
        self._regions: Optional[List[MemoryRegion]] = None
        self._run_index: Optional[CapturedRunIndex] = None
        self._identities: Optional[List[ProcessIdentity]] = None
        self._vas_maps: Optional[List[VasMap]] = None
        self._modules: Optional[List[ModuleEntry]] = None
        self._module_indexes: Optional[List[ModuleListIndex]] = None
        self._key_hints: Optional[List[KeyHint]] = None
        self._thread_contexts: Optional[list] = None
        self._provenance: Optional[List[ImportProvenance]] = None
        self._end_of_capture: Optional[List[EndOfCapture]] = None

    def open(self) -> "MslSlimReader":
        self._file = handle = open(self.path, "rb")
        try:
            size = os.fstat(handle.fileno()).st_size
            header = parse_file_header(handle.read(FILE_HEADER_SIZE))
            if header.encrypted:
                raise MslSlimUnsupported(
                    "encrypted .msl (AES-256-GCM / XChaCha20-Poly1305 with Argon2id, X25519 "
                    "or ML-KEM and HKDF-BLAKE3, spec 10): the standard library cannot "
                    f"decrypt it; {INSTALL_HINT}")
            self._mmap = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            self._header = header
            self._blocks = list(self._walk_blocks(self._mmap, size))
            if not self._allow_compressed:
                self._reject_compressed()
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "MslSlimReader":
        return self.open()

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def file_header(self) -> FileHeader:
        if self._header is None:
            raise MslSlimError("reader not opened")
        return self._header

    @property
    def buffer_length(self) -> int:
        return 0 if self._mmap is None else len(self._mmap)

    def _walk_blocks(self, buf: mmap.mmap, size: int) -> Iterator[BlockHeader]:
        """Capture-segment block headers, up to and including End-of-Capture.

        Stops (as MemDiver does) at the end of the file, at bytes that are not a block
        magic, or before a block that runs past the end of the file (a truncated capture).
        """
        offset = self.file_header.header_size
        while offset + BLOCK_HEADER_SIZE <= size:
            raw = buf[offset:offset + BLOCK_HEADER_SIZE]
            if raw[:4] != BLOCK_MAGIC:
                break
            hdr = parse_block_header(raw, offset)
            if hdr.block_length < BLOCK_HEADER_SIZE:
                raise MslSlimError(f"invalid block length {hdr.block_length} at 0x{offset:X}")
            if offset + hdr.block_length > size:
                vollog.warning("%s: truncated block at 0x%X", self.path, offset)
                break
            yield hdr
            offset += hdr.block_length
            if hdr.block_type == END_OF_CAPTURE:
                self._note_extension_bytes(offset, size)
                break

    def _note_extension_bytes(self, end_of_capture: int, size: int) -> None:
        if end_of_capture < size:
            vollog.info("%s: %d bytes after End-of-Capture (extension segments) are not read "
                        "by the slim reader; %s", self.path, size - end_of_capture, INSTALL_HINT)

    def _reject_compressed(self) -> None:
        for hdr in self._blocks:
            if hdr.compressed and hdr.block_type in DECODED_BLOCK_TYPES:
                algo = {1: "zstd", 2: "lz4"}.get((hdr.flags >> 1) & 0x03, "unknown")
                raise MslSlimUnsupported(
                    f"compressed ({algo}) block type 0x{hdr.block_type:04X} at "
                    f"0x{hdr.file_offset:X}: the standard library cannot decode it; "
                    f"{INSTALL_HINT}")

    def read_bytes(self, offset: int, length: int) -> bytes:
        """``length`` file bytes from ``offset``, clamped to the end of the file."""
        if self._mmap is None or length <= 0 or offset < 0:
            return b""
        return self._mmap[offset:min(offset + length, len(self._mmap))]

    #: Same signature as ``MslReader.read_view``; returns ``bytes`` (``bytes(x)`` is free).
    read_view = read_bytes

    def read_block_payload(self, hdr: BlockHeader) -> bytes:
        if hdr.compressed:
            raise MslSlimUnsupported(f"compressed block at 0x{hdr.file_offset:X}; {INSTALL_HINT}")
        return self.read_bytes(hdr.payload_offset, hdr.payload_length)

    def _region_head(self, hdr: BlockHeader) -> bytes:
        """A region block's fixed header plus its padded page-state map, never page data."""
        avail = max(0, min(hdr.payload_length, self.buffer_length - hdr.payload_offset))
        head = self.read_bytes(hdr.payload_offset, min(avail, REGION_HEADER_SIZE))
        if len(head) < REGION_HEADER_SIZE:
            return head
        region_size = struct.unpack_from("<Q", head, 8)[0]
        log2 = head[0x12]
        num_pages = region_size >> log2 if 10 <= log2 <= 40 else 0
        map_bytes = _pad8((num_pages + 3) // 4)
        return self.read_bytes(hdr.payload_offset, min(avail, REGION_HEADER_SIZE + map_bytes))

    def collect_regions(self) -> List[MemoryRegion]:
        """Every decodable MEMORY_REGION in merge order; a malformed one is skipped."""
        if self._regions is None:
            regions = []
            for hdr in merge_order(self._blocks):
                if hdr.block_type != MEMORY_REGION:
                    continue
                try:
                    regions.append(decode_memory_region(hdr, self._region_head(hdr)))
                except (MslSlimError, struct.error, IndexError) as excp:
                    vollog.warning("Skipping malformed MEMORY_REGION block at 0x%X: %s",
                                   hdr.file_offset, excp)
            self._regions = regions
        return self._regions

    def captured_run_index(self) -> CapturedRunIndex:
        """CAPTURED runs, ordered by region base address then page (MemDiver's vas order)."""
        if self._run_index is None:
            runs: List[CapturedRun] = []
            vas_offset = 0
            for region in sorted(self.collect_regions(), key=lambda r: r.base_addr):
                runs.extend(self._region_runs(region, vas_offset))
                vas_offset += region.captured_pages * region.page_size
            by_va = tuple(sorted(runs, key=lambda run: run.va_start))
            self._run_index = CapturedRunIndex(
                runs=tuple(runs), by_va=by_va,
                va_starts=tuple(run.va_start for run in by_va),
                vas_starts=tuple(run.vas_offset for run in runs))
        return self._run_index

    def _region_runs(self, region: MemoryRegion, vas_offset: int) -> List[CapturedRun]:
        """One region's CAPTURED runs; page data follows the 8-padded page-state map."""
        page_size = region.page_size
        base = (region.block_header.payload_offset + REGION_HEADER_SIZE
                + _pad8((region.num_pages + 3) // 4))
        region_avail = max(0, min(region.captured_pages * page_size, self.buffer_length - base))
        runs, data_offset = [], 0
        for interval in region.page_intervals:
            if interval.state != CAPTURED or interval.count <= 0:
                continue
            length = interval.count * page_size
            runs.append(CapturedRun(
                va_start=region.base_addr + interval.start_page * page_size, length=length,
                buf_offset=base + data_offset,
                avail=max(0, min(length, region_avail - data_offset)),
                vas_offset=vas_offset + data_offset))
            data_offset += length
        return runs

    def run_span(self, run: CapturedRun) -> int:
        """Bytes of ``run`` the file actually holds."""
        return max(0, min(run.buf_offset + run.avail, self.buffer_length) - run.buf_offset)

    def _collect_blocks(self, block_type: int,
                        decoder: Callable[[BlockHeader, bytes], object]) -> list:
        """Decode every block of ``block_type``; a malformed one is skipped with a warning.

        A compressed block raises :class:`MslSlimUnsupported` (it must not look like an
        absent or malformed one).
        """
        wanted = [hdr for hdr in self._blocks if hdr.block_type == block_type]
        decoded = []
        for hdr, payload in merged_payloads(wanted, self.read_block_payload):
            try:
                decoded.append(decoder(hdr, payload))
            except MslSlimUnsupported:
                raise
            except (MslSlimError, struct.error, IndexError) as excp:
                vollog.warning("Skipping malformed block 0x%04X at 0x%X: %s",
                               block_type, hdr.file_offset, excp)
        return decoded

    def _collect(self, block_type: int, decoder: Callable[[bytes], object]) -> list:
        return self._collect_blocks(block_type, lambda _hdr, payload: decoder(payload))

    def _cached(self, attribute: str, block_type: int, decoder: Callable) -> list:
        if getattr(self, attribute) is None:
            setattr(self, attribute, self._collect_blocks(block_type, decoder))
        return getattr(self, attribute)

    @property
    def blocks(self) -> List[BlockHeader]:
        """Capture-segment block headers in file order, up to End-of-Capture."""
        return self._blocks

    def collect_modules(self) -> List[ModuleEntry]:
        return self._cached("_modules", MODULE_ENTRY, decode_module_entry)

    def collect_module_list_index(self) -> List[ModuleListIndex]:
        return self._cached("_module_indexes", MODULE_LIST_INDEX, decode_module_list_index)

    def collect_key_hints(self) -> List[KeyHint]:
        return self._cached("_key_hints", KEY_HINT, decode_key_hint)

    def collect_thread_contexts(self) -> list:
        return self._cached("_thread_contexts", THREAD_CONTEXT, decode_thread_context)

    def collect_import_provenance(self) -> List[ImportProvenance]:
        return self._cached("_provenance", IMPORT_PROVENANCE, decode_import_provenance)

    def collect_end_of_capture(self) -> List[EndOfCapture]:
        return self._cached("_end_of_capture", END_OF_CAPTURE, decode_end_of_capture)

    def collect_process_identity(self) -> List[ProcessIdentity]:
        if self._identities is None:
            self._identities = self._collect(PROCESS_IDENTITY, decode_process_identity)
        return self._identities

    def collect_vas_map(self) -> List[VasMap]:
        if self._vas_maps is None:
            self._vas_maps = self._collect(VAS_MAP, decode_vas_map)
        return self._vas_maps

    def effective_vas_map(self) -> Optional[VasMap]:
        """The last capture-segment VAS map (spec 5.8), else ``None``."""
        maps = self.collect_vas_map()
        return maps[-1] if maps else None


class MslSlimSource:
    """The ``open_dump`` source shape ``msl_layer.MslSlice`` reads: ``path``,
    ``get_reader()`` and ``close()``."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._reader = MslSlimReader(path)

    def open(self) -> "MslSlimSource":
        self._reader.open()
        return self

    def get_reader(self) -> MslSlimReader:
        return self._reader

    def close(self) -> None:
        self._reader.close()


# ------------------------------------------------------------------------ integrity


class MslSlimHashUnavailable(MslSlimUnsupported):
    """The container's hash algorithm is not in the standard library (BLAKE3)."""

    def __init__(self, algo: int) -> None:
        name = HashAlgo(algo).name if algo in set(HashAlgo) else f"0x{algo:02X}"
        super().__init__(
            f"the container's HashAlgo is {name}: needs memdiver (BLAKE3 is not in the "
            f"standard library); {INSTALL_HINT}")
        self.algo = algo


class BlockCheck(NamedTuple):
    """The PrevHash check of one capture-segment block."""

    index: int
    block_type: int
    file_offset: int
    block_length: int
    ok: bool
    detail: str


@dataclass
class SegmentCheck:
    """Verification of one extension segment (spec 4.6), as MemDiver's ``SegmentReport``."""

    index: int
    start: int
    end: int
    block_count: int
    terminated: bool
    chain_ok: bool = True
    segment_hash_ok: bool = False
    block_count_ok: bool = False
    errors: List[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return (self.terminated and self.chain_ok and self.segment_hash_ok
                and self.block_count_ok)


@dataclass
class VerifyReport:
    """What :func:`verify_container` found; ``valid`` is the verdict (``not tampered``)."""

    hash_algo: int
    blocks: List[BlockCheck] = field(default_factory=list)
    segments: List[SegmentCheck] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    file_hash_ok: Optional[bool] = None
    block_count: int = 0
    header_block_count: int = 0
    eoc_block_count: int = 0
    block_count_ok: bool = True
    trailing_bytes: int = 0
    capture_ok: bool = True
    legacy_unchained_header: bool = False

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def broken_at(self) -> Optional[int]:
        bad = [check.file_offset for check in self.blocks if not check.ok]
        return bad[0] if bad else None


def _sha512_256(data: bytes = b"") -> Any:
    return hashlib.new("sha512_256", data)


def chain_hashers(hash_algo: int, blake3_module: Any = None
                  ) -> Tuple[Callable[[bytes], bytes], Callable[[], Any]]:
    """``(one-shot hash, incremental hasher factory)`` for ``hash_algo``.

    BLAKE3 needs ``blake3_module`` (the ``blake3`` package); without it
    :class:`MslSlimHashUnavailable` is raised. Unknown codes raise :class:`MslSlimError`.
    """
    if hash_algo == HashAlgo.SHA256:
        return (lambda data: hashlib.sha256(data).digest()), hashlib.sha256
    if hash_algo == HashAlgo.SHA512_256:
        return (lambda data: _sha512_256(data).digest()), _sha512_256
    if hash_algo == HashAlgo.BLAKE3:
        if blake3_module is None:
            raise MslSlimHashUnavailable(hash_algo)
        return (lambda data: blake3_module.blake3(data).digest()), blake3_module.blake3
    raise MslSlimError(f"unsupported HashAlgo 0x{hash_algo:02X}")


_HASH_CHUNK = 16 << 20
#: SegmentHash(32) WrittenAt(8) BlockCount(4) Reserved(4) ProducerLen(2) Reserved(6).
END_OF_EXTENSION_HEAD_SIZE = 0x38


def _hash_span(reader: "MslSlimReader", start: int, end: int, factory: Callable) -> bytes:
    hasher = factory()
    for offset in range(start, end, _HASH_CHUNK):
        hasher.update(reader.read_bytes(offset, min(_HASH_CHUNK, end - offset)))
    return hasher.digest()


def verify_container(reader: "MslSlimReader", blake3_module: Any = None) -> VerifyReport:
    """The integrity checks of MemDiver's ``verify_chain`` on a plaintext capture.

    Capture segment: every block's PrevHash (block 0 chains from the header bytes), the
    End-of-Capture FileHash (all-zero = not recorded, a warning) and header / EoC BlockCount
    against the parsed count. Then every extension segment after the EoC (spec 4.6): chain
    continuity, SegmentHash and BlockCount. Raises :class:`MslSlimHashUnavailable` for BLAKE3
    without ``blake3_module``.
    """
    header = reader.file_header
    hasher, factory = chain_hashers(header.hash_algo, blake3_module)
    report = VerifyReport(hash_algo=header.hash_algo)
    last_hash = _check_capture_chain(reader, report, hasher)
    blocks = reader.blocks
    eoc = blocks[-1] if blocks and blocks[-1].block_type == END_OF_CAPTURE else None
    _check_block_counts(reader, report, eoc)
    if eoc is not None:
        _check_file_hash(reader, report, eoc, factory)
    report.capture_ok = report.valid
    if eoc is not None:
        _check_segments(reader, report, eoc, last_hash, hasher, factory)
    else:
        _note_truncation(reader, report)
    return report


def _check_capture_chain(reader: "MslSlimReader", report: VerifyReport,
                         hasher: Callable[[bytes], bytes]) -> bytes:
    """Per-block PrevHash rows; returns the hash chained after the last block."""
    expected = hasher(reader.read_bytes(0, reader.file_header.header_size))
    for index, hdr in enumerate(reader.blocks):
        detail = ""
        if index == 0 and hdr.prev_hash == ZERO_HASH and expected != ZERO_HASH:
            report.legacy_unchained_header = True
            report.warnings.append("Block 0 PrevHash is zero (legacy MemDiver writer): the "
                                   "file header is not covered by the chain")
            expected = ZERO_HASH
        ok = hdr.prev_hash == expected
        if not ok:
            detail = (f"PrevHash mismatch: expected {expected[:8].hex()}..., "
                      f"got {hdr.prev_hash[:8].hex()}...")
            report.errors.append(f"Hash mismatch at block 0x{hdr.file_offset:X}: expected "
                                 f"{expected[:8].hex()}..., got {hdr.prev_hash[:8].hex()}...")
        report.blocks.append(BlockCheck(index, hdr.block_type, hdr.file_offset,
                                        hdr.block_length, ok, detail))
        expected = hasher(reader.read_bytes(hdr.file_offset, hdr.block_length))
    report.block_count = len(reader.blocks)
    return expected


def _note_truncation(reader: "MslSlimReader", report: VerifyReport) -> None:
    blocks = reader.blocks
    end = blocks[-1].file_offset + blocks[-1].block_length if blocks else \
        reader.file_header.header_size
    if reader.read_bytes(end, 4) == BLOCK_MAGIC:
        report.errors.append(f"Truncated block at 0x{end:X}")
    report.warnings.append("no End-of-Capture block (truncated or still streaming)")


def _check_block_counts(reader: "MslSlimReader", report: VerifyReport,
                        eoc: Optional[BlockHeader]) -> None:
    """Consumer rule 13: non-zero header / EoC counts must match the parse."""
    report.header_block_count = reader.file_header.block_count
    if eoc is not None:
        try:
            report.eoc_block_count = reader.collect_end_of_capture()[0].block_count
        except (IndexError, MslSlimError):
            report.eoc_block_count = 0
    for label, stored in (("header", report.header_block_count),
                          ("EoC", report.eoc_block_count)):
        if stored and stored != report.block_count:
            report.block_count_ok = False
            report.errors.append(f"{label} BlockCount {stored} != {report.block_count} "
                                 f"capture-segment blocks parsed (truncated or corrupt)")


def _check_file_hash(reader: "MslSlimReader", report: VerifyReport, eoc: BlockHeader,
                     factory: Callable) -> None:
    stored = reader.read_bytes(eoc.payload_offset, 32)
    if stored == ZERO_HASH:
        report.warnings.append("EoC FileHash is zero (not recorded by the producer)")
        return
    report.file_hash_ok = _hash_span(reader, 0, eoc.file_offset, factory) == stored
    if not report.file_hash_ok:
        report.errors.append(f"EoC FileHash mismatch: stored {stored[:8].hex()}... does not "
                             "cover the bytes before the EoC block")


def _frame_segment(reader: "MslSlimReader", index: int, start: int
                   ) -> Optional[Tuple[SegmentCheck, List[BlockHeader], Optional[bytes], int]]:
    """``(check, headers, SegmentHash, terminator BlockCount)`` of the segment at ``start``."""
    size = reader.buffer_length
    headers: List[BlockHeader] = []
    offset, segment_hash, term_count = start, None, 0
    while offset + BLOCK_HEADER_SIZE <= size:
        raw = reader.read_bytes(offset, BLOCK_HEADER_SIZE)
        if raw[:4] != BLOCK_MAGIC:
            break
        hdr = parse_block_header(raw, offset)
        if hdr.block_length < BLOCK_HEADER_SIZE or offset + hdr.block_length > size:
            break
        headers.append(hdr)
        offset += hdr.block_length
        if hdr.block_type == END_OF_EXTENSION:
            payload = reader.read_bytes(hdr.payload_offset, hdr.payload_length)
            if len(payload) < END_OF_EXTENSION_HEAD_SIZE or hdr.compressed:
                headers.pop()
                offset = hdr.file_offset
            else:
                segment_hash = bytes(payload[:32])
                term_count = struct.unpack_from("<I", payload, 0x28)[0]
            break
    if not headers:
        return None
    terminated = segment_hash is not None
    return (SegmentCheck(index, start, offset, len(headers), terminated), headers,
            segment_hash, term_count)


def _check_segments(reader: "MslSlimReader", report: VerifyReport, eoc: BlockHeader,
                    last_hash: bytes, hasher: Callable, factory: Callable) -> None:
    """Extension segments after the EoC; verification is prefix-closed (as MemDiver's)."""
    start = eoc.file_offset + eoc.block_length
    expected_prev, verified_end, broken, index = last_hash, start, False, 0
    while start < reader.buffer_length:
        framed = _frame_segment(reader, index, start)
        if framed is None:
            break
        check, headers, segment_hash, term_count = framed
        expected_prev = _check_one_segment(reader, check, headers, segment_hash, term_count,
                                           expected_prev, hasher, factory)
        if broken:
            check.chain_ok = False
            check.errors.append("follows an unverified segment")
        report.segments.append(check)
        if check.verified and not broken:
            verified_end = check.end
        else:
            broken = True
        start, index = check.end, index + 1
        if not check.terminated:
            break
    report.trailing_bytes = reader.buffer_length - verified_end
    for check in report.segments:
        if check.verified:
            continue
        if not check.terminated:
            report.warnings.append(
                f"extension segment {check.index} at 0x{check.start:X} is not terminated "
                "by an End-of-Extension block; treated as trailing data")
        else:
            report.errors.extend(f"extension segment {check.index}: {err}"
                                 for err in check.errors)
    if report.trailing_bytes:
        report.warnings.append(
            f"{report.trailing_bytes} trailing byte(s) after the last verified segment")


def _check_one_segment(reader: "MslSlimReader", check: SegmentCheck,
                       headers: List[BlockHeader], segment_hash: Optional[bytes],
                       term_count: int, expected_prev: bytes, hasher: Callable,
                       factory: Callable) -> bytes:
    """Fill ``check``; returns the PrevHash the next segment must chain from."""
    for hdr in headers:
        if hdr.prev_hash != expected_prev:
            check.chain_ok = False
            check.errors.append(f"PrevHash mismatch at block 0x{hdr.file_offset:X}")
            break
        expected_prev = hasher(reader.read_bytes(hdr.file_offset, hdr.block_length))
    if segment_hash is None:
        check.errors.append("no End-of-Extension block")
        return expected_prev
    check.segment_hash_ok = (_hash_span(reader, check.start, headers[-1].file_offset, factory)
                             == segment_hash)
    if not check.segment_hash_ok:
        check.errors.append("SegmentHash mismatch")
    check.block_count_ok = term_count == len(headers)
    if not check.block_count_ok:
        check.errors.append(f"BlockCount {term_count} != {len(headers)} blocks parsed")
    return expected_prev
