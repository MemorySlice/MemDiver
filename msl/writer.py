"""MSL file writer for producing valid Memory Slice binary files.

Implements the Memory Slice Specification v1.0.0 (binary format 1.1)
producer requirements (§14.1). Supports both Analysis-mode and
Investigation-mode acquisition, three-state page maps (CAPTURED/FAILED/
UNMAPPED), accurate capability bitmap accumulation, and spec-mandated
block ordering (Block 0 = Process Identity / Import Provenance,
Block 1 = Module List Index, Block 2 = System Context for Investigation).

All struct layouts must match the corresponding decoders.py decoder
for roundtrip compatibility via MslReader.
"""

import itertools
import logging
import os
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import (Callable, Dict, Iterator, List, Optional, Sequence,
                    Tuple, Union)
from uuid import UUID, uuid4

from .compress import compress
from .aead_stream import aead_stream_encryptor
from .crypto import (RewrapMaterial, aead_encrypt, clamp_argon2id_params,
                     derive_cek_producer, encryption_aad, nonce_for_cipher, random_nonce)
from .enums import (ARGON2ID_MIN_LANES, ARGON2ID_MIN_MEMORY_KIB,
                    ARGON2ID_MIN_TIME, BLOCK_HEADER_SIZE, BLOCK_MAGIC,
                    CIPHER_LEN_OFFSET, CIPHER_LEN_SIZE, EXTENSION_FORBIDDEN_TYPES, FILE_HEADER_ENC_SIZE,
                    FILE_HEADER_SIZE, FILE_MAGIC,
                    POINTER_GRAPH_INTEGRITY_FLAG, ArchType, BlockFlag,
                    BlockType, CompAlgo, ConnRowType, EncAlgo, Endianness,
                    HashAlgo, HeaderFlag, KdfType, KeyEncap, OSType, PageState,
                    ThreadState)
from .hashing import _new_hasher, hash_bytes, hash_file, hash_stream
from .types import (ConnectivityRow, PhysicalRange, MslConnArpEntry, MslConnIfaceStats,
                    MslConnIPv4Route, MslConnIPv6Route, MslConnMibCounter,
                    MslConnPacketSocket, MslConnSocketFamilyAgg,
                    MslPointerGraphEdge, MslPointerGraphNode, MslThreadRegister,
                    MslVasEntry)

logger = logging.getLogger("memdiver.msl.writer")

_ZERO_HASH = b"\x00" * 32
_ZERO_UUID = b"\x00" * 16
_NIL_UUID = UUID(int=0)

# Largest MEMORY_REGION block the writer emits by default. BlockLength is a
# u32 (spec Table 6), so one block can never exceed 4 GiB; larger regions are
# split into consecutive MEMORY_REGION blocks at page boundaries. Override per
# writer via ``MslWriter(region_block_cap=...)`` (must be page-aligned).
REGION_BLOCK_CAP = 1 << 30
# Bounded copy size for streamed region bytes: peak RAM is O(this), not O(dump).
STREAM_CHUNK_SIZE = 16 << 20
# Ciphertext slice size for streaming encryption (see _seal_block).
SEAL_PIECE_SIZE = 1 << 20
_U32_MAX = 0xFFFFFFFF

# ``Producer`` written into End-of-Extension blocks (spec Table 12a).
def _default_extension_producer() -> str:
    try:
        from memdiver import __version__
    except Exception:  # pragma: no cover - import cycle / unknown version
        __version__ = "0.0.0+unknown"
    return f"memdiver/{__version__}"


# Byte source for a streamed region: ``read_chunk(offset, length)`` returns
# exactly *length* bytes starting *offset* bytes into the region's captured-
# byte stream (the same bytes ``add_memory_region(data=...)`` would receive).
ReadChunk = Callable[[int, int], Union[bytes, bytearray, memoryview]]


# Capability Bitmap bit positions per Memory Slice Specification v1.0.0 §9.
# Producers MUST set bits accurately for data categories present. See spec
# Table 27 (Capability Bitmap) for the authoritative mapping.
class CapBit:
    MEMORY_REGIONS = 1 << 0
    MODULE_LIST = 1 << 1
    THREAD_CONTEXTS = 1 << 2
    FILE_DESCRIPTORS = 1 << 3
    NETWORK_STATE = 1 << 4
    ENVIRONMENT_VARS = 1 << 5
    SHARED_MEMORY = 1 << 6
    SECURITY_CONTEXT = 1 << 7
    PROCESS_IDENTITY = 1 << 8
    RELATED_DUMPS = 1 << 9
    CRYPTO_HINTS = 1 << 10
    SYSTEM_CONTEXT = 1 << 11   # MUST be set when Investigation=1
    SYSTEM_PROCESS_TABLE = 1 << 12
    SYSTEM_NETWORK_TABLE = 1 << 13
    SYSTEM_HANDLE_TABLE = 1 << 14

    # MemDiver extension (not spec-registered; occupies a Reserved bit).
    # Marks that the page-state map was assigned by convention on import,
    # not observed during live acquisition. A static source (ELF core,
    # Minidump) performs no reads, so its page states are inferred, not
    # genuine acquisition observations. Set on every imported file.
    PAGE_STATES_INFERRED = 1 << 15


# Spec §6.2 System Context TableBitmap bits — distinct from FileHeader CapBitmap.
# These describe which tables are referenced under this System Context block.
class TableBit:
    PROCESS_TABLE = 1 << 0
    CONNECTION_TABLE = 1 << 1
    HANDLE_TABLE = 1 << 2


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _pack_padded_str(s: str) -> bytes:
    raw = s.encode("utf-8") + b"\x00"
    return raw.ljust(_pad8(len(raw)), b"\x00")


def _padded_str_len(s: str) -> int:
    """Bytes a writer would emit for `s` including NUL + 8-byte alignment.

    Empty string convention matches decoders._advance_str: 0 bytes.
    """
    if not s:
        return 0
    return _pad8(len(s.encode("utf-8")) + 1)


def _file_digest_or_zero(path: Optional[Path]) -> bytes:
    """Return BLAKE3 digest of *path* via streamed reads, or zeros if missing.

    Handles the TOCTOU-safe path: we attempt the read directly and swallow
    FileNotFoundError rather than pre-checking with .exists().
    """
    if path is None:
        return _ZERO_HASH
    try:
        return hash_file(Path(path))
    except (FileNotFoundError, IsADirectoryError):
        return _ZERO_HASH


# -- Investigation-mode entry dataclasses (mirror decoders.py shapes) --

@dataclass
class ModuleEntrySpec:
    """One module record for add_module_list_index().

    The writer assigns a UUID at write() time so the Module List Index
    payload (Block 1) and the corresponding Module Entry block (which
    references the Index via parent_uuid) carry matching identifiers.
    """
    base_addr: int
    module_size: int
    path: str
    version: str = ""
    disk_hash: bytes = b""  # 32 bytes BLAKE3, or empty/short -> zero-padded
    # Filled in by writer at emit time; users do not set this.
    module_uuid: Optional[UUID] = None


@dataclass
class ProcessTableEntry:
    pid: int
    ppid: int = 0
    uid: int = 0
    is_target: bool = False
    start_time_ns: int = 0
    rss: int = 0
    exe_name: str = ""
    cmd_line: str = ""
    user: str = ""


@dataclass
class ConnectionTableEntry:
    pid: int = 0
    family: int = 0     # 0x02 = AF_INET, 0x0A = AF_INET6
    protocol: int = 0   # 0x06 = TCP, 0x11 = UDP
    state: int = 0
    local_addr: bytes = b""    # 16 bytes; v4 lives in first 4
    local_port: int = 0        # spec §6.4: little-endian (NOT network order)
    remote_addr: bytes = b""
    remote_port: int = 0


@dataclass
class HandleTableEntry:
    pid: int
    fd: int
    handle_type: int = 0
    path: str = ""


@dataclass(frozen=True)
class ExtensionBlock:
    """One block of an extension segment (spec 4.6) for
    :meth:`MslWriter.add_extension_segment`.

    ``payload`` is the on-disk payload (already compressed when ``flags``
    says so); ``block_uuid`` / ``parent_uuid`` default to a fresh uuid4 /
    zero. Used by materialize to re-emit a verified source segment with
    its block identities intact.
    """
    block_type: int
    payload: bytes
    block_uuid: Optional[UUID] = None
    parent_uuid: Optional[UUID] = None
    flags: int = 0


@dataclass
class _ExtensionSegmentSpec:
    """A pending extension segment: blocks + the terminator's identity."""
    producer: str
    blocks: List[Tuple[int, bytes, UUID, bytes, int]]
    terminator_uuid: UUID = field(default_factory=uuid4)
    # WrittenAt of the terminator; None = the writer's own timestamp.
    written_at_ns: Optional[int] = None


@dataclass
class MslEncryptionConfig:
    """Producer-side AEAD encryption configuration (spec §10).

    Pass to ``MslWriter(encryption=...)`` to emit an encrypted container.
    Provide exactly one form of key material matching the chosen
    ``key_encap`` / ``kdf_type``:

      * key_encap=NONE, kdf_type=NONE      -> raw_key (32 bytes)
      * key_encap=NONE, kdf_type=ARGON2ID  -> passphrase
      * key_encap!=NONE                     -> recipient_public

    `nonce` and `kdf_salt` are normally generated from a CSPRNG; supply
    them only for deterministic fixtures/tests.

    Re-wrap mode (:meth:`rewrap`): a derived copy of a decrypted container
    reuses its content key and key wrapping (``rewrap_material``) so the same
    key / passphrase / private key opens the copy; the nonce is always fresh
    and the source nonce is refused.
    """
    enc_algo: EncAlgo = EncAlgo.AES_256_GCM
    kdf_type: KdfType = KdfType.NONE
    key_encap: KeyEncap = KeyEncap.NONE
    raw_key: Optional[bytes] = field(default=None, repr=False)
    passphrase: Optional[bytes] = field(default=None, repr=False)
    recipient_public: Optional[bytes] = None
    kdf_time: int = ARGON2ID_MIN_TIME
    kdf_memory: int = ARGON2ID_MIN_MEMORY_KIB
    kdf_lanes: int = ARGON2ID_MIN_LANES
    nonce: Optional[bytes] = None       # 24-byte Nonce field; None -> CSPRNG
    kdf_salt: Optional[bytes] = None    # 16-byte salt; None -> CSPRNG when Argon2id
    rewrap_material: Optional[RewrapMaterial] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        # A new Argon2id container never stores parameters weaker than the
        # spec §10.5 minimum: the header must hold exactly the parameters the
        # producer derives with, so any reader can open it. Re-wrap configs
        # keep the source's parameters (the CEK is reused, not re-derived).
        if self.kdf_type == KdfType.ARGON2ID and self.rewrap_material is None:
            self.kdf_time, self.kdf_memory, self.kdf_lanes = clamp_argon2id_params(
                self.kdf_time, self.kdf_memory, self.kdf_lanes)

    @classmethod
    def rewrap(cls, material: RewrapMaterial) -> "MslEncryptionConfig":
        """Config that re-encrypts under *material*'s key wrapping (fresh nonce)."""
        return cls(enc_algo=material.enc_algo, kdf_type=material.kdf_type,
                   key_encap=material.key_encap, kdf_time=material.kdf_time,
                   kdf_memory=material.kdf_memory, kdf_lanes=material.kdf_lanes,
                   kdf_salt=material.kdf_salt, rewrap_material=material)


class MslWriter:
    """Accumulate blocks and write a valid MSL file.

    Block-ordering policy enforced at write() time per spec §6.1:
      * If imported=True and add_import_provenance() was called, that block
        is emitted as Block 0 with HeaderFlag.IMPORTED set.
      * If imported=False and add_process_identity() was called, that block
        is emitted as Block 0.
      * If add_module_list_index() was called, the index is emitted as
        Block 1, immediately followed by one Module Entry block per
        module, each with parent_uuid = index UUID.
      * If investigation=True and add_system_context() was called, that
        block is emitted as Block 2; HeaderFlag.INVESTIGATION is set in
        the file header; CapBit.SYSTEM_CONTEXT is OR'd into the
        capability bitmap; and any Process/Connection/Handle table blocks
        are emitted as children with parent_uuid = system context UUID.
      * Thread contexts, memory regions, key hints, related dumps, and any
        other generic blocks follow in the order their add_* method was
        called (add thread contexts first so they precede the regions).
      * End-of-Capture, if added, is always emitted last and its file_hash
        is finalized over the actual on-disk byte stream.
    """

    def __init__(self, path: Path, pid: int = 0,
                 os_type: int = OSType.UNKNOWN,
                 arch_type: int = ArchType.UNKNOWN,
                 imported: bool = True,
                 investigation: bool = False,
                 encryption: Optional["MslEncryptionConfig"] = None,
                 region_block_cap: int = REGION_BLOCK_CAP,
                 dump_uuid: Optional[UUID] = None,
                 timestamp_ns: Optional[int] = None,
                 clock_source: int = 0):
        """*dump_uuid* / *timestamp_ns* / *clock_source* override the file
        header fields (default: fresh uuid4, write time, 0). Used when a file
        is rewritten from an existing ``.msl`` and must keep its identity.
        """
        self._path = Path(path)
        self._pid = pid
        self._os_type = os_type
        self._arch_type = arch_type
        self._imported = imported
        self._investigation = investigation
        self._encryption = encryption
        self._dump_uuid = dump_uuid if dump_uuid is not None else uuid4()
        self._timestamp_ns = timestamp_ns
        self._clock_source = clock_source
        # Generic blocks (memory regions, key hints, related dumps, ...)
        # in user call order. Each entry is (block_type, payload, block_uuid,
        # parent_uuid_bytes, flags). `flags` carries BlockFlag bits — bit 0
        # COMPRESSED, bits 1-2 compression algorithm — and is set by add_*
        # methods that accept a `compress=` argument; for all other blocks
        # it stays zero.
        self._blocks: List[Tuple[int, bytes, UUID, bytes, int]] = []
        # Capability bitmap accumulator (spec §9, MUST be set accurately).
        self._cap_bitmap: int = 0
        # Spec-mandated positional slots (resolved at write() time).
        self._import_provenance: Optional[Tuple[bytes, UUID]] = None
        self._process_identity: Optional[Tuple[bytes, UUID]] = None
        self._module_list: Optional[Tuple[List[ModuleEntrySpec], UUID]] = None
        self._system_context: Optional[Tuple[bytes, UUID, int]] = None  # (payload, uuid, table_bitmap)
        self._sc_children: List[Tuple[int, bytes, UUID, int]] = []
        self._end_of_capture: Optional[Tuple[bytes, UUID]] = None
        # Extension segments (spec 4.6): emitted after EoC in registration
        # order, each closed by an End-of-Extension block. The PrevHash
        # chain continues from H(EoC) (zero inside an encrypted container).
        self._extension_segments: List[_ExtensionSegmentSpec] = []
        # Index into _extension_segments of the writer's own pointer-graph
        # segment (add_pointer_graph replaces it instead of adding another).
        self._pointer_graph_segment: Optional[int] = None
        # One WrittenAt for every segment this writer emits, fixed at
        # construction so two write() calls of the same writer are
        # byte-identical (the streaming/in-memory equality tests rely on it).
        self._extension_written_at_ns: int = int(time.time() * 1e9)
        # Region splitting (see REGION_BLOCK_CAP). `_region_index` holds
        # (base_addr, region_size, block_uuid) for every MEMORY_REGION block;
        # `_split_regions` maps a split region's first-block UUID to
        # [(offset_from_region_base, chunk_block_uuid)] so key hints that
        # address the whole region land on the correct chunk block.
        self._region_block_cap = region_block_cap
        self._region_index: List[Tuple[int, int, UUID]] = []
        self._split_regions: Dict[UUID, List[Tuple[int, UUID]]] = {}
        # True once a byte-source region is registered: such regions can
        # only be emitted by write_streaming().
        self._has_streamed_regions = False

    @property
    def dump_uuid(self) -> UUID:
        return self._dump_uuid

    # ------------------------------------------------------------------
    # Capture-time blocks (Analysis Mode)
    # ------------------------------------------------------------------

    def add_memory_region(self, base_addr: int, data: bytes,
                          protection: int = 0x03, region_type: int = 0x05,
                          page_size_log2: int = 12,
                          timestamp_ns: int = 0,
                          page_states: Optional[Sequence[int]] = None,
                          compression: CompAlgo = CompAlgo.NONE) -> UUID:
        """Add a memory region block (spec §5.1). Returns block UUID.

        Validates spec range constraints:
          * page_size_log2 ∈ [10, 40]  (spec §5.1)
          * region_size MUST be a multiple of page_size  (spec §5.1)

        Three-state page model (spec §7): supply *page_states* as a
        sequence of PageState codes (one per page). Only CAPTURED pages
        contribute to *data*; FAILED / UNMAPPED pages occupy zero bytes
        in the data segment. When *page_states* is None (default), all
        pages are encoded as CAPTURED — backward-compatible behavior.

        When *compression* is anything other than CompAlgo.NONE, the
        block payload is run through the chosen codec and the block
        header's flag bits are set so the reader transparently
        decompresses on read. The BLAKE3 integrity chain hashes the
        on-disk (compressed) bytes, so chain validation works unchanged.

        Regions larger than the writer's region block cap are split into
        consecutive MEMORY_REGION blocks at page boundaries; the UUID of
        the first block is returned (see region_for_va()).
        """
        page_size, cap_pages = self._region_geometry(page_size_log2)
        num_pages = _in_memory_page_count(len(data), page_size, page_states)
        chunks = _plan_region_chunks(base_addr, page_size, num_pages,
                                     page_states, cap_pages)
        meta = _RegionMeta(protection, region_type, page_size_log2, timestamp_ns)
        view = memoryview(data)
        flags = _encode_comp_flags(compression)

        def payload_for(chunk: "_RegionChunk") -> bytes:
            payload = _region_payload_prefix(chunk, page_size, page_states, meta)
            payload += view[chunk.data_offset:chunk.data_offset + chunk.data_len]
            if compression is not CompAlgo.NONE:
                payload = compress(payload, compression)
            return payload

        return self._append_region_blocks(chunks, page_size, payload_for, flags)

    def add_memory_region_source(self, base_addr: int, region_size: int,
                                 read_chunk: ReadChunk,
                                 protection: int = 0x03, region_type: int = 0x05,
                                 page_size_log2: int = 12,
                                 timestamp_ns: int = 0,
                                 page_states: Optional[Sequence[int]] = None,
                                 compression: CompAlgo = CompAlgo.NONE) -> UUID:
        """Register a memory region whose bytes are pulled at write time.

        Streaming counterpart of add_memory_region(): instead of the bytes,
        pass *read_chunk(offset, length)* returning exactly *length* bytes
        from the region's captured-byte stream (only CAPTURED pages, in page
        order). Bytes are copied in STREAM_CHUNK_SIZE pieces during
        write_streaming(), so peak RAM stays O(chunk), not O(dump).

        Same validation and splitting rules as add_memory_region(). Streamed
        regions cannot be compressed or encrypted (both codecs are one-shot):
        either raises ValueError so callers can fall back to the in-memory
        path. Returns the UUID of the region's first block.
        """
        self._require_streamable(compression)
        page_size, cap_pages = self._region_geometry(page_size_log2)
        num_pages = _source_page_count(region_size, page_size, page_states)
        chunks = _plan_region_chunks(base_addr, page_size, num_pages,
                                     page_states, cap_pages)
        meta = _RegionMeta(protection, region_type, page_size_log2, timestamp_ns)

        def payload_for(chunk: "_RegionChunk") -> "_StreamedRegionPayload":
            prefix = _region_payload_prefix(chunk, page_size, page_states, meta)
            return _StreamedRegionPayload(prefix, read_chunk,
                                          chunk.data_offset, chunk.data_len)

        self._has_streamed_regions = True
        return self._append_region_blocks(chunks, page_size, payload_for, 0)

    def region_for_va(self, va: int) -> Optional[Tuple[UUID, int]]:
        """Return (block_uuid, offset_in_block) of the region block holding *va*.

        Resolves to the specific chunk block of a split region, so key hints
        built from the result reference the block that contains the bytes.
        Returns None when no registered region covers *va*.
        """
        for base, size, block_uuid in self._region_index:
            if base <= va < base + size:
                return block_uuid, va - base
        return None

    def _region_geometry(self, page_size_log2: int) -> Tuple[int, int]:
        """Validate page size (spec §5.1) and return (page_size, cap_pages)."""
        if not (10 <= page_size_log2 <= 40):
            raise ValueError(
                f"page_size_log2={page_size_log2} out of spec range [10, 40] "
                f"(MSL Specification v1.0.0 §5.1)"
            )
        page_size = 1 << page_size_log2
        cap = self._region_block_cap
        if cap < page_size or cap % page_size != 0:
            raise ValueError(
                f"region_block_cap={cap} must be a positive multiple of "
                f"page_size={page_size}"
            )
        return page_size, cap // page_size

    def _require_streamable(self, compression: CompAlgo) -> None:
        if compression is not CompAlgo.NONE:
            raise ValueError(
                "streamed memory regions cannot be compressed; use "
                "add_memory_region() for compressed output"
            )

    def _append_region_blocks(self, chunks: Sequence["_RegionChunk"],
                              page_size: int, payload_for, flags: int) -> UUID:
        """Queue one MEMORY_REGION block per chunk; return the first UUID."""
        placed: List[Tuple[int, UUID]] = []
        for chunk in chunks:
            block_uuid = uuid4()
            self._blocks.append((BlockType.MEMORY_REGION, payload_for(chunk),
                                 block_uuid, _ZERO_UUID, flags))
            self._region_index.append(
                (chunk.base_addr, chunk.page_count * page_size, block_uuid))
            placed.append((chunk.first_page * page_size, block_uuid))
        if len(placed) > 1:
            self._split_regions[placed[0][1]] = placed
        self._cap_bitmap |= CapBit.MEMORY_REGIONS
        return placed[0][1]

    def _resolve_region_chunk(self, region_uuid: UUID,
                              offset: int) -> Tuple[UUID, int]:
        """Map (first-block UUID, region offset) onto the owning chunk block."""
        placed = self._split_regions.get(region_uuid)
        if not placed:
            return region_uuid, offset
        for chunk_offset, chunk_uuid in reversed(placed):
            if offset >= chunk_offset:
                return chunk_uuid, offset - chunk_offset
        return region_uuid, offset

    def add_key_hint(self, region_uuid: UUID, offset: int,
                     key_length: int, key_type: int, protocol: int,
                     confidence: int = 0x01, key_state: int = 0,
                     note: str = "") -> UUID:
        """Add a key hint block (spec §5.6) referencing a memory region.

        When *region_uuid* names a region that was split into several
        blocks, (region_uuid, offset) is remapped to the chunk block that
        holds *offset* and the offset is rebased onto that chunk.
        """
        region_uuid, offset = self._resolve_region_chunk(region_uuid, offset)
        note_bytes = _pack_padded_str(note) if note else b""
        note_raw_len = (len(note.encode("utf-8")) + 1) if note else 0
        payload = struct.pack("<16sQIHHBB2xI4x", region_uuid.bytes, offset,
                              key_length, key_type, protocol,
                              confidence, key_state, note_raw_len)
        payload += note_bytes
        block_uuid = uuid4()
        self._blocks.append((BlockType.KEY_HINT, payload, block_uuid,
                             _ZERO_UUID, 0))
        self._cap_bitmap |= CapBit.CRYPTO_HINTS
        return block_uuid

    def add_import_provenance(self, source_format: int, tool_name: str,
                              orig_file_size: int, note: str = "",
                              source_path: Optional[Path] = None) -> UUID:
        """Add an Import Provenance block (spec §11).

        For imported=True files, this block is emitted as Block 0.

        When *source_path* is provided and readable, its BLAKE3 digest
        is computed and written as `source_hash`. Otherwise source_hash
        is 32 zero bytes.
        """
        payload = build_import_provenance_payload(
            source_format, tool_name, orig_file_size, note, source_path)
        block_uuid = uuid4()
        self._import_provenance = (payload, block_uuid)
        # Every imported file carries inferred (not observed) page states:
        # a static source performs no live reads. See CapBit.PAGE_STATES_INFERRED.
        self._cap_bitmap |= CapBit.PAGE_STATES_INFERRED
        return block_uuid

    def add_related_dump(self, related_uuid: UUID, related_pid: int,
                         relationship: int,
                         target_path: Optional[Path] = None) -> UUID:
        """Add a Related Dump block (spec §5.5, type 0x0041).

        When *target_path* is provided and readable, its BLAKE3 digest
        is computed and written as `target_hash`, pinning the
        cross-reference. Otherwise target_hash is 32 zero bytes.
        """
        payload = struct.pack("<16sIH2x", related_uuid.bytes,
                              related_pid, relationship)
        payload += _file_digest_or_zero(target_path)
        block_uuid = uuid4()
        self._blocks.append((BlockType.RELATED_DUMP, payload, block_uuid,
                             _ZERO_UUID, 0))
        self._cap_bitmap |= CapBit.RELATED_DUMPS
        return block_uuid

    def add_process_identity(self, ppid: int = 0, session_id: int = 0,
                             start_time_ns: int = 0,
                             exe_path: str = "", cmd_line: str = "") -> UUID:
        """Add a Process Identity block (spec §5.4, type 0x0040).

        For imported=False (live) acquisitions, this is emitted as Block 0.
        """
        exe_bytes = _pack_padded_str(exe_path) if exe_path else b""
        exe_raw_len = (len(exe_path.encode("utf-8")) + 1) if exe_path else 0
        cmd_bytes = _pack_padded_str(cmd_line) if cmd_line else b""
        cmd_raw_len = (len(cmd_line.encode("utf-8")) + 1) if cmd_line else 0
        # Header: ppid(4) + session_id(4) + start_time_ns(8) + exe_len(2)
        # + cmd_len(2) + 4 reserved bytes = 24 bytes (decoder reads strings
        # starting at 0x18). Spec §5.4 Table 14.
        payload = struct.pack("<IIQHH4x", ppid, session_id, start_time_ns,
                              exe_raw_len, cmd_raw_len)
        payload += exe_bytes + cmd_bytes
        block_uuid = uuid4()
        self._process_identity = (payload, block_uuid)
        self._cap_bitmap |= CapBit.PROCESS_IDENTITY
        return block_uuid

    def add_module_list_index(self, modules: Sequence[ModuleEntrySpec]) -> UUID:
        """Add a Module List Index (spec §5.3, type 0x0010) plus one Module
        Entry block (spec §5.2, type 0x0002) per module as children.

        The index is emitted as Block 1 (immediately after Block 0). Each
        Module Entry's block_uuid matches the pre-assigned ModuleUUID
        recorded in the index, and its parent_uuid references the index.
        Implements the spec's Variant A (inline entries).
        """
        mod_list = list(modules)
        for m in mod_list:
            if m.module_uuid is None:
                m.module_uuid = uuid4()
        index_uuid = uuid4()
        self._module_list = (mod_list, index_uuid)
        self._cap_bitmap |= CapBit.MODULE_LIST
        return index_uuid

    def add_thread_context(self, thread_id: int,
                           registers: Sequence[MslThreadRegister], *,
                           flags: int,
                           state: int = ThreadState.STOPPED,
                           arch: int = 0, name: str = "",
                           start_time: int = 0,
                           parent_uuid: Optional[UUID] = None) -> UUID:
        """Queue a Thread Context block (spec §5.7, type 0x0011).

        *flags* carries the ``TC_FLAG_*`` bits, *state* a ``ThreadState``
        code (default Stopped: a core / minidump thread is a stopped
        snapshot) and *arch* 0 for "same as the header ArchType". Register
        names are written lowercase. The block lands in call order among
        the generic blocks, so call this before the first
        ``add_memory_region*`` (spec: SHOULD precede the first Memory
        Region). *parent_uuid* may name the Process Identity block.

        Raises ``ValueError`` on an empty / over-long register name, a
        width outside 1..255, a value not exactly *width* bytes, or a
        state / arch that does not fit u8.
        """
        payload = _build_thread_context_payload(
            thread_id, start_time, flags, state, arch, name, registers)
        block_uuid = uuid4()
        parent = parent_uuid.bytes if parent_uuid is not None else _ZERO_UUID
        self._blocks.append((BlockType.THREAD_CONTEXT, payload, block_uuid,
                             parent, 0))
        self._cap_bitmap |= CapBit.THREAD_CONTEXTS
        return block_uuid

    def add_raw_block(self, block_type: int, payload: bytes,
                      block_uuid: Optional[UUID] = None,
                      parent_uuid: Optional[UUID] = None,
                      flags: int = 0) -> UUID:
        """Queue an opaque block (already-encoded *payload*) in call order.

        For copying blocks from an existing ``.msl`` without re-decoding them:
        *payload* is written as-is (it must already be compressed when *flags*
        carries BlockFlag.COMPRESSED), and passing the source's *block_uuid* /
        *parent_uuid* keeps parent references between copied blocks valid.
        The caller is responsible for the capability bitmap
        (see add_capabilities()).
        """
        block_uuid = block_uuid if block_uuid is not None else uuid4()
        parent = parent_uuid.bytes if parent_uuid is not None else _ZERO_UUID
        self._blocks.append((int(block_type), bytes(payload), block_uuid,
                             parent, int(flags)))
        return block_uuid

    def add_capabilities(self, bits: int) -> None:
        """OR *bits* into the capability bitmap (for add_raw_block content)."""
        self._cap_bitmap |= int(bits)

    def add_raw_appendix(self, encoded: bytes) -> None:
        """Deprecated: unchained post-EoC appendices no longer exist.

        Spec 1.1 (Section 4.6) replaced the appendix with extension
        segments: blocks after EoC are chained, counted and closed by an
        End-of-Extension block. Re-emit the blocks through
        :meth:`add_extension_segment` instead (materialize does this for
        verified source segments).
        """
        raise NotImplementedError(
            "add_raw_appendix() was removed with MSL 1.1 extension segments "
            "(spec 4.6); use add_extension_segment(producer, blocks) instead")

    def add_extension_segment(self, producer: Optional[str],
                              blocks: Sequence[ExtensionBlock],
                              written_at_ns: Optional[int] = None) -> int:
        """Register an extension segment (spec 4.6) to be emitted after EoC.

        *blocks* (at least one) are written in order after the End-of-Capture
        block and every earlier segment, then closed by an End-of-Extension
        block carrying ``SegmentHash``, the exact ``BlockCount`` (blocks +
        terminator) and *producer* (``None`` = ``memdiver/<version>``).
        *written_at_ns* sets the terminator's ``WrittenAt`` (``None`` = this
        writer's own timestamp); materialize keeps a source segment's value.
        Block types the spec forbids in extension segments (evidence:
        0x0001, 0x0002, 0x0010-0x0015, 0x0030, 0x0040, 0x0050-0x0058,
        0x0FFF) and the terminator itself are rejected.

        Returns the segment's index (emission order). ``write()`` requires
        an End-of-Capture block once any segment is registered.
        """
        blocks = list(blocks)
        if not blocks:
            raise ValueError("an extension segment needs at least one block")
        entries: List[Tuple[int, bytes, UUID, bytes, int]] = []
        for blk in blocks:
            btype = int(blk.block_type)
            if btype in EXTENSION_FORBIDDEN_TYPES or btype == BlockType.END_OF_EXTENSION:
                raise ValueError(
                    f"block type 0x{btype:04X} may not appear in an extension "
                    "segment (spec 4.6)")
            parent = blk.parent_uuid.bytes if blk.parent_uuid is not None else _ZERO_UUID
            entries.append((btype, bytes(blk.payload),
                            blk.block_uuid if blk.block_uuid is not None else uuid4(),
                            parent, int(blk.flags)))
        name = producer if producer is not None else _default_extension_producer()
        self._extension_segments.append(
            _ExtensionSegmentSpec(name, entries, written_at_ns=written_at_ns))
        return len(self._extension_segments) - 1

    @property
    def extension_segment_count(self) -> int:
        """Segments registered so far (emitted in this order after EoC)."""
        return len(self._extension_segments)

    def add_vas_map(self, entries: Sequence[MslVasEntry]) -> UUID:
        """Add a VAS Map block (type 0x1001): the address-space layout overlay.

        Payload (mirrors ``decoders.decode_vas_map``): ``u32 entry_count``,
        ``u32 entry_size`` (0 = variable-length entries), then per entry
        ``u64 base_addr, u64 region_size, u8 protection, u8 region_type,
        u16 path_len`` (raw length incl. NUL, 0 when no path), ``u8
        name_source`` (VasNameSource), 3 reserved bytes, and the
        NUL-terminated path padded to 8 bytes. The format has no
        "captured" flag: a VAS entry without a matching MEMORY_REGION block
        is a range whose bytes were not stored.
        """
        payload = _build_vas_map_payload(entries)
        block_uuid = uuid4()
        self._blocks.append((BlockType.VAS_MAP, payload, block_uuid,
                             _ZERO_UUID, 0))
        return block_uuid

    # ------------------------------------------------------------------
    # Investigation-mode blocks (spec §6)
    # ------------------------------------------------------------------

    def add_system_context(self, boot_time_ns: int, target_count: int,
                           acq_user: str, hostname: str,
                           domain: str = "", os_detail: str = "",
                           case_ref: str = "") -> UUID:
        """Add a System Context block (spec §6.2, type 0x0050).

        Emitted as Block 2 when investigation=True. Sets HeaderFlag.
        INVESTIGATION in the file header and CapBit.SYSTEM_CONTEXT in the
        capability bitmap (both required by spec §9 when Investigation=1).

        TableBitmap is populated automatically based on which add_*_table
        methods are subsequently called.
        """
        if not self._investigation:
            raise ValueError(
                "add_system_context() requires investigation=True at "
                "MslWriter construction (spec §6.1)"
            )
        # Pure-spec layout — no memdiver deviation tail. The reader still
        # accepts the deviation tail for backward compat with older files;
        # we don't emit it.
        acq_user_b = _pack_padded_str(acq_user) if acq_user else b""
        hostname_b = _pack_padded_str(hostname) if hostname else b""
        domain_b = _pack_padded_str(domain) if domain else b""
        os_detail_b = _pack_padded_str(os_detail) if os_detail else b""
        case_ref_b = _pack_padded_str(case_ref) if case_ref else b""

        def _raw_len(s: str) -> int:
            return (len(s.encode("utf-8")) + 1) if s else 0

        # Header layout per spec §6.2 Table 20: Boot(8) + Targets(4) +
        # TableBitmap(4) + 5×u16 lengths + 6 reserved bytes = 32 bytes.
        # Actual TableBitmap is rewritten at write() time once table
        # children are known.
        header_bytes = struct.pack(
            "<QIIHHHHH6x",
            boot_time_ns, target_count, 0,
            _raw_len(acq_user), _raw_len(hostname), _raw_len(domain),
            _raw_len(os_detail), _raw_len(case_ref),
        )
        payload = (header_bytes + acq_user_b + hostname_b
                   + domain_b + os_detail_b + case_ref_b)
        block_uuid = uuid4()
        self._system_context = (payload, block_uuid, 0)
        self._cap_bitmap |= CapBit.SYSTEM_CONTEXT
        return block_uuid

    def _require_system_context(self, who: str) -> UUID:
        if self._system_context is None:
            raise ValueError(
                f"{who} requires add_system_context() to have been called "
                f"first (spec §6.3 — table blocks reference System Context)"
            )
        return self._system_context[1]

    def add_process_table(self, entries: Sequence[ProcessTableEntry]) -> UUID:
        """Add a Process Table block (spec §6.3, type 0x0051).

        ParentUUID references the System Context block (mandatory).
        """
        sc_uuid = self._require_system_context("add_process_table()")
        rows = list(entries)
        payload = struct.pack("<II", len(rows), 0)
        for e in rows:
            payload += struct.pack(
                "<IIIB3xQQHHH2x",
                e.pid, e.ppid, e.uid, 0x01 if e.is_target else 0,
                e.start_time_ns, e.rss,
                _len_with_nul(e.exe_name), _len_with_nul(e.cmd_line),
                _len_with_nul(e.user),
            )
            payload += _pack_padded_str(e.exe_name) if e.exe_name else b""
            payload += _pack_padded_str(e.cmd_line) if e.cmd_line else b""
            payload += _pack_padded_str(e.user) if e.user else b""
        block_uuid = uuid4()
        self._sc_children.append((BlockType.PROCESS_TABLE, payload, block_uuid, 0))
        # Set TableBitmap bit + CapBitmap bit.
        sc_payload, sc_uuid_, sc_tb = self._system_context
        self._system_context = (sc_payload, sc_uuid_, sc_tb | TableBit.PROCESS_TABLE)
        self._cap_bitmap |= CapBit.SYSTEM_PROCESS_TABLE
        return block_uuid

    def add_connection_table(self, entries: Sequence[ConnectionTableEntry]) -> UUID:
        """Add a Connection Table block (spec §6.4, type 0x0052).

        Spec §6.4 mandates that ports be stored little-endian in the
        block — callers MUST convert from network byte order before
        passing entries to this method.
        """
        sc_uuid = self._require_system_context("add_connection_table()")
        rows = list(entries)
        payload = struct.pack("<II", len(rows), 0)
        for e in rows:
            local = (e.local_addr or b"\x00" * 16).ljust(16, b"\x00")[:16]
            remote = (e.remote_addr or b"\x00" * 16).ljust(16, b"\x00")[:16]
            payload += struct.pack(
                "<IBBBB16sH2x16sH2x",
                e.pid, e.family, e.protocol, e.state, 0,
                local, e.local_port, remote, e.remote_port,
            )
        block_uuid = uuid4()
        self._sc_children.append((BlockType.CONNECTION_TABLE, payload, block_uuid, 0))
        sc_payload, sc_uuid_, sc_tb = self._system_context
        self._system_context = (sc_payload, sc_uuid_, sc_tb | TableBit.CONNECTION_TABLE)
        self._cap_bitmap |= CapBit.SYSTEM_NETWORK_TABLE
        return block_uuid

    def add_handle_table(self, entries: Sequence[HandleTableEntry]) -> UUID:
        """Add a Handle Table block (spec §6.5, type 0x0053)."""
        sc_uuid = self._require_system_context("add_handle_table()")
        rows = list(entries)
        payload = struct.pack("<II", len(rows), 0)
        for e in rows:
            payload += struct.pack(
                "<IIHH4x",
                e.pid, e.fd, e.handle_type, _len_with_nul(e.path),
            )
            payload += _pack_padded_str(e.path) if e.path else b""
        block_uuid = uuid4()
        self._sc_children.append((BlockType.HANDLE_TABLE, payload, block_uuid, 0))
        sc_payload, sc_uuid_, sc_tb = self._system_context
        self._system_context = (sc_payload, sc_uuid_, sc_tb | TableBit.HANDLE_TABLE)
        self._cap_bitmap |= CapBit.SYSTEM_HANDLE_TABLE
        return block_uuid

    def add_pointer_graph(
        self,
        nodes: Sequence[MslPointerGraphNode],
        edges: Sequence[MslPointerGraphEdge],
        emit_integrity: bool = True,
        producer: Optional[str] = None,
    ) -> UUID:
        """Register a POINTER_GRAPH block in its own extension segment.

        POINTER_GRAPH (0x1003) is a producer-defined Structural block, so
        the spec (4.6) admits it only in an extension segment: it is written
        after the End-of-Capture block, chained from it (zero PrevHash inside
        an encrypted container) and closed by an End-of-Extension block. The
        user opts in by calling this method; readers that do not implement
        extension segments stop at EoC and ignore it.

        When *emit_integrity* is True (default), the payload is followed by
        a 32-byte BLAKE3 trailer over (header + nodes + edges). The reader
        surfaces the stored hash on `MslPointerGraph.appendix_hash`; callers
        may use ``decoders_ext.verify_pointer_graph_integrity`` to re-check
        it (the segment's SegmentHash covers the block as well).

        Returns the block's UUID. Calling twice replaces the writer's own
        pointer-graph segment (segments added through
        :meth:`add_extension_segment` are untouched).
        """
        block_uuid = uuid4()
        payload = _build_pointer_graph_payload(
            list(nodes), list(edges), emit_integrity=emit_integrity)
        block = ExtensionBlock(BlockType.POINTER_GRAPH, payload, block_uuid)
        if self._pointer_graph_segment is not None:
            spec = self._extension_segments[self._pointer_graph_segment]
            spec.blocks = [(int(BlockType.POINTER_GRAPH), payload, block_uuid,
                            _ZERO_UUID, 0)]
            if producer is not None:
                spec.producer = producer
        else:
            self._pointer_graph_segment = self.add_extension_segment(
                producer, [block])
        return block_uuid

    def add_connectivity_table(self, rows: Sequence[ConnectivityRow]) -> UUID:
        """Add a Connectivity Table block (spec §6.6, type 0x0055).

        System-wide connectivity snapshot — routes, ARP, packet sockets,
        interface stats, socket-family aggregates, MIB counters. Unlike
        the per-process tables under System Context, this is a top-level
        block; spec has not yet assigned a CapBit, so the bitmap is left
        untouched (SYSTEM_NETWORK_TABLE is for the per-process
        CONNECTION_TABLE 0x0052, a distinct concept).
        """
        payload = _build_connectivity_table_payload(rows)
        block_uuid = uuid4()
        self._blocks.append(
            (BlockType.CONNECTIVITY_TABLE, payload, block_uuid, _ZERO_UUID, 0)
        )
        return block_uuid

    def add_physical_memory_map(self, rows: Sequence[PhysicalRange]) -> UUID:
        """Add a Physical Memory Map block (spec 5.9, type 0x0059, v1.1).

        Host physical address ranges (``/proc/iomem`` top level) at
        acquisition time. Optional, ParentUUID zero. Files using it already
        carry Version 0x0101 (the writer's only version).
        """
        payload = _build_physical_memory_map_payload(rows)
        block_uuid = uuid4()
        self._blocks.append(
            (BlockType.PHYSICAL_MEMORY_MAP, payload, block_uuid, _ZERO_UUID, 0))
        return block_uuid

    # ------------------------------------------------------------------
    # End-of-Capture
    # ------------------------------------------------------------------

    def add_end_of_capture(self, reason: int = 0,
                           acq_end_ns: Optional[int] = None) -> None:
        """Add an End-of-Capture block (spec §4.5).

        The 32-byte file_hash slot is left as zeros here; `write()`
        finalizes it with a digest covering the file header and every
        preceding encoded block, and fills in the block count (the 40-byte
        stub grows to the 48-byte EoC payload). *acq_end_ns* defaults to now.
        """
        if acq_end_ns is None:
            acq_end_ns = int(time.time() * 1e9)
        payload = struct.pack("<32sQ", b"\x00" * 32, acq_end_ns)
        self._end_of_capture = (payload, uuid4())

    # ------------------------------------------------------------------
    # write() — assemble blocks in spec-mandated order
    # ------------------------------------------------------------------

    def write(self) -> None:
        """Write all accumulated blocks to the output file.

        Spec-mandated block ordering (§6.1)::

          Block 0 -> Import Provenance (if imported) OR Process Identity
          Block 1 -> Module List Index (+ Module Entry children)
          Block 2 -> System Context (if investigation) (+ table children)
          Then: generic blocks in user call order (regions, key hints,
                related dumps), then End-of-Capture (last).

        The End-of-Capture block's `file_hash` is finalized over the file
        header + every prior encoded block, so the EoC pins the full
        file contents.

        If any region was registered via add_memory_region_source(), the
        file is emitted by write_streaming() (the only path able to pull
        source bytes).
        """
        if self._has_streamed_regions:
            self.write_streaming()
            return
        ordered = self._prepare_ordered_blocks()
        if self._encryption is not None:
            self._write_encrypted(ordered)
        else:
            self._write_plaintext(ordered)

    def write_streaming(self) -> None:
        """Write the file block-by-block with O(chunk) peak memory.

        Produces the same layout as the plaintext write() path: header with
        the exact pre-computed BlockCount and CapBitmap, BLAKE3-chained
        blocks, EoC FileHash over header + every prior block, then the
        registered extension segments. The prev_hash chain and EoC hasher
        are updated incrementally while bytes are written, and streamed
        region bytes are pulled in STREAM_CHUNK_SIZE pieces. Writes to a
        temp file and calls ``os.replace`` on it on success, like write().

        Encrypted writers stream too (:meth:`_write_streaming_encrypted`):
        the output is byte-identical to the in-memory encrypted write() for
        the same nonce.
        """
        self._require_streamable(CompAlgo.NONE)
        ordered = self._prepare_ordered_blocks()
        if self._encryption is not None:
            self._write_streaming_encrypted(ordered)
            return
        file_header = self._encode_base_header(encrypted=False, block_count=len(ordered))
        file_hasher = _new_hasher()
        file_hasher.update(file_header)
        prev_hash = hash_bytes(file_header)  # §4.4: Block 0 chains from the header
        self._require_eoc_for_extensions(ordered)
        with self._atomic_output() as f:
            f.write(file_header)
            for (block_type, payload, block_uuid, parent_uuid, flags) in ordered:
                if block_type == BlockType.END_OF_CAPTURE:
                    payload = _eoc_payload_with_hash(payload, file_hasher.digest(),
                                                     len(ordered))
                header = self._encode_block_header(block_type, len(payload), block_uuid,
                                                   parent_uuid, prev_hash, flags)
                prev_hash = _stream_block(f, file_hasher, header, payload)
            # prev_hash is now H(EoC block): extension segments chain from it.
            self._emit_extension_segments(f.write, prev_hash, chained=True,
                                          hasher=hash_bytes)
        logger.info("Wrote MSL file (streaming): %s (%d blocks%s)",
                    self._path, len(ordered), self._extension_note())

    def _prepare_ordered_blocks(self) -> List[Tuple[int, bytes, UUID, bytes, int]]:
        """Finalize late-bound payloads, ensure the output dir, return blocks."""
        # Materialize System Context payload with the now-known TableBitmap.
        if self._system_context is not None:
            sc_payload, sc_uuid, sc_tb = self._system_context
            sc_payload = sc_payload[:0x0C] + struct.pack("<I", sc_tb) + sc_payload[0x10:]
            self._system_context = (sc_payload, sc_uuid, sc_tb)

        ordered = self._compose_ordered_blocks()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return ordered

    @contextmanager
    def _atomic_output(self):
        """Yield a writable handle backed by a temp file, then ``os.replace`` it
        onto the destination on clean exit.

        The destination ``.msl`` is the integrity boundary for every produced
        slice; streaming straight to the final path means a mid-write failure
        (disk full, ``KeyboardInterrupt``, kill) leaves a truncated/corrupt file
        that a later reader silently mis-parses. Writing to a sibling temp and
        renaming makes the swap atomic (same-directory rename) — the same
        pattern ``task_manager._persist`` uses.
        """
        tmp = self._path.with_name(f"{self._path.name}.{uuid4().hex}.tmp")
        try:
            with open(tmp, "wb") as f:
                yield f
            os.replace(tmp, self._path)
        except BaseException:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise

    def _write_plaintext(self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Write an unencrypted file: 64-byte header, BLAKE3-chained blocks,
        then the registered extension segments chained from the EoC block."""
        self._require_eoc_for_extensions(ordered)
        file_header = self._encode_base_header(encrypted=False, block_count=len(ordered))
        encoded_blocks: List[Optional[bytes]] = []
        prev_hash = hash_bytes(file_header)  # §4.4: Block 0 chains from the header
        eoc_index: Optional[int] = None

        for idx, (block_type, payload, block_uuid, parent_uuid, flags) in enumerate(ordered):
            if block_type == BlockType.END_OF_CAPTURE:
                eoc_index = idx
                encoded_blocks.append(None)
                continue
            block_data = self._encode_block(block_type, payload,
                                             block_uuid, parent_uuid,
                                             prev_hash, flags)
            encoded_blocks.append(block_data)
            prev_hash = hash_bytes(block_data)

        if eoc_index is not None:
            self._finalize_end_of_capture(
                encoded_blocks, file_header, eoc_index, prev_hash, ordered,
            )
            prev_hash = hash_bytes(encoded_blocks[eoc_index])

        with self._atomic_output() as f:
            f.write(file_header)
            for block in encoded_blocks:
                if block is not None:
                    f.write(block)
            # Extension segments (spec 4.6): chained from H(EoC). Readers
            # without segment support stop at EoC and ignore them.
            self._emit_extension_segments(f.write, prev_hash, chained=True,
                                          hasher=hash_bytes)
        logger.info("Wrote MSL file: %s (%d blocks%s)",
                    self._path, len(ordered), self._extension_note())

    def _write_encrypted(self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Write a full-container AEAD-encrypted file (spec §10).

        Layout: [Header 128B | KEM ct | AEAD(block stream incl. segments) | Tag 16B].
        Per §10.6: every block's PrevHash is zero, the EoC FileHash is computed
        over the plaintext, and the AAD is the 128-byte header plus KEM
        ciphertext. Extension segments (if any) lie inside the encrypted
        region after EoC, before the tag (spec 4.6), with zero PrevHash.

        Spec 1.1.1: the one-shot ciphertext length is known before writing,
        so the final ``CipherLen`` goes straight into the on-disk header;
        the AAD and FileHash still cover it as zero (§10.2, §10.7).
        """
        self._require_eoc_for_extensions(ordered)
        cfg = self._encryption
        file_header, kem_ct, cek, nonce = self._encryption_envelope()
        aad = encryption_aad(file_header, kem_ct)

        # Encode non-EoC blocks with zero PrevHash (§10.6), then EoC with a
        # FileHash over the plaintext (header + KEM ct + preceding blocks).
        pre_eoc: List[bytes] = []
        eoc_entry: Optional[Tuple[bytes, UUID]] = None
        for (block_type, payload, block_uuid, parent_uuid, flags) in ordered:
            if block_type == BlockType.END_OF_CAPTURE:
                eoc_entry = (payload, block_uuid)
                continue
            pre_eoc.append(self._encode_block(block_type, payload, block_uuid,
                                              parent_uuid, _ZERO_HASH, flags))

        # Collect every plaintext part, then join once (no repeated full-stream copies).
        stream_parts: List[bytes] = list(pre_eoc)
        if eoc_entry is not None:
            eoc_payload_stub, eoc_uuid = eoc_entry
            file_hash = hash_stream((file_header, kem_ct, *pre_eoc))
            new_eoc_payload = _eoc_payload_with_hash(eoc_payload_stub, file_hash,
                                                     len(ordered))
            stream_parts.append(self._encode_block(
                BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid,
                _ZERO_UUID, _ZERO_HASH, 0,
            ))
        # Extension segments inside the encrypted region, after EoC.
        self._emit_extension_segments(stream_parts.append, _ZERO_HASH,
                                      chained=False, hasher=hash_bytes)
        block_stream = b"".join(stream_parts)

        ciphertext_and_tag = aead_encrypt(cfg.enc_algo, cek, nonce, aad, block_stream)

        with self._atomic_output() as f:
            f.write(_header_with_cipher_len(file_header, len(block_stream)))
            f.write(kem_ct)
            f.write(ciphertext_and_tag)
        logger.info("Wrote encrypted MSL file: %s (%d blocks, %s%s)",
                    self._path, len(ordered), cfg.enc_algo.name,
                    self._extension_note())

    def _compose_ordered_blocks(self) -> List[Tuple[int, bytes, UUID, bytes, int]]:
        """Return the full block list in spec-mandated emission order.

        Each entry is (block_type, payload, block_uuid, parent_uuid_bytes,
        flags). `flags` is non-zero only for blocks emitted with a
        compression policy; all positional / table / control blocks emit
        zero.
        """
        out: List[Tuple[int, bytes, UUID, bytes, int]] = []

        # Block 0: Import Provenance (imported) OR Process Identity (live).
        if self._imported and self._import_provenance is not None:
            payload, uid = self._import_provenance
            out.append((BlockType.IMPORT_PROVENANCE, payload, uid, _ZERO_UUID, 0))
        elif (not self._imported) and self._process_identity is not None:
            payload, uid = self._process_identity
            out.append((BlockType.PROCESS_IDENTITY, payload, uid, _ZERO_UUID, 0))
        # If neither is set, no positional Block 0 — Memory Region etc.
        # will become Block 0. This is permitted for analysis-mode files
        # where no provenance/identity metadata is available.

        # Block 1: Module List Index, then Module Entry children.
        if self._module_list is not None:
            modules, mli_uuid = self._module_list
            out.append((BlockType.MODULE_LIST_INDEX,
                        _build_module_list_index_payload(modules),
                        mli_uuid, _ZERO_UUID, 0))
            for mod in modules:
                out.append((BlockType.MODULE_ENTRY,
                            _build_module_entry_payload(mod),
                            mod.module_uuid, mli_uuid.bytes, 0))

        # Block 2: System Context (Investigation only), then table children.
        if self._investigation and self._system_context is not None:
            sc_payload, sc_uuid, _ = self._system_context
            out.append((BlockType.SYSTEM_CONTEXT, sc_payload, sc_uuid, _ZERO_UUID, 0))
            for (block_type, payload, block_uuid, flags) in self._sc_children:
                out.append((block_type, payload, block_uuid, sc_uuid.bytes, flags))
        elif (self._system_context is not None) and not self._investigation:
            logger.warning(
                "add_system_context() called but investigation=False; "
                "System Context block will be omitted (spec §6.1)"
            )

        # Generic blocks (memory regions, key hints, related dumps, ...).
        out.extend(self._blocks)

        # End-of-Capture last.
        if self._end_of_capture is not None:
            payload, uid = self._end_of_capture
            out.append((BlockType.END_OF_CAPTURE, payload, uid, _ZERO_UUID, 0))

        return out

    def _finalize_end_of_capture(
        self,
        encoded_blocks: List[Optional[bytes]],
        file_header: bytes,
        eoc_index: int,
        prev_hash: bytes,
        ordered: List[Tuple[int, bytes, UUID, bytes, int]],
    ) -> None:
        """Fill in the EoC block's `file_hash` with a streaming digest.

        Streams the file header and all prior encoded blocks through the
        hasher to avoid materializing a concatenated digest input — MSL
        files can easily reach multi-GB when memory regions are included.
        """
        file_hash = hash_stream(
            (file_header, *(b for b in encoded_blocks if b is not None))
        )
        _, eoc_payload_stub, eoc_uuid, _, _ = ordered[eoc_index]
        new_eoc_payload = _eoc_payload_with_hash(eoc_payload_stub, file_hash,
                                                 len(ordered))
        encoded_blocks[eoc_index] = self._encode_block(
            BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid,
            _ZERO_UUID, prev_hash, 0,
        )

    # ------------------------------------------------------------------
    # Extension segments (spec 4.6)
    # ------------------------------------------------------------------

    def _require_eoc_for_extensions(
            self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Segments follow the End-of-Capture block; refuse to emit without one."""
        if not self._extension_segments:
            return
        if not any(bt == BlockType.END_OF_CAPTURE for bt, *_ in ordered):
            raise ValueError(
                "extension segments require an End-of-Capture block: call "
                "add_end_of_capture() before write()")

    def _extension_note(self) -> str:
        n = len(self._extension_segments)
        return f" + {n} extension segment(s)" if n else ""

    def _segment_written_at(self, spec: _ExtensionSegmentSpec) -> int:
        """WrittenAt for *spec*'s terminator (its own, else the writer's)."""
        if spec.written_at_ns is not None:
            return spec.written_at_ns
        return self._extension_written_at_ns

    def _emit_extension_segments(self, write: Callable[[bytes], object],
                                 prev_hash: bytes, chained: bool,
                                 hasher: Callable[[bytes], bytes]) -> bytes:
        """Emit every registered segment through *write*; return the chain head.

        *prev_hash* is the PrevHash the first segment block continues from
        (H(EoC) in plaintext files). With *chained* False (inside an AEAD
        container, spec 10.6) every PrevHash is written as zero instead.
        Each segment is closed by an End-of-Extension block whose
        SegmentHash is *hasher* over the segment's bytes before it and
        whose BlockCount counts the terminator too.
        """
        for spec in self._extension_segments:
            segment_hasher = _new_hasher()
            for (block_type, payload, block_uuid, parent_uuid, flags) in spec.blocks:
                block = self._encode_block(block_type, payload, block_uuid, parent_uuid,
                                           prev_hash if chained else _ZERO_HASH, flags)
                write(block)
                segment_hasher.update(block)
                prev_hash = hasher(block)
            terminator = self._encode_block(
                BlockType.END_OF_EXTENSION,
                _build_end_of_extension_payload(
                    segment_hasher.digest(), self._segment_written_at(spec),
                    len(spec.blocks) + 1, spec.producer),
                spec.terminator_uuid, _ZERO_UUID,
                prev_hash if chained else _ZERO_HASH, 0)
            write(terminator)
            prev_hash = hasher(terminator)
        return prev_hash

    def _encode_base_header(self, *, encrypted: bool, block_count: int,
                            hash_algo: int = HashAlgo.BLAKE3) -> bytes:
        # binary format 1.1 per MSL Specification v1.0.0 (spec Table 3).
        # Layout: magic(8) endian(1) hdrsize(1) version(2) flags(4)
        # capbitmap(8) dumpuuid(16) timestamp(8) ostype(2) archtype(2)
        # pid(4) clocksource(1) blockcount(4) hashalgo(1) reserved(2) = 64.
        version = (1 << 8) | 1
        flags = 0
        if self._imported:
            flags |= HeaderFlag.IMPORTED
        if self._investigation:
            flags |= HeaderFlag.INVESTIGATION
        if encrypted:
            flags |= HeaderFlag.ENCRYPTED
        header_size = FILE_HEADER_ENC_SIZE if encrypted else FILE_HEADER_SIZE
        return struct.pack(
            "<8sBBHIQ16sQHHIBIB2x",
            FILE_MAGIC, Endianness.LITTLE, header_size, version,
            flags, self._cap_bitmap, self._dump_uuid.bytes,
            self._header_timestamp_ns(), self._os_type, self._arch_type,
            self._pid, self._clock_source, block_count, hash_algo,
        )

    def _header_timestamp_ns(self) -> int:
        if self._timestamp_ns is not None:
            return self._timestamp_ns
        return int(time.time() * 1e9)

    def _encryption_envelope(self) -> Tuple[bytes, bytes, bytes, bytes]:
        """(128-byte header, KEM ct, CEK, cipher nonce) for an encrypted write.

        Shared by the in-memory and the streaming encrypted paths. In re-wrap
        mode the CEK, KDF salt/params and KEM ciphertext come from the source
        container; the nonce is always fresh (never the source nonce).
        """
        cfg = self._encryption
        kdf_salt = cfg.kdf_salt
        if kdf_salt is None:
            kdf_salt = os.urandom(16) if cfg.kdf_type == KdfType.ARGON2ID else b"\x00" * 16
        nonce_field = cfg.nonce if cfg.nonce is not None else random_nonce(cfg.enc_algo)
        if cfg.rewrap_material is not None:
            cek, kem_ct = self._rewrap_cek(cfg.rewrap_material, nonce_field)
        else:
            cek, kem_ct = derive_cek_producer(
                key_encap=cfg.key_encap, kdf_type=cfg.kdf_type,
                dump_uuid_bytes=self._dump_uuid.bytes,
                raw_key=cfg.raw_key, passphrase=cfg.passphrase, kdf_salt=kdf_salt,
                kdf_time=cfg.kdf_time, kdf_memory=cfg.kdf_memory,
                kdf_lanes=cfg.kdf_lanes, recipient_public=cfg.recipient_public,
            )
        # BlockCount=0 for encrypted files: the count would otherwise leak in
        # the cleartext header, defeating full-container confidentiality. The
        # spec permits 0 ("unknown/streaming").
        base = self._encode_base_header(encrypted=True, block_count=0)
        ext = self._encode_enc_extension(cfg, nonce_field, kdf_salt, len(kem_ct))
        return base + ext, kem_ct, cek, nonce_for_cipher(cfg.enc_algo, nonce_field)

    def _rewrap_cek(self, material: RewrapMaterial,
                    nonce_field: bytes) -> Tuple[bytes, bytes]:
        """Validate a re-wrap and return (source CEK, source KEM ct)."""
        n = len(nonce_for_cipher(material.enc_algo, nonce_field))
        if nonce_field[:n] == material.source_nonce[:n]:
            raise ValueError("refusing to reuse the source container's AEAD "
                             "nonce for a re-wrapped copy")
        if (material.key_encap != KeyEncap.NONE
                and material.dump_uuid_bytes != self._dump_uuid.bytes):
            # KEM CEK = HKDF(shared, salt=DumpUUID): a new UUID would make the
            # reused KEM ciphertext derive a different key on open.
            raise ValueError("a KEM re-wrap must keep the source dump_uuid")
        return material.cek, material.kem_ciphertext

    def _write_streaming_encrypted(
            self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Streaming twin of :meth:`_write_encrypted` (same bytes, O(chunk) RAM).

        One incremental AEAD (:mod:`memdiver.msl.aead_stream`) over the same
        plaintext block stream: zero PrevHash, EoC FileHash over header + KEM
        ct + every pre-EoC block, extension segments after EoC, 16-byte tag
        last. The header is written with ``CipherLen=0`` and patched once
        after the tag (spec 1.1.1 §10.7; the temp output is seekable).
        """
        self._require_eoc_for_extensions(ordered)
        cfg = self._encryption
        file_header, kem_ct, cek, nonce = self._encryption_envelope()
        sealer = aead_stream_encryptor(cfg.enc_algo, cek, nonce,
                                       encryption_aad(file_header, kem_ct))
        file_hasher = _new_hasher()
        file_hasher.update(file_header)
        file_hasher.update(kem_ct)
        eoc_entry: Optional[Tuple[bytes, UUID]] = None
        with self._atomic_output() as f:
            f.write(file_header)
            f.write(kem_ct)
            for (block_type, payload, block_uuid, parent_uuid, flags) in ordered:
                if block_type == BlockType.END_OF_CAPTURE:
                    eoc_entry = (payload, block_uuid)
                    continue
                header = self._encode_block_header(block_type, len(payload), block_uuid,
                                                   parent_uuid, _ZERO_HASH, flags)
                _seal_block(f, sealer, file_hasher, header, payload)
            if eoc_entry is not None:
                eoc_payload = _eoc_payload_with_hash(eoc_entry[0], file_hasher.digest(),
                                                     len(ordered))
                f.write(sealer.update(self._encode_block(
                    BlockType.END_OF_CAPTURE, eoc_payload, eoc_entry[1],
                    _ZERO_UUID, _ZERO_HASH, 0)))
            self._emit_extension_segments(
                lambda data: f.write(sealer.update(data)), _ZERO_HASH,
                chained=False, hasher=hash_bytes)
            cipher_len = f.tell() - len(file_header) - len(kem_ct)
            f.write(sealer.finalize())
            _patch_cipher_len(f, cipher_len)
        logger.info("Wrote encrypted MSL file (streaming): %s (%d blocks, %s%s)",
                    self._path, len(ordered), cfg.enc_algo.name,
                    self._extension_note())

    def _encode_enc_extension(self, cfg: "MslEncryptionConfig",
                              nonce_field: bytes, kdf_salt: bytes,
                              kem_ct_len: int) -> bytes:
        # Encryption extension header (spec Table 5, 64 bytes at 0x40-0x7F).
        # EncAlgo(1) KDFType(1) KeyEncap(1) Rsv(1) KDFTime(4) KDFMemory(4)
        # KDFLanes(1) Rsv2(1) KEMCtLen(2) Nonce(24) KDFSalt(16) CipherLen(8) = 64.
        # CipherLen is written as 0 here; the encrypted write paths fill it in.
        nonce_field = nonce_field.ljust(24, b"\x00")[:24]
        kdf_salt = kdf_salt.ljust(16, b"\x00")[:16]
        return struct.pack(
            "<BBBxIIBxH24s16s8x",
            int(cfg.enc_algo), int(cfg.kdf_type), int(cfg.key_encap),
            cfg.kdf_time, cfg.kdf_memory, cfg.kdf_lanes,
            kem_ct_len, nonce_field, kdf_salt,
        )

    def _encode_block(self, block_type: int, payload: bytes,
                      block_uuid: UUID, parent_uuid: bytes,
                      prev_hash: bytes, flags: int = 0) -> bytes:
        header = self._encode_block_header(block_type, len(payload), block_uuid,
                                           parent_uuid, prev_hash, flags)
        return header + payload

    def _encode_block_header(self, block_type: int, payload_len: int,
                             block_uuid: UUID, parent_uuid: bytes,
                             prev_hash: bytes, flags: int = 0) -> bytes:
        total_len = BLOCK_HEADER_SIZE + payload_len
        if total_len > _U32_MAX:
            # BlockLength is a u32 (spec Table 6). Memory regions are split
            # below REGION_BLOCK_CAP, so only an oversized generic payload
            # (or a cap > 4 GiB) can reach this.
            raise ValueError(
                f"block of {total_len} bytes exceeds the u32 BlockLength limit"
            )
        return struct.pack(
            "<4sHHIH2x16s16s32s",
            BLOCK_MAGIC, block_type, flags, total_len, 1,
            block_uuid.bytes, parent_uuid, prev_hash,
        )


# ---------------------------------------------------------------------- helpers


def build_import_provenance_payload(source_format: int, tool_name: str,
                                    orig_file_size: int, note: str = "",
                                    source_path: Optional[Path] = None) -> bytes:
    """Encode an IMPORT_PROVENANCE payload (spec §11).

    Shared by add_import_provenance() and callers that place the block
    themselves via add_raw_block().
    """
    tool_bytes = _pack_padded_str(tool_name)
    tool_raw_len = len(tool_name.encode("utf-8")) + 1
    note_bytes = _pack_padded_str(note) if note else b""
    note_raw_len = (len(note.encode("utf-8")) + 1) if note else 0
    payload = struct.pack("<H2xIQQI4x", source_format, tool_raw_len,
                          int(time.time() * 1e9), orig_file_size,
                          note_raw_len)
    payload += tool_bytes + note_bytes
    payload += _file_digest_or_zero(source_path)
    return payload


def _len_with_nul(s: str) -> int:
    """Length of UTF-8 bytes plus NUL terminator (0 if empty)."""
    return (len(s.encode("utf-8")) + 1) if s else 0


def _pack_cipher_len(cipher_len: int) -> bytes:
    """Header ``CipherLen`` field (spec 1.1.1 Table 5): u64 little-endian."""
    return struct.pack("<Q", cipher_len)


def _header_with_cipher_len(header: bytes, cipher_len: int) -> bytes:
    """Return the 128-byte encrypted *header* with ``CipherLen`` filled in."""
    end = CIPHER_LEN_OFFSET + CIPHER_LEN_SIZE
    return header[:CIPHER_LEN_OFFSET] + _pack_cipher_len(cipher_len) + header[end:]


def _patch_cipher_len(f, cipher_len: int) -> None:
    """One-time ``CipherLen`` patch after the tag (spec 1.1.1 §10.7)."""
    resume = f.tell()
    f.seek(CIPHER_LEN_OFFSET)
    f.write(_pack_cipher_len(cipher_len))
    f.seek(resume)


def _eoc_payload_with_hash(eoc_payload_stub: bytes, file_hash: bytes,
                           block_count: int) -> bytes:
    """Return the 48-byte EoC payload: *file_hash* and *block_count* filled in.

    Layout: FileHash(32) AcqEnd(8) BlockCount(4) Reserved(4). acq_end_ns is
    kept from the stub; *block_count* counts every capture-segment block
    including the EoC itself.
    """
    acq_end_ns = struct.unpack_from("<Q", eoc_payload_stub, 32)[0]
    return file_hash + struct.pack("<QII", acq_end_ns, block_count, 0)


def _build_end_of_extension_payload(segment_hash: bytes, written_at_ns: int,
                                    block_count: int, producer: str) -> bytes:
    """End-of-Extension payload (spec Table 12a).

    Layout: SegmentHash(32) WrittenAt(8) BlockCount(4) Reserved(4)
    ProducerLen(2, incl. NUL, 0 = none) Reserved(6) Producer(UTF-8, NUL, pad8).
    Byte-identical to memslicer's ``finalize_extension``.
    """
    producer = producer or ""
    if _len_with_nul(producer) > 0xFFFF:
        producer = ""
    head = struct.pack("<32sQIIH6x", segment_hash, written_at_ns, block_count, 0,
                       _len_with_nul(producer))
    return head + (_pack_padded_str(producer) if producer else b"")


# -- Memory region splitting / streaming helpers --


@dataclass(frozen=True)
class _RegionMeta:
    """Per-region header fields shared by every chunk block of the region."""
    protection: int
    region_type: int
    page_size_log2: int
    timestamp_ns: int


@dataclass(frozen=True)
class _RegionChunk:
    """One MEMORY_REGION block's slice of a (possibly larger) region."""
    base_addr: int
    first_page: int
    page_count: int
    data_offset: int  # offset into the region's captured-byte stream
    data_len: int


@dataclass(frozen=True)
class _StreamedRegionPayload:
    """Deferred MEMORY_REGION payload: fixed prefix + bytes from a source.

    ``len()`` reports the full on-disk payload length so the block header
    can be packed before any source byte is read.
    """
    prefix: bytes
    read_chunk: ReadChunk
    data_offset: int
    data_len: int

    def __len__(self) -> int:
        return len(self.prefix) + self.data_len

    def iter_pieces(self, chunk_size: int = STREAM_CHUNK_SIZE) -> Iterator[memoryview]:
        yield memoryview(self.prefix)
        done = 0
        while done < self.data_len:
            want = min(chunk_size, self.data_len - done)
            piece = memoryview(self.read_chunk(self.data_offset + done, want))
            if piece.nbytes != want:
                raise ValueError(
                    f"read_chunk returned {piece.nbytes} bytes at offset "
                    f"{self.data_offset + done}, expected {want}"
                )
            yield piece
            done += want


def _stream_block(f, file_hasher, header: bytes, payload) -> bytes:
    """Write one block, feeding the file hasher; return the block's hash."""
    block_hasher = _new_hasher()
    pieces = (payload.iter_pieces() if isinstance(payload, _StreamedRegionPayload)
              else (payload,))
    for piece in itertools.chain((header,), pieces):
        f.write(piece)
        block_hasher.update(piece)
        file_hasher.update(piece)
    return block_hasher.digest()


def _seal_block(f, sealer, file_hasher, header: bytes, payload) -> None:
    """Encrypt one plaintext block into *f*, feeding the EoC file hasher."""
    pieces = (payload.iter_pieces() if isinstance(payload, _StreamedRegionPayload)
              else (payload,))
    for piece in itertools.chain((header,), pieces):
        view = memoryview(piece)
        file_hasher.update(view)
        # Seal in SEAL_PIECE_SIZE slices: each update() allocates its whole
        # ciphertext, so this caps the transient buffer independently of the
        # (up to STREAM_CHUNK_SIZE) source piece.
        for start in range(0, view.nbytes, SEAL_PIECE_SIZE):
            f.write(sealer.update(view[start:start + SEAL_PIECE_SIZE]))


def _in_memory_page_count(data_len: int, page_size: int,
                          page_states: Optional[Sequence[int]]) -> int:
    """Validate in-memory region data against page states; return page count."""
    if page_states is None:
        # Backward-compat: data is the whole region; all pages CAPTURED.
        if data_len % page_size != 0:
            raise ValueError(
                f"region_size={data_len} is not a multiple of "
                f"page_size={page_size} (MSL Specification v1.0.0 §5.1)"
            )
        return data_len // page_size
    # Three-state model. region_size derives from page count, not from data
    # length, because FAILED/UNMAPPED pages contribute zero bytes to data.
    captured_count = _count_captured(page_states, 0, len(page_states))
    expected_data_len = captured_count * page_size
    if data_len != expected_data_len:
        raise ValueError(
            f"data length {data_len} does not match expected "
            f"{expected_data_len} bytes for {captured_count} "
            f"CAPTURED pages × page_size={page_size}"
        )
    return len(page_states)


def _source_page_count(region_size: int, page_size: int,
                       page_states: Optional[Sequence[int]]) -> int:
    """Validate a streamed region's size against page states; return pages."""
    if region_size % page_size != 0:
        raise ValueError(
            f"region_size={region_size} is not a multiple of "
            f"page_size={page_size} (MSL Specification v1.0.0 §5.1)"
        )
    num_pages = region_size // page_size
    if page_states is not None and len(page_states) != num_pages:
        raise ValueError(
            f"page_states has {len(page_states)} entries but region_size="
            f"{region_size} spans {num_pages} pages"
        )
    return num_pages


def _count_captured(page_states: Optional[Sequence[int]],
                    first: int, count: int) -> int:
    if page_states is None:
        return count
    captured = int(PageState.CAPTURED)
    return sum(1 for s in page_states[first:first + count] if int(s) == captured)


def _plan_region_chunks(base_addr: int, page_size: int, num_pages: int,
                        page_states: Optional[Sequence[int]],
                        cap_pages: int) -> List[_RegionChunk]:
    """Split a region into <= cap_pages chunks at page boundaries.

    Always yields at least one chunk (an empty region stays one block).
    Each chunk's data_offset/data_len locate its CAPTURED bytes inside the
    region's captured-byte stream.
    """
    chunks: List[_RegionChunk] = []
    first_page = data_offset = 0
    while True:
        page_count = min(cap_pages, num_pages - first_page)
        data_len = _count_captured(page_states, first_page, page_count) * page_size
        chunks.append(_RegionChunk(base_addr + first_page * page_size,
                                   first_page, page_count, data_offset, data_len))
        first_page += page_count
        data_offset += data_len
        if first_page >= num_pages:
            return chunks


def _region_payload_prefix(chunk: _RegionChunk, page_size: int,
                           page_states: Optional[Sequence[int]],
                           meta: _RegionMeta) -> bytes:
    """Encode a chunk's MEMORY_REGION header + PageStateMap (spec §5.1)."""
    header = struct.pack("<QQBBB5xQ", chunk.base_addr,
                         chunk.page_count * page_size, meta.protection,
                         meta.region_type, meta.page_size_log2,
                         meta.timestamp_ns)
    if page_states is None:
        psm = b"\x00" * _pad8((chunk.page_count + 3) // 4)  # all CAPTURED
    else:
        end = chunk.first_page + chunk.page_count
        psm = _encode_page_state_map(page_states[chunk.first_page:end])
    return header + psm


def _encode_comp_flags(algo: CompAlgo) -> int:
    """Encode a CompAlgo into the BlockFlag bits the reader expects.

    Layout (spec Table 7, mirroring reader at msl/types.py:85-87):
      bit 0       = COMPRESSED  (1 if compressed, 0 if not)
      bits 1..2   = algo index  (NONE=0, ZSTD=1, LZ4=2)

    CompAlgo.NONE returns 0. Any other value sets bit 0 and packs the
    algo into bits 1-2 — so ZSTD → 0b011 (3), LZ4 → 0b101 (5).
    """
    if algo is CompAlgo.NONE:
        return 0
    return (int(algo) << 1) | BlockFlag.COMPRESSED


def _encode_page_state_map(page_states: Sequence[int]) -> bytes:
    """Encode per-page states as a 2-bit-per-page bitmap, padded to 8 bytes.

    Bit ordering matches `page_map.decode_page_intervals`: page i lives at
    byte (i // 4), shift (6 - 2 * (i % 4)) — MSB-first within each byte.
    """
    num_pages = len(page_states)
    if num_pages == 0:
        return b""
    raw_len = (num_pages + 3) // 4
    buf = bytearray(_pad8(raw_len))
    for i, state in enumerate(page_states):
        bits = int(state) & 0x03
        byte_idx = i // 4
        shift = 6 - 2 * (i % 4)
        buf[byte_idx] |= (bits << shift)
    return bytes(buf)


# Thread Context (spec Tables 19a/19b): ThreadID(8) StartTime(8) Flags(2)
# ThreadState(1) Arch(1) RegCount(4) NameLen(2) Reserved(6), ThreadName
# (pad8, omitted when NameLen=0); then per register NameLen(1) Width(1)
# Flags(2) Reserved(4) + Name (pad8) + Value (pad8).
_THREAD_CONTEXT_HEAD = "<QQHBBIH6x"
_THREAD_REGISTER_HEAD = "<BBH4x"
_U8_MAX = 0xFF


def _build_thread_context_payload(thread_id: int, start_time: int,
                                  flags: int, state: int, arch: int,
                                  name: str,
                                  registers: Sequence[MslThreadRegister]) -> bytes:
    """Encode a Thread Context payload (spec Tables 19a/19b)."""
    for field_name, value in (("ThreadState", state), ("Arch", arch)):
        if not 0 <= int(value) <= _U8_MAX:
            raise ValueError(f"Thread Context {field_name} {value} must fit u8")
    regs = list(registers)
    head = struct.pack(_THREAD_CONTEXT_HEAD, thread_id, start_time, flags,
                       int(state), int(arch), len(regs), _len_with_nul(name))
    name_bytes = _pack_padded_str(name) if name else b""
    return head + name_bytes + b"".join(_pack_thread_register(r) for r in regs)


def _pack_thread_register(register: MslThreadRegister) -> bytes:
    """Encode one Table 19b register entry (lowercase name, pad8 fields)."""
    name = register.name.lower()
    raw_name_len = _len_with_nul(name)
    if not name or raw_name_len > _U8_MAX:
        raise ValueError(f"Thread register name {name!r} must be 1..254 bytes")
    if not 1 <= register.width <= _U8_MAX or len(register.value) != register.width:
        raise ValueError(
            f"Thread register {name!r}: width {register.width} must be 1..255 "
            f"and equal the value length {len(register.value)}")
    head = struct.pack(_THREAD_REGISTER_HEAD, raw_name_len, register.width,
                       register.flags)
    value = bytes(register.value).ljust(_pad8(register.width), b"\x00")
    return head + _pack_padded_str(name) + value


def _build_vas_map_payload(entries: Sequence[MslVasEntry]) -> bytes:
    """Encode VAS_MAP entries (see :meth:`MslWriter.add_vas_map`)."""
    entries = list(entries)
    parts = [struct.pack("<II", len(entries), 0)]
    for e in entries:
        path = e.mapped_path or ""
        if _len_with_nul(path) > 0xFFFF:  # u16 path_len: drop, never fail
            path = ""
        parts.append(struct.pack("<QQBBHB3x", e.base_addr, e.region_size,
                                 int(e.protection) & 0xFF,
                                 int(e.region_type) & 0xFF,
                                 _len_with_nul(path) if path else 0,
                                 int(e.name_source) & 0xFF))
        parts.append(_pack_padded_str(path) if path else b"")
    return b"".join(parts)


def _build_module_list_index_payload(modules: Sequence[ModuleEntrySpec]) -> bytes:
    """Encode a Module List Index (Variant A: inline entries) per spec §5.3."""
    payload = struct.pack("<II", len(modules), 0)
    for m in modules:
        path_raw_len = _len_with_nul(m.path)
        # +0x00 module_uuid (16) +0x10 base_addr (8) +0x18 module_size (8)
        # +0x20 path_len (2) +0x22 reserved (2) +0x24 reserved (4) +0x28 path (var, pad8)
        payload += struct.pack(
            "<16sQQH2xI",
            m.module_uuid.bytes, m.base_addr, m.module_size, path_raw_len,
            0,  # reserved u32
        )
        payload += _pack_padded_str(m.path) if m.path else b""
    return payload


def _build_module_entry_payload(m: ModuleEntrySpec) -> bytes:
    """Encode a Module Entry block payload per spec §5.2."""
    path_raw_len = _len_with_nul(m.path)
    version_raw_len = _len_with_nul(m.version)
    # +0x00 base_addr (8) +0x08 module_size (8) +0x10 path_len (2)
    # +0x12 version_len (2) +0x14 reserved (4) +0x18 path (var, pad8)
    # then version (var, pad8), then disk_hash (32), then blob_len (4)
    # +4 reserved + native_blob (var). decode_module_entry only reads
    # path, version, disk_hash — we omit native_blob (blob_len=0).
    payload = struct.pack(
        "<QQHH4x",
        m.base_addr, m.module_size, path_raw_len, version_raw_len,
    )
    payload += _pack_padded_str(m.path) if m.path else b""
    payload += _pack_padded_str(m.version) if m.version else b""
    disk_hash = m.disk_hash if m.disk_hash else b"\x00" * 32
    if len(disk_hash) < 32:
        disk_hash = disk_hash.ljust(32, b"\x00")
    elif len(disk_hash) > 32:
        disk_hash = disk_hash[:32]
    payload += disk_hash
    return payload


# -- Connectivity Table row encoders (mirror of decoders._CONN_ROW_DISPATCH) --


def _pack_conn_string(s: str) -> bytes:
    """Pack a uint16 length-prefixed UTF-8 string for a Connectivity row.

    Unlike spec Table 20 strings (8-byte aligned), Connectivity row strings
    pack tight — the row's RowLen field gives the explicit extent. Empty
    string emits Len=0 with no body bytes. Mirrors the decoder's
    `_read_conn_str` (decoders.py:404).
    """
    if not s:
        return struct.pack("<H", 0)
    raw = s.encode("utf-8") + b"\x00"
    return struct.pack("<H", len(raw)) + raw


def _pack_conn_row(row_type: int, body: bytes) -> bytes:
    """Wrap a row body with the 3-byte tag header (RowType + RowLen)."""
    return struct.pack("<BH", row_type, len(body)) + body


def _encode_conn_ipv4_route(r: MslConnIPv4Route) -> bytes:
    body = _pack_conn_string(r.iface)
    body += r.dest + r.gateway + r.mask
    body += struct.pack("<HII", r.flags, r.metric, r.mtu)
    return _pack_conn_row(ConnRowType.IPV4_ROUTE, body)


def _encode_conn_ipv6_route(r: MslConnIPv6Route) -> bytes:
    body = _pack_conn_string(r.iface)
    body += r.dest
    body += struct.pack("<B", r.dest_prefix)
    body += r.next_hop
    body += struct.pack("<II", r.metric, r.flags)
    return _pack_conn_row(ConnRowType.IPV6_ROUTE, body)


def _encode_conn_arp_entry(r: MslConnArpEntry) -> bytes:
    body = struct.pack("<B", r.family)
    body += r.ip
    body += struct.pack("<HH", r.hw_type, r.flags)
    body += r.hw_addr
    body += _pack_conn_string(r.iface)
    return _pack_conn_row(ConnRowType.ARP_ENTRY, body)


def _encode_conn_packet_socket(r: MslConnPacketSocket) -> bytes:
    body = struct.pack(
        "<IQHIIQ",
        r.pid, r.inode, r.proto, r.iface_index, r.user, r.mem,
    )
    return _pack_conn_row(ConnRowType.PACKET_SOCKET, body)


def _encode_conn_iface_stats(r: MslConnIfaceStats) -> bytes:
    body = _pack_conn_string(r.iface)
    body += struct.pack(
        "<8Q",
        r.rx_bytes, r.rx_pkts, r.rx_err, r.rx_drop,
        r.tx_bytes, r.tx_pkts, r.tx_err, r.tx_drop,
    )
    return _pack_conn_row(ConnRowType.IFACE_STATS, body)


def _encode_conn_socket_family_agg(r: MslConnSocketFamilyAgg) -> bytes:
    body = struct.pack("<BIIQ", r.family, r.in_use, r.alloc, r.mem)
    return _pack_conn_row(ConnRowType.SOCKET_FAMILY_AGG, body)


def _encode_conn_mib_counter(r: MslConnMibCounter) -> bytes:
    body = _pack_conn_string(r.mib)
    body += _pack_conn_string(r.counter)
    body += struct.pack("<Q", r.value)
    return _pack_conn_row(ConnRowType.MIB_COUNTER, body)


_CONN_ROW_ENCODERS = {
    MslConnIPv4Route: _encode_conn_ipv4_route,
    MslConnIPv6Route: _encode_conn_ipv6_route,
    MslConnArpEntry: _encode_conn_arp_entry,
    MslConnPacketSocket: _encode_conn_packet_socket,
    MslConnIfaceStats: _encode_conn_iface_stats,
    MslConnSocketFamilyAgg: _encode_conn_socket_family_agg,
    MslConnMibCounter: _encode_conn_mib_counter,
}


# -- POINTER_GRAPH encoder (MemDiver extension-segment block, type 0x1003) --


def _encode_pointer_graph_node(node: MslPointerGraphNode) -> bytes:
    """Encode one POINTER_GRAPH node: 12-byte header + pad8(label)."""
    label_len = _len_with_nul(node.label)
    header = struct.pack(
        "<BBHQ",
        node.node_kind & 0xFF, 0, label_len, node.value,
    )
    return header + (_pack_padded_str(node.label) if node.label else b"")


def _encode_pointer_graph_edge(edge: MslPointerGraphEdge) -> bytes:
    """Encode one POINTER_GRAPH edge: 12-byte header + pad8(metadata)."""
    meta_len = _len_with_nul(edge.metadata)
    header = struct.pack(
        "<IIBBH",
        edge.src_idx, edge.dst_idx,
        edge.edge_kind & 0xFF, 0, meta_len,
    )
    return header + (_pack_padded_str(edge.metadata) if edge.metadata else b"")


def _build_pointer_graph_payload(
    nodes: Sequence[MslPointerGraphNode],
    edges: Sequence[MslPointerGraphEdge],
    emit_integrity: bool = True,
) -> bytes:
    """Encode a POINTER_GRAPH payload (layout in docs/file_formats/msl_v1_0_0.md).

    Header (16 bytes): node_count, edge_count, flags, reserved (u32 each);
    then the nodes, the edges and — when *emit_integrity* — a 32-byte
    BLAKE3 trailer over everything before it.
    """
    pg_flags = POINTER_GRAPH_INTEGRITY_FLAG if emit_integrity else 0
    payload_header = struct.pack(
        "<IIII", len(nodes), len(edges), pg_flags, 0,
    )
    nodes_blob = b"".join(_encode_pointer_graph_node(n) for n in nodes)
    edges_blob = b"".join(_encode_pointer_graph_edge(e) for e in edges)
    payload_body = payload_header + nodes_blob + edges_blob
    if emit_integrity:
        return payload_body + hash_bytes(payload_body)
    return payload_body


def _build_pointer_graph_block(
    nodes: Sequence[MslPointerGraphNode],
    edges: Sequence[MslPointerGraphEdge],
    block_uuid: UUID,
    emit_integrity: bool = True,
    prev_hash: bytes = _ZERO_HASH,
) -> bytes:
    """Encode a full POINTER_GRAPH block (80-byte header + payload).

    Kept for callers that assemble segments by hand; ``MslWriter`` emits the
    block through :meth:`MslWriter._emit_extension_segments`, which supplies
    the chained *prev_hash*.
    """
    payload = _build_pointer_graph_payload(nodes, edges, emit_integrity)
    total_len = BLOCK_HEADER_SIZE + len(payload)
    block_header = struct.pack(
        "<4sHHIH2x16s16s32s",
        BLOCK_MAGIC, BlockType.POINTER_GRAPH, 0, total_len, 1,
        block_uuid.bytes, _ZERO_UUID, prev_hash,
    )
    return block_header + payload


def _build_physical_memory_map_payload(rows: Sequence[PhysicalRange]) -> bytes:
    """Encode a Physical Memory Map payload (spec 5.9 Table 25).

    ``u32 RowCount, u32 Reserved``; rows packed back to back (``u64 Start,
    u64 End`` inclusive, ``u16 LabelLen, u16 Reserved``, UTF-8 label, no NUL,
    no per-row padding); the whole payload padded to 8 bytes.
    """
    rows = list(rows)
    parts = [struct.pack("<II", len(rows), 0)]
    for r in rows:
        label = r.label.encode("utf-8")
        if r.start < 0 or r.end_inclusive < r.start or r.end_inclusive > 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                f"invalid physical range {r.start:#x}..{r.end_inclusive:#x}")
        if len(label) > 0xFFFF:
            raise ValueError("physical range label exceeds 65535 bytes")
        parts.append(struct.pack("<QQHH", r.start, r.end_inclusive, len(label), 0))
        parts.append(label)
    payload = b"".join(parts)
    return payload + b"\x00" * (_pad8(len(payload)) - len(payload))


def _build_connectivity_table_payload(
    rows: Sequence[ConnectivityRow],
) -> bytes:
    """Encode a Connectivity Table payload (type 0x0055) per spec Table 25.

    Header: RowCount(u32 LE) + Reserved(u32 LE). Rows follow as a tight
    concatenation of tagged bodies (RowType u8 + RowLen u16 + body).
    Strings inside rows are uint16-length-prefixed UTF-8+NUL — NOT
    8-byte aligned, because RowLen gives explicit extent. Exposed at
    module scope so tests can compare wire bytes against the standalone
    fixture builder.
    """
    encoded_rows = []
    for row in rows:
        encoder = _CONN_ROW_ENCODERS.get(type(row))
        if encoder is None:
            raise ValueError(
                f"Unsupported connectivity row type: {type(row).__name__}"
            )
        encoded_rows.append(encoder(row))
    return struct.pack("<II", len(rows), 0) + b"".join(encoded_rows)
