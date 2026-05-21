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

import logging
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from uuid import UUID, uuid4

from .compress import compress
from .crypto import (aead_encrypt, derive_cek_producer, nonce_for_cipher,
                     random_nonce)
from .enums import (ARGON2ID_MIN_LANES, ARGON2ID_MIN_MEMORY_KIB,
                    ARGON2ID_MIN_TIME, BLOCK_HEADER_SIZE, BLOCK_MAGIC,
                    FILE_HEADER_ENC_SIZE, FILE_HEADER_SIZE, FILE_MAGIC,
                    POINTER_GRAPH_INTEGRITY_FLAG, ArchType, BlockFlag,
                    BlockType, CompAlgo, ConnRowType, EncAlgo, Endianness,
                    HashAlgo, HeaderFlag, KdfType, KeyEncap, OSType, PageState)
from .hashing import hash_bytes, hash_file, hash_stream
from .types import (ConnectivityRow, MslConnArpEntry, MslConnIfaceStats,
                    MslConnIPv4Route, MslConnIPv6Route, MslConnMibCounter,
                    MslConnPacketSocket, MslConnSocketFamilyAgg,
                    MslPointerGraphEdge, MslPointerGraphNode)

logger = logging.getLogger("memdiver.msl.writer")

_ZERO_HASH = b"\x00" * 32
_ZERO_UUID = b"\x00" * 16


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
    """
    enc_algo: EncAlgo = EncAlgo.AES_256_GCM
    kdf_type: KdfType = KdfType.NONE
    key_encap: KeyEncap = KeyEncap.NONE
    raw_key: Optional[bytes] = None
    passphrase: Optional[bytes] = None
    recipient_public: Optional[bytes] = None
    kdf_time: int = ARGON2ID_MIN_TIME
    kdf_memory: int = ARGON2ID_MIN_MEMORY_KIB
    kdf_lanes: int = ARGON2ID_MIN_LANES
    nonce: Optional[bytes] = None       # 24-byte Nonce field; None -> CSPRNG
    kdf_salt: Optional[bytes] = None    # 16-byte salt; None -> CSPRNG when Argon2id


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
      * Memory regions, key hints, related dumps, and any other generic
        blocks follow in the order their add_* method was called.
      * End-of-Capture, if added, is always emitted last and its file_hash
        is finalized over the actual on-disk byte stream.
    """

    def __init__(self, path: Path, pid: int = 0,
                 os_type: int = OSType.UNKNOWN,
                 arch_type: int = ArchType.UNKNOWN,
                 imported: bool = True,
                 investigation: bool = False,
                 encryption: Optional["MslEncryptionConfig"] = None):
        self._path = Path(path)
        self._pid = pid
        self._os_type = os_type
        self._arch_type = arch_type
        self._imported = imported
        self._investigation = investigation
        self._encryption = encryption
        self._dump_uuid = uuid4()
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
        # Optional POINTER_GRAPH appendix (spec §A, MemDiver extension).
        # When set, written verbatim after EoC (and after the AEAD Tag for
        # encrypted containers in Phase C). Lives outside the BLAKE3 chain.
        # Tuple shape: (encoded_appendix_block_bytes, block_uuid).
        self._pointer_graph_appendix: Optional[Tuple[bytes, UUID]] = None

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
        """
        if not (10 <= page_size_log2 <= 40):
            raise ValueError(
                f"page_size_log2={page_size_log2} out of spec range [10, 40] "
                f"(MSL Specification v1.0.0 §5.1)"
            )
        page_size = 1 << page_size_log2

        if page_states is None:
            # Backward-compat: data is the whole region; all pages CAPTURED.
            region_size = len(data)
            if region_size % page_size != 0:
                raise ValueError(
                    f"region_size={region_size} is not a multiple of "
                    f"page_size={page_size} (MSL Specification v1.0.0 §5.1)"
                )
            num_pages = region_size // page_size
            psm_bytes = (num_pages + 3) // 4
            psm_padded = _pad8(psm_bytes)
            page_state_map = b"\x00" * psm_padded  # all CAPTURED
        else:
            # Three-state model. region_size derives from page count, not
            # from data length, because FAILED/UNMAPPED pages contribute
            # zero bytes to data.
            num_pages = len(page_states)
            region_size = num_pages * page_size
            captured_count = sum(
                1 for s in page_states if int(s) == int(PageState.CAPTURED)
            )
            expected_data_len = captured_count * page_size
            if len(data) != expected_data_len:
                raise ValueError(
                    f"data length {len(data)} does not match expected "
                    f"{expected_data_len} bytes for {captured_count} "
                    f"CAPTURED pages × page_size={page_size}"
                )
            page_state_map = _encode_page_state_map(page_states)

        payload = struct.pack("<QQBBB5xQ", base_addr, region_size,
                              protection, region_type, page_size_log2,
                              timestamp_ns)
        payload += page_state_map + data
        flags = _encode_comp_flags(compression)
        if compression is not CompAlgo.NONE:
            payload = compress(payload, compression)
        block_uuid = uuid4()
        self._blocks.append((BlockType.MEMORY_REGION, payload, block_uuid,
                             _ZERO_UUID, flags))
        self._cap_bitmap |= CapBit.MEMORY_REGIONS
        return block_uuid

    def add_key_hint(self, region_uuid: UUID, offset: int,
                     key_length: int, key_type: int, protocol: int,
                     confidence: int = 0x01, key_state: int = 0,
                     note: str = "") -> UUID:
        """Add a key hint block (spec §5.6) referencing a memory region."""
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
        tool_bytes = _pack_padded_str(tool_name)
        tool_raw_len = len(tool_name.encode("utf-8")) + 1
        note_bytes = _pack_padded_str(note) if note else b""
        note_raw_len = (len(note.encode("utf-8")) + 1) if note else 0
        payload = struct.pack("<H2xIQQI4x", source_format, tool_raw_len,
                              int(time.time() * 1e9), orig_file_size,
                              note_raw_len)
        payload += tool_bytes + note_bytes
        payload += _file_digest_or_zero(source_path)
        block_uuid = uuid4()
        self._import_provenance = (payload, block_uuid)
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
    ) -> UUID:
        """Register a POINTER_GRAPH appendix to be emitted after EoC.

        The appendix is a MemDiver extension: a plaintext block of type
        0x1003 written *after* the End-of-Capture block (and, in Phase C,
        after the AEAD Tag for encrypted containers). It lives outside
        the BLAKE3 in-chain `prev_hash` chain — readers that don't
        understand the appendix stop at EoC and ignore it. The user is
        opting in to inclusion by calling this method; `write()` checks
        the state and emits the appendix only when set.

        When *emit_integrity* is True (default), the appendix payload is
        followed by a 32-byte BLAKE3 trailer over (header + nodes + edges).
        The reader surfaces the stored hash on `MslPointerGraph.appendix_hash`;
        callers may use ``decoders_ext.verify_pointer_graph_integrity`` to
        re-check it.

        Returns the appendix block's UUID. Calling twice replaces the
        previous registration — only one appendix may be emitted per file.
        """
        block_uuid = uuid4()
        encoded = _build_pointer_graph_block(
            list(nodes), list(edges),
            block_uuid=block_uuid, emit_integrity=emit_integrity,
        )
        self._pointer_graph_appendix = (encoded, block_uuid)
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

    # ------------------------------------------------------------------
    # End-of-Capture
    # ------------------------------------------------------------------

    def add_end_of_capture(self, reason: int = 0) -> None:
        """Add an End-of-Capture block (spec §4.5).

        The 32-byte file_hash slot is left as zeros here; `write()`
        finalizes it with a digest covering the file header and every
        preceding encoded block.
        """
        payload = struct.pack("<32sQ", b"\x00" * 32, int(time.time() * 1e9))
        self._end_of_capture = (payload, uuid4())

    # ------------------------------------------------------------------
    # write() — assemble blocks in spec-mandated order
    # ------------------------------------------------------------------

    def write(self) -> None:
        """Write all accumulated blocks to the output file.

        Spec-mandated block ordering (§6.1):
          Block 0 -> Import Provenance (if imported) OR Process Identity
          Block 1 -> Module List Index (+ Module Entry children)
          Block 2 -> System Context (if investigation) (+ table children)
          Then: generic blocks in user call order (regions, key hints,
                related dumps), then End-of-Capture (last).

        The End-of-Capture block's `file_hash` is finalized over the file
        header + every prior encoded block, so the EoC pins the full
        file contents.
        """
        # Materialize System Context payload with the now-known TableBitmap.
        if self._system_context is not None:
            sc_payload, sc_uuid, sc_tb = self._system_context
            sc_payload = sc_payload[:0x0C] + struct.pack("<I", sc_tb) + sc_payload[0x10:]
            self._system_context = (sc_payload, sc_uuid, sc_tb)

        ordered = self._compose_ordered_blocks()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._encryption is not None:
            self._write_encrypted(ordered)
        else:
            self._write_plaintext(ordered)

    def _write_plaintext(self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Write an unencrypted file: 64-byte header, BLAKE3-chained blocks,
        optional plaintext POINTER_GRAPH appendix after EoC."""
        file_header = self._encode_base_header(encrypted=False, block_count=len(ordered))
        encoded_blocks: List[Optional[bytes]] = []
        prev_hash = _ZERO_HASH
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

        with open(self._path, "wb") as f:
            f.write(file_header)
            for block in encoded_blocks:
                if block is not None:
                    f.write(block)
            # POINTER_GRAPH appendix: plaintext bytes after the chain (outside
            # the integrity chain). Old readers stop at EoC and ignore them.
            if self._pointer_graph_appendix is not None:
                f.write(self._pointer_graph_appendix[0])
        appendix_note = (
            " + POINTER_GRAPH appendix"
            if self._pointer_graph_appendix is not None else ""
        )
        logger.info("Wrote MSL file: %s (%d blocks%s)",
                    self._path, len(ordered), appendix_note)

    def _write_encrypted(self, ordered: List[Tuple[int, bytes, UUID, bytes, int]]) -> None:
        """Write a full-container AEAD-encrypted file (spec §10).

        Layout: [Header 128B | KEM ct | AEAD(block stream incl. appendix) | Tag 16B].
        Per §10.6: every block's PrevHash is zero, the EoC FileHash is computed
        over the plaintext, and the AAD is the 128-byte header plus KEM
        ciphertext. The POINTER_GRAPH appendix (if any) lives inside the
        encrypted region, after EoC.
        """
        cfg = self._encryption
        kdf_salt = cfg.kdf_salt
        if kdf_salt is None:
            kdf_salt = os.urandom(16) if cfg.kdf_type == KdfType.ARGON2ID else b"\x00" * 16
        nonce_field = cfg.nonce if cfg.nonce is not None else random_nonce(cfg.enc_algo)

        cek, kem_ct = derive_cek_producer(
            key_encap=cfg.key_encap, kdf_type=cfg.kdf_type,
            dump_uuid_bytes=self._dump_uuid.bytes,
            raw_key=cfg.raw_key, passphrase=cfg.passphrase, kdf_salt=kdf_salt,
            kdf_time=cfg.kdf_time, kdf_memory=cfg.kdf_memory, kdf_lanes=cfg.kdf_lanes,
            recipient_public=cfg.recipient_public,
        )

        # BlockCount=0 for encrypted files: the count would otherwise leak in
        # the cleartext header, defeating full-container confidentiality. The
        # spec permits 0 ("unknown/streaming").
        base = self._encode_base_header(encrypted=True, block_count=0)
        ext = self._encode_enc_extension(cfg, nonce_field, kdf_salt, len(kem_ct))
        file_header = base + ext
        aad = file_header + kem_ct

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

        block_stream = b"".join(pre_eoc)
        if eoc_entry is not None:
            eoc_payload_stub, eoc_uuid = eoc_entry
            file_hash = hash_stream((file_header, kem_ct, *pre_eoc))
            acq_end_ns = struct.unpack_from("<Q", eoc_payload_stub, 32)[0]
            new_eoc_payload = file_hash + struct.pack("<Q", acq_end_ns)
            block_stream += self._encode_block(
                BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid,
                _ZERO_UUID, _ZERO_HASH, 0,
            )
        # Appendix inside the encrypted region, after EoC.
        if self._pointer_graph_appendix is not None:
            block_stream += self._pointer_graph_appendix[0]

        nonce = nonce_for_cipher(cfg.enc_algo, nonce_field)
        ciphertext_and_tag = aead_encrypt(cfg.enc_algo, cek, nonce, aad, block_stream)

        with open(self._path, "wb") as f:
            f.write(file_header)
            f.write(kem_ct)
            f.write(ciphertext_and_tag)
        appendix_note = (
            " + POINTER_GRAPH appendix"
            if self._pointer_graph_appendix is not None else ""
        )
        logger.info("Wrote encrypted MSL file: %s (%d blocks, %s%s)",
                    self._path, len(ordered), cfg.enc_algo.name, appendix_note)

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
        acq_end_ns = struct.unpack_from("<Q", eoc_payload_stub, 32)[0]
        new_eoc_payload = file_hash + struct.pack("<Q", acq_end_ns)
        encoded_blocks[eoc_index] = self._encode_block(
            BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid,
            _ZERO_UUID, prev_hash, 0,
        )

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
            int(time.time() * 1e9), self._os_type, self._arch_type,
            self._pid, 0, block_count, hash_algo,
        )

    def _encode_enc_extension(self, cfg: "MslEncryptionConfig",
                              nonce_field: bytes, kdf_salt: bytes,
                              kem_ct_len: int) -> bytes:
        # Encryption extension header (spec Table 5, 64 bytes at 0x40-0x7F).
        # EncAlgo(1) KDFType(1) KeyEncap(1) Rsv(1) KDFTime(4) KDFMemory(4)
        # KDFLanes(1) Rsv2(1) KEMCtLen(2) Nonce(24) KDFSalt(16) Rsv3(8) = 64.
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
        total_len = BLOCK_HEADER_SIZE + len(payload)
        header = struct.pack(
            "<4sHHIH2x16s16s32s",
            BLOCK_MAGIC, block_type, flags, total_len, 1,
            block_uuid.bytes, parent_uuid, prev_hash,
        )
        return header + payload


# ---------------------------------------------------------------------- helpers


def _len_with_nul(s: str) -> int:
    """Length of UTF-8 bytes plus NUL terminator (0 if empty)."""
    return (len(s.encode("utf-8")) + 1) if s else 0


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


# -- POINTER_GRAPH appendix encoder (MemDiver extension, block type 0x1003) --


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


def _build_pointer_graph_block(
    nodes: Sequence[MslPointerGraphNode],
    edges: Sequence[MslPointerGraphEdge],
    block_uuid: UUID,
    emit_integrity: bool = True,
) -> bytes:
    """Encode a full POINTER_GRAPH appendix block (80-byte block header
    + payload) ready to append after the in-chain region.

    The block header carries BLOCK_MAGIC, type=0x1003, flags=0, version=1,
    `block_uuid`, parent_uuid=zeros, and prev_hash=zeros (signals
    "appendix, not chained" to readers). The payload follows the
    layout documented in docs/file_formats/msl_v1_0_0.md.
    """
    pg_flags = POINTER_GRAPH_INTEGRITY_FLAG if emit_integrity else 0
    payload_header = struct.pack(
        "<IIII", len(nodes), len(edges), pg_flags, 0,
    )
    nodes_blob = b"".join(_encode_pointer_graph_node(n) for n in nodes)
    edges_blob = b"".join(_encode_pointer_graph_edge(e) for e in edges)
    payload_body = payload_header + nodes_blob + edges_blob
    if emit_integrity:
        payload = payload_body + hash_bytes(payload_body)
    else:
        payload = payload_body

    total_len = BLOCK_HEADER_SIZE + len(payload)
    block_header = struct.pack(
        "<4sHHIH2x16s16s32s",
        BLOCK_MAGIC, BlockType.POINTER_GRAPH, 0, total_len, 1,
        block_uuid.bytes, _ZERO_UUID, _ZERO_HASH,
    )
    return block_header + payload


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
