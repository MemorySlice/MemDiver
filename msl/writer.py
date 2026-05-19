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
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from uuid import UUID, uuid4

from .enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, ArchType, BlockType,
                    Endianness, FILE_HEADER_SIZE, FILE_MAGIC, HeaderFlag,
                    OSType, PageState)
from .hashing import hash_bytes, hash_file, hash_stream

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
                 investigation: bool = False):
        self._path = Path(path)
        self._pid = pid
        self._os_type = os_type
        self._arch_type = arch_type
        self._imported = imported
        self._investigation = investigation
        self._dump_uuid = uuid4()
        # Generic blocks (memory regions, key hints, related dumps, ...)
        # in user call order. Each entry is (block_type, payload, block_uuid,
        # parent_uuid_bytes).
        self._blocks: List[Tuple[int, bytes, UUID, bytes]] = []
        # Capability bitmap accumulator (spec §9, MUST be set accurately).
        self._cap_bitmap: int = 0
        # Spec-mandated positional slots (resolved at write() time).
        self._import_provenance: Optional[Tuple[bytes, UUID]] = None
        self._process_identity: Optional[Tuple[bytes, UUID]] = None
        self._module_list: Optional[Tuple[List[ModuleEntrySpec], UUID]] = None
        self._system_context: Optional[Tuple[bytes, UUID, int]] = None  # (payload, uuid, table_bitmap)
        self._sc_children: List[Tuple[int, bytes, UUID]] = []
        self._end_of_capture: Optional[Tuple[bytes, UUID]] = None

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
                          page_states: Optional[Sequence[int]] = None) -> UUID:
        """Add a memory region block (spec §5.1). Returns block UUID.

        Validates spec range constraints:
          * page_size_log2 ∈ [10, 40]  (spec §5.1)
          * region_size MUST be a multiple of page_size  (spec §5.1)

        Three-state page model (spec §7): supply *page_states* as a
        sequence of PageState codes (one per page). Only CAPTURED pages
        contribute to *data*; FAILED / UNMAPPED pages occupy zero bytes
        in the data segment. When *page_states* is None (default), all
        pages are encoded as CAPTURED — backward-compatible behavior.
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
        block_uuid = uuid4()
        self._blocks.append((BlockType.MEMORY_REGION, payload, block_uuid,
                             _ZERO_UUID))
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
                             _ZERO_UUID))
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
                             _ZERO_UUID))
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
        self._sc_children.append((BlockType.PROCESS_TABLE, payload, block_uuid))
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
        self._sc_children.append((BlockType.CONNECTION_TABLE, payload, block_uuid))
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
        self._sc_children.append((BlockType.HANDLE_TABLE, payload, block_uuid))
        sc_payload, sc_uuid_, sc_tb = self._system_context
        self._system_context = (sc_payload, sc_uuid_, sc_tb | TableBit.HANDLE_TABLE)
        self._cap_bitmap |= CapBit.SYSTEM_HANDLE_TABLE
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
        file_header = self._encode_file_header()
        encoded_blocks: List[Optional[bytes]] = []
        prev_hash = _ZERO_HASH
        eoc_index: Optional[int] = None

        for idx, (block_type, payload, block_uuid, parent_uuid) in enumerate(ordered):
            if block_type == BlockType.END_OF_CAPTURE:
                eoc_index = idx
                encoded_blocks.append(None)
                continue
            block_data = self._encode_block(block_type, payload,
                                             block_uuid, parent_uuid, prev_hash)
            encoded_blocks.append(block_data)
            prev_hash = hash_bytes(block_data)

        if eoc_index is not None:
            self._finalize_end_of_capture(
                encoded_blocks, file_header, eoc_index, prev_hash, ordered,
            )

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "wb") as f:
            f.write(file_header)
            for block in encoded_blocks:
                if block is not None:
                    f.write(block)
        logger.info("Wrote MSL file: %s (%d blocks)",
                    self._path, len(ordered))

    def _compose_ordered_blocks(self) -> List[Tuple[int, bytes, UUID, bytes]]:
        """Return the full block list in spec-mandated emission order.

        Each entry is (block_type, payload, block_uuid, parent_uuid_bytes).
        """
        out: List[Tuple[int, bytes, UUID, bytes]] = []

        # Block 0: Import Provenance (imported) OR Process Identity (live).
        if self._imported and self._import_provenance is not None:
            payload, uid = self._import_provenance
            out.append((BlockType.IMPORT_PROVENANCE, payload, uid, _ZERO_UUID))
        elif (not self._imported) and self._process_identity is not None:
            payload, uid = self._process_identity
            out.append((BlockType.PROCESS_IDENTITY, payload, uid, _ZERO_UUID))
        # If neither is set, no positional Block 0 — Memory Region etc.
        # will become Block 0. This is permitted for analysis-mode files
        # where no provenance/identity metadata is available.

        # Block 1: Module List Index, then Module Entry children.
        if self._module_list is not None:
            modules, mli_uuid = self._module_list
            out.append((BlockType.MODULE_LIST_INDEX,
                        _build_module_list_index_payload(modules),
                        mli_uuid, _ZERO_UUID))
            for mod in modules:
                out.append((BlockType.MODULE_ENTRY,
                            _build_module_entry_payload(mod),
                            mod.module_uuid, mli_uuid.bytes))

        # Block 2: System Context (Investigation only), then table children.
        if self._investigation and self._system_context is not None:
            sc_payload, sc_uuid, _ = self._system_context
            out.append((BlockType.SYSTEM_CONTEXT, sc_payload, sc_uuid, _ZERO_UUID))
            for (block_type, payload, block_uuid) in self._sc_children:
                out.append((block_type, payload, block_uuid, sc_uuid.bytes))
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
            out.append((BlockType.END_OF_CAPTURE, payload, uid, _ZERO_UUID))

        return out

    def _finalize_end_of_capture(
        self,
        encoded_blocks: List[Optional[bytes]],
        file_header: bytes,
        eoc_index: int,
        prev_hash: bytes,
        ordered: List[Tuple[int, bytes, UUID, bytes]],
    ) -> None:
        """Fill in the EoC block's `file_hash` with a streaming digest.

        Streams the file header and all prior encoded blocks through the
        hasher to avoid materializing a concatenated digest input — MSL
        files can easily reach multi-GB when memory regions are included.
        """
        file_hash = hash_stream(
            (file_header, *(b for b in encoded_blocks if b is not None))
        )
        _, eoc_payload_stub, eoc_uuid, _ = ordered[eoc_index]
        acq_end_ns = struct.unpack_from("<Q", eoc_payload_stub, 32)[0]
        new_eoc_payload = file_hash + struct.pack("<Q", acq_end_ns)
        encoded_blocks[eoc_index] = self._encode_block(
            BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid,
            _ZERO_UUID, prev_hash,
        )

    def _encode_file_header(self) -> bytes:
        # binary format 1.1 per MSL Specification v1.0.0
        version = (1 << 8) | 1
        flags = 0
        if self._imported:
            flags |= HeaderFlag.IMPORTED
        if self._investigation:
            flags |= HeaderFlag.INVESTIGATION
        return struct.pack(
            "<8sBBHIQ16sQHHIB7x",
            FILE_MAGIC, Endianness.LITTLE, FILE_HEADER_SIZE, version,
            flags, self._cap_bitmap, self._dump_uuid.bytes,
            int(time.time() * 1e9), self._os_type, self._arch_type,
            self._pid, 0,
        )

    def _encode_block(self, block_type: int, payload: bytes,
                      block_uuid: UUID, parent_uuid: bytes,
                      prev_hash: bytes) -> bytes:
        total_len = BLOCK_HEADER_SIZE + len(payload)
        header = struct.pack(
            "<4sHHIH2x16s16s32s",
            BLOCK_MAGIC, block_type, 0, total_len, 1,
            block_uuid.bytes, parent_uuid, prev_hash,
        )
        return header + payload


# ---------------------------------------------------------------------- helpers


def _len_with_nul(s: str) -> int:
    """Length of UTF-8 bytes plus NUL terminator (0 if empty)."""
    return (len(s.encode("utf-8")) + 1) if s else 0


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
