"""MSL format data types (Memory Slice Specification v1.0.0 — binary format 1.1).

Dataclasses for parsed MSL file structures. Enum definitions are in enums.py.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union
from uuid import UUID

from .enums import (
    BLOCK_HEADER_SIZE,
    BlockFlag,
    CompAlgo,
    HeaderFlag,
    PageState,
)

# Forward reference — PageInterval is defined in page_map.py
# to avoid circular imports, we use a string annotation
logger = logging.getLogger("memdiver.msl.types")


# -- Exceptions --

class MslEncryptedError(ValueError):
    """Raised when an encrypted MSL file is encountered without a key."""

class MslParseError(ValueError):
    """Raised on MSL format parsing errors."""

class MslAuthError(ValueError):
    """Raised when AEAD tag verification fails — wrong key or tampering (spec §10)."""

class MslCryptoError(ValueError):
    """Raised when a cipher/KDF/KEM is unsupported or its backing library is absent."""

# -- File and Block Headers --

@dataclass(frozen=True)
class MslFileHeader:
    """Parsed MSL file header (spec Table 3, 64 or 128 bytes)."""
    endianness: int
    header_size: int
    version_major: int
    version_minor: int
    flags: int
    cap_bitmap: int
    dump_uuid: UUID
    timestamp_ns: int
    os_type: int
    arch_type: int
    pid: int
    clock_source: int
    block_count: int = 0   # 0 = unknown/streaming (spec §3.1)
    hash_algo: int = 0     # integrity hash selector (spec Table 12); 0 = BLAKE3

    @property
    def imported(self) -> bool:
        return bool(self.flags & HeaderFlag.IMPORTED)

    @property
    def investigation(self) -> bool:
        return bool(self.flags & HeaderFlag.INVESTIGATION)

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & HeaderFlag.ENCRYPTED)


@dataclass(frozen=True)
class MslEncryptionParams:
    """Parsed encryption extension header (spec Table 5, bytes 0x40-0x7F)."""
    enc_algo: int       # EncAlgo
    kdf_type: int       # KdfType
    key_encap: int      # KeyEncap
    kdf_time: int
    kdf_memory: int
    kdf_lanes: int
    kem_ct_len: int
    nonce: bytes        # 24-byte Nonce field (cipher uses a prefix)
    kdf_salt: bytes     # 16-byte KDF salt


@dataclass(frozen=True)
class MslBlockHeader:
    """Parsed common block header (spec Table 6, 80 bytes)."""
    block_type: int
    flags: int
    block_length: int
    payload_version: int
    block_uuid: UUID
    parent_uuid: UUID
    prev_hash: bytes
    file_offset: int  # computed: absolute offset in file
    payload_offset: int  # computed: file_offset + 80

    @property
    def payload_length(self) -> int:
        return self.block_length - BLOCK_HEADER_SIZE

    @property
    def compressed(self) -> bool:
        return bool(self.flags & BlockFlag.COMPRESSED)

    @property
    def comp_algo(self) -> CompAlgo:
        bits = (self.flags >> 1) & 0x03
        return CompAlgo(bits) if bits <= 2 else CompAlgo.NONE


# -- Capture-Time Payloads --
@dataclass
class MslMemoryRegion:
    """Memory Region payload (spec Table 11, type 0x0001)."""
    block_header: MslBlockHeader
    base_addr: int
    region_size: int
    protection: int
    region_type: int
    page_size_log2: int
    timestamp_ns: int
    page_intervals: List = field(default_factory=list)  # List[PageInterval]
    page_states: List[PageState] = field(default_factory=list)  # backward compat

    @property
    def page_size(self) -> int:
        return 1 << self.page_size_log2

    @property
    def num_pages(self) -> int:
        return self.region_size // self.page_size


@dataclass
class MslModuleEntry:
    """Module Entry payload (spec Table 12, type 0x0002)."""
    block_header: MslBlockHeader
    base_addr: int
    module_size: int
    path: str
    version: str
    disk_hash: bytes  # 32 bytes BLAKE3 or zeros


@dataclass
class MslProcessIdentity:
    """Process Identity payload (spec Table 14, type 0x0040)."""
    block_header: MslBlockHeader
    ppid: int
    session_id: int
    start_time_ns: int
    exe_path: str
    cmd_line: str


@dataclass
class MslKeyHint:
    """Key Hint payload (spec Table 16, type 0x0020)."""
    block_header: MslBlockHeader
    region_uuid: UUID
    region_offset: int
    key_length: int
    key_type: int
    protocol: int
    confidence: int
    key_state: int
    note: str = ""


@dataclass
class MslRelatedDump:
    """Related Dump payload (spec Table 15, type 0x0041).

    The `target_hash` field pins the reference to a 32-byte BLAKE3
    digest of the target dump file contents, so the reference cannot
    silently drift if the target is re-acquired or modified.
    """
    block_header: MslBlockHeader
    related_dump_uuid: UUID
    related_pid: int
    relationship: int
    target_hash: bytes = b"\x00" * 32  # 32 bytes BLAKE3 (or sha256 fallback)


@dataclass
class MslEndOfCapture:
    """End-of-Capture payload (spec Table 10, type 0x0FFF)."""
    block_header: MslBlockHeader
    file_hash: bytes  # 32 bytes BLAKE3
    acq_end_ns: int


@dataclass
class MslImportProvenance:
    """Import Provenance payload (spec Table 26, type 0x0030).

    The `source_hash` field pins the provenance to a 32-byte BLAKE3
    digest of the original source file contents.
    """
    block_header: MslBlockHeader
    source_format: int
    tool_name: str
    import_time_ns: int
    orig_file_size: int
    note: str = ""
    source_hash: bytes = b"\x00" * 32  # 32 bytes BLAKE3


# -- VAS Map Payloads (Phase 15) --
@dataclass
class MslVasEntry:
    """Single segment within a VAS_MAP block."""
    base_addr: int
    region_size: int
    protection: int       # Protection flags
    region_type: int      # RegionType enum value
    mapped_path: str      # empty string for anonymous regions


@dataclass
class MslVasMap:
    """VAS Map payload (spec type 0x1001)."""
    block_header: MslBlockHeader
    entry_count: int
    entries: List[MslVasEntry] = field(default_factory=list)


# -- Table Blocks (spec §5.3, §6.3–§6.5) --

@dataclass(frozen=True)
class MslModuleIndexEntry:
    """Single entry within a MODULE_LIST_INDEX block (spec Table 15)."""
    module_uuid: UUID
    base_addr: int
    module_size: int
    path: str


@dataclass(frozen=True)
class MslModuleListIndex:
    """Module List Index payload (spec Table 15, type 0x0010)."""
    block_header: MslBlockHeader
    entry_count: int
    entries: Tuple[MslModuleIndexEntry, ...] = ()


@dataclass(frozen=True)
class MslProcessEntry:
    """Single entry within a PROCESS_TABLE block (spec Table 21)."""
    pid: int
    ppid: int
    uid: int
    is_target: bool
    start_time_ns: int
    rss: int
    exe_name: str
    cmd_line: str
    user: str


@dataclass(frozen=True)
class MslProcessTable:
    """Process Table payload (spec Table 21, type 0x0051)."""
    block_header: MslBlockHeader
    entry_count: int
    entries: Tuple[MslProcessEntry, ...] = ()


@dataclass(frozen=True)
class MslConnectionEntry:
    """Single entry within a CONNECTION_TABLE block (spec Table 22)."""
    pid: int
    family: int   # 0x02=AF_INET, 0x0A=AF_INET6
    protocol: int  # 0x06=TCP, 0x11=UDP
    state: int
    local_addr: bytes   # 16 bytes raw
    local_port: int     # uint16 LE (NOT network byte order)
    remote_addr: bytes  # 16 bytes raw
    remote_port: int    # uint16 LE


@dataclass(frozen=True)
class MslConnectionTable:
    """Connection Table payload (spec Table 22, type 0x0052)."""
    block_header: MslBlockHeader
    entry_count: int
    entries: Tuple[MslConnectionEntry, ...] = ()


@dataclass(frozen=True)
class MslHandleEntry:
    """Single entry within a HANDLE_TABLE block (spec Table 24)."""
    pid: int
    fd: int
    handle_type: int  # spec Table 24: 0x00 Unknown..0x07 Other (uint16)
    path: str


@dataclass(frozen=True)
class MslHandleTable:
    """Handle Table payload (spec Table 24, type 0x0053)."""
    block_header: MslBlockHeader
    entry_count: int
    entries: Tuple[MslHandleEntry, ...] = ()


@dataclass(frozen=True)
class MslConnIPv4Route:
    """IPv4 route entry (spec Table 26, RowType=0x01)."""
    iface: str
    dest: bytes      # 4 raw bytes, network order
    gateway: bytes   # 4 raw bytes, network order
    mask: bytes      # 4 raw bytes, network order
    flags: int
    metric: int
    mtu: int


@dataclass(frozen=True)
class MslConnIPv6Route:
    """IPv6 route entry (spec Table 26, RowType=0x02)."""
    iface: str
    dest: bytes          # 16 raw bytes
    dest_prefix: int
    next_hop: bytes      # 16 raw bytes
    metric: int
    flags: int


@dataclass(frozen=True)
class MslConnArpEntry:
    """ARP cache entry (spec Table 26, RowType=0x03)."""
    family: int
    ip: bytes            # 4 raw bytes
    hw_type: int
    flags: int
    hw_addr: bytes       # 6 raw bytes
    iface: str


@dataclass(frozen=True)
class MslConnPacketSocket:
    """Raw packet socket (spec Table 26, RowType=0x04)."""
    pid: int
    inode: int
    proto: int
    iface_index: int
    user: int
    mem: int


@dataclass(frozen=True)
class MslConnIfaceStats:
    """Per-interface counter snapshot (spec Table 26, RowType=0x05)."""
    iface: str
    rx_bytes: int
    rx_pkts: int
    rx_err: int
    rx_drop: int
    tx_bytes: int
    tx_pkts: int
    tx_err: int
    tx_drop: int


@dataclass(frozen=True)
class MslConnSocketFamilyAgg:
    """Socket-family aggregate (spec Table 26, RowType=0x06)."""
    family: int
    in_use: int
    alloc: int
    mem: int


@dataclass(frozen=True)
class MslConnMibCounter:
    """MIB counter (spec Table 26, RowType=0x07)."""
    mib: str
    counter: str
    value: int


ConnectivityRow = Union[
    MslConnIPv4Route, MslConnIPv6Route, MslConnArpEntry,
    MslConnPacketSocket, MslConnIfaceStats, MslConnSocketFamilyAgg,
    MslConnMibCounter,
]


@dataclass(frozen=True)
class MslConnectivityTable:
    """Connectivity Table payload (spec Table 25, type 0x0055).

    Heterogeneous tagged-row format: routes, ARP entries, raw packet
    sockets, interface statistics, socket-family aggregates, and MIB
    counters. Unknown row types are skipped per the forward-compat
    rule in spec §6.6.
    """
    block_header: MslBlockHeader
    row_count: int
    rows: Tuple[ConnectivityRow, ...] = ()


@dataclass(frozen=True)
class MslGenericBlock:
    """Fallback container for block types without a dedicated decoder."""
    block_header: MslBlockHeader
    payload: bytes


# -- POINTER_GRAPH appendix (0x1003) — MemDiver extension --

@dataclass(frozen=True)
class MslPointerGraphNode:
    """Single node in a POINTER_GRAPH appendix.

    `value` holds either a virtual address, a file/region offset, or a
    symbol identifier depending on `node_kind` (see enums.NodeKind).
    `label` is an optional UTF-8 name (e.g., symbol name).
    """
    node_kind: int   # NodeKind value
    value: int       # interpretation depends on node_kind
    label: str = ""


@dataclass(frozen=True)
class MslPointerGraphEdge:
    """Single directed edge between two nodes in a POINTER_GRAPH appendix.

    `src_idx` / `dst_idx` index into the parent graph's `nodes` tuple.
    `metadata` is an optional UTF-8 free-form annotation (call count,
    confidence label, etc.) — readers may ignore unknown formats.
    """
    src_idx: int
    dst_idx: int
    edge_kind: int   # EdgeKind value
    metadata: str = ""


@dataclass(frozen=True)
class MslPointerGraph:
    """POINTER_GRAPH appendix payload (type 0x1003).

    A plaintext appendix block emitted *after* End-of-Capture (and after
    the AEAD Tag for encrypted containers). Lives outside the BLAKE3
    block chain (block header `prev_hash` is zero). The appendix carries
    its own optional self-integrity BLAKE3 (`appendix_hash`), independent
    of the main container's chain.

    A reader that doesn't recognize block type 0x1003 stops at EoC and
    safely ignores the appendix — fully backward compatible.
    """
    block_header: MslBlockHeader
    nodes: Tuple[MslPointerGraphNode, ...] = ()
    edges: Tuple[MslPointerGraphEdge, ...] = ()
    # Trailing 32-byte BLAKE3 over (header + nodes + edges) when the
    # producer set POINTER_GRAPH_INTEGRITY_FLAG; None when the producer
    # opted out of emitting integrity. `None` is "no claim made", NOT
    # "corruption detected" — to actually verify a present hash, call
    # decoders_ext.verify_pointer_graph_integrity(graph, raw_payload).
    appendix_hash: Optional[bytes] = None
