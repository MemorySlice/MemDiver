"""MSL format constants and enumerations (Memory Slice spec v1.1.0).

Magic bytes and all IntEnum/IntFlag types from the specification tables.
"""

from enum import IntEnum, IntFlag

# -- Magic bytes --
FILE_MAGIC = b"\x4D\x45\x4D\x53\x4C\x49\x43\x45"  # "MEMSLICE"
BLOCK_MAGIC = b"\x4D\x53\x4C\x43"  # "MSLC"
FILE_HEADER_SIZE = 64
FILE_HEADER_ENC_SIZE = 128
BLOCK_HEADER_SIZE = 80


class Endianness(IntEnum):
    LITTLE = 0x01
    BIG = 0x02


class HeaderFlag(IntFlag):
    IMPORTED = 1 << 0
    INVESTIGATION = 1 << 1
    ENCRYPTED = 1 << 2


class BlockType(IntEnum):
    """Block type registry (spec Table 9)."""
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
    # POINTER_GRAPH: RESERVED — no producer or payload layout defined.
    # Analysis-side pointer graphs belong in engine/project_db.py.
    POINTER_GRAPH = 0x1003


class BlockFlag(IntFlag):
    """Per-block flags (spec Table 7)."""
    COMPRESSED = 1 << 0
    COMP_ZSTD = 1 << 1
    COMP_LZ4 = 2 << 1
    HAS_KEY_HINTS = 1 << 3
    HAS_CHILDREN = 1 << 4
    CONTINUATION = 1 << 5


class CompAlgo(IntEnum):
    NONE = 0
    ZSTD = 1
    LZ4 = 2


class PageState(IntEnum):
    """Three-state page acquisition model (spec Table 22)."""
    CAPTURED = 0b00
    FAILED = 0b01
    UNMAPPED = 0b10
    RESERVED = 0b11  # treat as FAILED


class Protection(IntFlag):
    """Memory region protection flags (spec Section 5.1)."""
    READ = 0x01
    WRITE = 0x02
    EXECUTE = 0x04
    GUARD = 0x08
    COW = 0x10


class RegionType(IntEnum):
    """Memory region types (spec Section 5.1)."""
    UNKNOWN = 0x00
    HEAP = 0x01
    STACK = 0x02
    IMAGE = 0x03
    MAPPED_FILE = 0x04
    ANONYMOUS = 0x05
    SHARED_MEM = 0x06
    OTHER = 0xFF


class OSType(IntEnum):
    WINDOWS = 0x0000
    LINUX = 0x0001
    MACOS = 0x0002
    ANDROID = 0x0003
    IOS = 0x0004
    FREEBSD = 0x0005
    UNKNOWN = 0xFFFF


class ArchType(IntEnum):
    X86 = 0x0000
    X86_64 = 0x0001
    ARM64 = 0x0002
    ARM32 = 0x0003
    UNKNOWN = 0xFFFF


class MslKeyType(IntEnum):
    """Crypto key type codes (spec Table 17)."""
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


class MslProtocol(IntEnum):
    """Protocol codes (spec Table 17)."""
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
    """Key hint confidence levels (spec Section 5.6)."""
    SPECULATIVE = 0x00
    HEURISTIC = 0x01
    CONFIRMED = 0x02


class KeyState(IntEnum):
    """Key lifecycle state (spec Section 5.6)."""
    UNKNOWN = 0x00
    ACTIVE = 0x01
    EXPIRED = 0x02


class HandleType(IntEnum):
    """Handle Table entry type discriminator (spec Table 24, uint16)."""
    UNKNOWN = 0x00
    FILE = 0x01
    DIR = 0x02
    SOCKET = 0x03
    PIPE = 0x04
    MUTEX = 0x05
    TIMER = 0x06
    OTHER = 0x07


class ConnRowType(IntEnum):
    """Connectivity Table row-type discriminator (spec Table 26, uint8)."""
    IPV4_ROUTE = 0x01
    IPV6_ROUTE = 0x02
    ARP_ENTRY = 0x03
    PACKET_SOCKET = 0x04
    IFACE_STATS = 0x05
    SOCKET_FAMILY_AGG = 0x06
    MIB_COUNTER = 0x07
