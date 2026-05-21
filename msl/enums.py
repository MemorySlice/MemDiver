"""MSL format constants and enumerations (Memory Slice Specification v1.0.0 — binary format 1.1).

Magic bytes and all IntEnum/IntFlag types from the specification tables.
"""

from enum import Enum, IntEnum, IntFlag

# -- Magic bytes --
FILE_MAGIC = b"\x4D\x45\x4D\x53\x4C\x49\x43\x45"  # "MEMSLICE"
BLOCK_MAGIC = b"\x4D\x53\x4C\x43"  # "MSLC"
FILE_HEADER_SIZE = 64
FILE_HEADER_ENC_SIZE = 128
BLOCK_HEADER_SIZE = 80

# -- Encryption (spec §10) --
ENC_EXT_OFFSET = 0x40          # encryption extension starts here when Encrypted
ENC_EXT_SIZE = 64             # extension header is 64 bytes (0x40..0x7F)
AEAD_TAG_SIZE = 16            # both cipher suites use a 16-byte tag
# HKDF-BLAKE3 context (spec §10.4): info string for content-encryption-key derivation
MSL_CEK_INFO = b"MSL-CEK-v1"


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
    # POINTER_GRAPH (0x1003) is a MemDiver-driven extension: a plaintext
    # appendix block emitted AFTER the End-of-Capture block (and after the
    # AEAD Tag, when the container is encrypted). It is OUTSIDE the BLAKE3
    # block chain — its `prev_hash` is zeros — so existing readers can
    # safely stop at EoC and ignore everything that follows. Payload layout
    # is documented in docs/file_formats/msl_v1_0_0.md.
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


# -- POINTER_GRAPH appendix (0x1003) — MemDiver extension --

# Bit set in the POINTER_GRAPH payload header `flags` field when the
# 32-byte BLAKE3 trailer is present. The appendix lives outside the
# block chain, so it carries its own optional integrity hash.
POINTER_GRAPH_INTEGRITY_FLAG = 1 << 0


# -- Encryption enums (spec §10) --


class HashAlgo(IntEnum):
    """Integrity hash algorithm selector (file header offset 0x3D, spec Table 12).

    All registered algorithms produce 32-byte output, so field layouts are
    independent of the choice. Applies to PrevHash, EoC FileHash, DiskHash —
    NOT to HKDF key derivation (which always uses BLAKE3).
    """
    BLAKE3 = 0x00      # default
    SHA256 = 0x01
    SHA512_256 = 0x02
    OTHER = 0xFF


class EncAlgo(IntEnum):
    """AEAD cipher suite (encryption extension offset 0x40, spec Table 30)."""
    AES_256_GCM = 0x01           # 12-byte nonce, 16-byte tag (default)
    XCHACHA20_POLY1305 = 0x02    # 24-byte nonce, 16-byte tag


class KdfType(IntEnum):
    """Key derivation function (encryption extension offset 0x41, spec §10.5)."""
    NONE = 0x00        # 256-bit CEK supplied externally
    ARGON2ID = 0x01    # passphrase-derived; min time=3, memory=65536 KiB, lanes=4


class KeyEncap(IntEnum):
    """Key encapsulation mechanism (encryption extension offset 0x42, spec Table 31)."""
    NONE = 0x00                # raw key / passphrase
    X25519 = 0x01              # classical ECDH; 32-byte ciphertext
    ML_KEM_768 = 0x02          # FIPS 203; 1088-byte ciphertext
    ML_KEM_1024 = 0x03         # FIPS 203; 1568-byte ciphertext
    X25519_ML_KEM_768 = 0x04   # hybrid (recommended); 1120-byte ciphertext
    OTHER = 0xFF


# KEM ciphertext lengths per spec Table 31 (bytes). 0 means no KEM ciphertext.
KEM_CIPHERTEXT_LEN = {
    KeyEncap.NONE: 0,
    KeyEncap.X25519: 32,
    KeyEncap.ML_KEM_768: 1088,
    KeyEncap.ML_KEM_1024: 1568,
    KeyEncap.X25519_ML_KEM_768: 1120,  # 32 (X25519) + 1088 (ML-KEM-768)
}

# AEAD nonce sizes per spec Table 30 (bytes).
CIPHER_NONCE_LEN = {
    EncAlgo.AES_256_GCM: 12,
    EncAlgo.XCHACHA20_POLY1305: 24,
}

# Argon2id minimum parameters (spec §10.5).
ARGON2ID_MIN_TIME = 3
ARGON2ID_MIN_MEMORY_KIB = 65536
ARGON2ID_MIN_LANES = 4


class TagStatus(Enum):
    """Result of AEAD tag verification, surfaced to the user by MslReader.

    Distinguishes the four states a consumer must communicate (spec §10,
    §14.2): a plaintext file, a verified decryption, a failed/tampered
    decryption, and an encrypted file opened without a key.
    """
    NOT_ENCRYPTED = "not_encrypted"   # file is not encrypted
    VALID = "valid"                   # AEAD tag verified, plaintext recovered
    CORRUPTED = "corrupted"           # tag mismatch — wrong key or tampering
    MISSING_KEY = "missing_key"       # encrypted, but no key/passphrase supplied


class NodeKind(IntEnum):
    """POINTER_GRAPH node-kind discriminator (uint8).

    Distinguishes how to interpret the node's 64-bit `value` field.
    """
    ADDRESS = 0x01   # absolute virtual address
    OFFSET = 0x02    # file or region offset
    SYMBOL = 0x03    # symbol identifier; `label` carries the name


class EdgeKind(IntEnum):
    """POINTER_GRAPH edge-kind discriminator (uint8)."""
    POINTER = 0x01   # data pointer reference
    CALL = 0x02      # function call edge
    IMPORT = 0x03    # module import / dependency edge
