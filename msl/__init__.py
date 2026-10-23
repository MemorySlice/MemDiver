"""Memory Slice (.msl) format parser.

Optional dependencies (lazy-imported when needed):
- blake3: integrity chain verification
- zstandard: zstd block decompression
- lz4: lz4 block decompression
"""

from .enums import (
    BLOCK_HEADER_SIZE,
    BLOCK_MAGIC,
    EXTENSION_FORBIDDEN_TYPES,
    FILE_HEADER_SIZE,
    FILE_MAGIC,
    ArchType,
    BlockFlag,
    BlockType,
    CompAlgo,
    Confidence,
    Endianness,
    HeaderFlag,
    KeyState,
    MslKeyType,
    MslProtocol,
    OSType,
    PageState,
    Protection,
    RegionType,
    ThreadState,
    VasNameSource,
)
from .page_map import PageInterval
from .types import (
    MslBlockHeader,
    MslConnectionEntry,
    MslConnectionTable,
    MslEncryptedError,
    ExtensionSegment,
    MslEndOfCapture,
    MslEndOfExtension,
    MslFileHeader,
    MslGenericBlock,
    MslHandleEntry,
    MslHandleTable,
    MslImportProvenance,
    MslKeyHint,
    MslMemoryRegion,
    MslModuleEntry,
    MslModuleIndexEntry,
    MslModuleListIndex,
    MslParseError,
    MslProcessEntry,
    MslProcessIdentity,
    MslProcessTable,
    MslRelatedDump,
    MslThreadContext,
    MslThreadRegister,
    MslVasEntry,
    MslVasMap,
)
