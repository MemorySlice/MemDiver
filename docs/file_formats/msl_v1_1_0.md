# Memory Slice (.msl) v1.1.0

MemDiver's native snapshot format. Container for memory regions, module tables, process identity, VAS maps, connection tables, handle tables, key hints, and provenance metadata with BLAKE3 integrity chaining.

## Design goals

- **Streaming-friendly** — writers finalize a BLAKE3 file hash without rewinding.
- **Compression-agnostic** — each block carries its own codec (`none`, `zstd`, `lz4`) via flag bits.
- **Forward-compatible** — unknown block types fall back to `GenericBlock`.
- **Integrity-first** — each block carries a BLAKE3 of the previous block, producing a per-file hash chain finalized in `END_OF_CAPTURE`.

## Constants

| Constant | Value | Where |
|---|---|---|
| `FILE_MAGIC` | `b"MEMSLICE"` | `msl/enums.py:9` |
| `BLOCK_MAGIC` | `b"MSLC"` | `msl/enums.py:10` |
| `FILE_HEADER_SIZE` | `64` | `msl/enums.py:11` |
| `FILE_HEADER_ENC_SIZE` | `128` (encrypted files) | `msl/enums.py:12` |
| `BLOCK_HEADER_SIZE` | `80` | `msl/enums.py:13` |

## File header (64 bytes)

Layout verified against `msl/reader.py:90-122`.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 8 | magic | `b"MEMSLICE"` |
| 0x08 | 1 | endianness | `0x01` little, `0x02` big |
| 0x09 | 1 | header_size | declared header length (64 or 128) |
| 0x0A | 2 | version | uint16; `major = hi byte`, `minor = lo byte` |
| 0x0C | 4 | flags | `HeaderFlag` — `IMPORTED`, `INVESTIGATION`, `ENCRYPTED` |
| 0x10 | 8 | cap_bitmap | capability bitmap |
| 0x18 | 16 | dump_uuid | UUID |
| 0x28 | 8 | timestamp_ns | nanoseconds since epoch |
| 0x30 | 2 | os_type | `OSType` (Windows / Linux / macOS / Android / iOS / FreeBSD) |
| 0x32 | 2 | arch_type | `ArchType` (x86 / x86_64 / ARM64 / ARM32) |
| 0x34 | 4 | pid | process ID |
| 0x38 | 1 | clock_source | clock-source identifier |
| 0x39..0x3F | 7 | reserved | zero-filled |

Setting the `ENCRYPTED` flag bit causes `MslReader` to raise `MslEncryptedError`.

## Block header (80 bytes)

Layout verified against `msl/reader.py:124-139`.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | magic | `b"MSLC"` |
| 0x04 | 2 | block_type | `BlockType` (see table below) |
| 0x06 | 2 | flags | `BlockFlag` — compression + structural bits |
| 0x08 | 4 | block_length | total block length on disk (header + payload) |
| 0x0C | 2 | payload_version | per-block schema version |
| 0x0E | 2 | padding / reserved | zero-filled |
| 0x10 | 16 | block_uuid | UUID |
| 0x20 | 16 | parent_uuid | UUID of referenced parent block (optional) |
| 0x30 | 32 | prev_hash | BLAKE3 of the previous block on disk; finalized in `END_OF_CAPTURE` |

Compression is encoded in `flags`, not in a dedicated codec field:

| `BlockFlag` bit | Meaning |
|---|---|
| `COMPRESSED` (bit 0) | payload is compressed |
| `COMP_ZSTD` (bit 1) | zstd |
| `COMP_LZ4` (bit 2) | lz4 |
| `HAS_KEY_HINTS` (bit 3) | block contains / references key hints |
| `HAS_CHILDREN` (bit 4) | block has child blocks |
| `CONTINUATION` (bit 5) | fragment of a larger logical block; merged by `MslReader` |

## Block type registry (spec Table 9)

Source: `msl/enums.py:27-51`.

| Code | Name | Notes |
|---|---|---|
| `0x0000` | `INVALID` | sentinel |
| `0x0001` | `MEMORY_REGION` | primary payload — bytes + metadata |
| `0x0002` | `MODULE_ENTRY` | loaded module record |
| `0x0010` | `MODULE_LIST_INDEX` | index of module entries |
| `0x0011` | `THREAD_CONTEXT` | per-thread register snapshot |
| `0x0012` | `FILE_DESCRIPTOR` | open-file-descriptor entry |
| `0x0013` | `NETWORK_CONNECTION` | socket / endpoint entry |
| `0x0014` | `ENVIRONMENT_BLOCK` | process environment variables |
| `0x0015` | `SECURITY_TOKEN` | OS security token / capability |
| `0x0020` | `KEY_HINT` | decrypted / inferred key material |
| `0x0030` | `IMPORT_PROVENANCE` | records conversion from a legacy `.dump` |
| `0x0040` | `PROCESS_IDENTITY` | PID / UID / command line |
| `0x0041` | `RELATED_DUMP` | reference to a sibling `.msl` |
| `0x0050` | `SYSTEM_CONTEXT` | global kernel / system snapshot |
| `0x0051` | `PROCESS_TABLE` | system process list |
| `0x0052` | `CONNECTION_TABLE` | system connection list |
| `0x0053` | `HANDLE_TABLE` | kernel-object handle entries |
| `0x0055` | `CONNECTIVITY_TABLE` | routing / ARP / socket-family aggregate |
| `0x0FFF` | `END_OF_CAPTURE` | finalizes the file-level BLAKE3 chain |
| `0x1001` | `VAS_MAP` | virtual-address-space map overlay |
| `0x1003` | `POINTER_GRAPH` | **RESERVED** — no producer; see `engine/project_db.py` for analysis-side pointer graphs |

Unknown block-type codes are preserved verbatim as `GenericBlock` so future spec revisions remain readable by older readers.

:::{note}
Kaitai Struct is used only for foreign binaries (ELF, PE, Mach-O) under `core/binary_formats/kaitai_compiled/`. The `.msl` format itself is hand-rolled, with `MslReader` / `MslWriter` as the reference implementations.
:::
