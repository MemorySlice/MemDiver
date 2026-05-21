# Memory Slice (.msl) — Specification v1.0.0 (binary format 1.1)

MemDiver's native snapshot format. Container for memory regions, module tables, process identity, VAS maps, connection tables, handle tables, key hints, and provenance metadata with BLAKE3 integrity chaining.

## Specification source

This document describes MemDiver's implementation of the Memory Slice format defined in the official specification:

- **Spec repository:** <https://github.com/MemorySlice/memslice-spec>
- **Spec document version:** 1.0.0 (Working Draft, draft-2026-03)
- **Binary format code** (file header offset `0x0A`): `0x0101` (the spec calls this "format 1.1")

The spec document version (1.0.0) and the on-wire format byte (0x0101) are intentionally distinct: the document is at its first stable release while the file header carries the format generation it specifies.

MemDiver implements the spec's consumer requirements (§14.2) in full. The producer (§14.1) supports both Analysis-mode and Investigation-mode acquisition: Process Identity, Module List Index, Module Entry, System Context, Process/Connection/Handle/Connectivity tables, Memory Region (with three-state page model), Key Hint, Related Dump, Import Provenance, and End-of-Capture. Per-block payload compression (§4.2.1) and full-container AEAD encryption (§10) are emitted by the writer and consumed by the reader.

## Implementation status

**Encryption (§10).** Both cipher suites (AES-256-GCM, XChaCha20-Poly1305), both KDFs (raw key, Argon2id passphrase), and HKDF-BLAKE3 key derivation ship in the base install (`cryptography`, `PyNaCl`, `argon2-cffi`, `blake3`). KeyEncap=None and X25519 work out of the box. Post-quantum key encapsulation — ML-KEM-768, ML-KEM-1024, and the recommended X25519+ML-KEM-768 hybrid — requires the optional `[crypto]` extra (`liboqs-python`); without it those mechanisms report unavailable and raise a clean error. The reader exposes a `TagStatus` (`VALID` / `CORRUPTED` / `MISSING_KEY` / `NOT_ENCRYPTED`) so consumers can communicate the AEAD verification outcome. Per §10.6, encrypted files carry zero `PrevHash` on every block and an EoC `FileHash` computed over plaintext; `verify_chain` skips the chain for encrypted files (§14.2 rule 16) and relies on the AEAD tag.

**Known limitation — whole-container buffering.** The current encrypt/decrypt path is whole-buffer, not streaming: encryption materializes the full plaintext block stream in memory and decryption materializes the full plaintext (≈2× file size transient RAM for the ciphertext copy + decrypted output). This matches the high-level AEAD APIs (`cryptography`, PyNaCl) which verify the tag over the complete ciphertext. The spec's streaming model (§10.7) is a future optimization; for multi-GB encrypted captures, plan for peak RAM around twice the file size. Plaintext (unencrypted) files remain mmap-backed and lazy.

Two reader-side compatibility quirks remain by design:

1. **SYSTEM_CONTEXT deviation tail (read-only).** The reader still parses an `uptime_ns` + `os_version` deviation tail past the spec-defined `CaseRef` field, for backward compatibility with files produced by older MemDiver builds. The current writer never emits this tail — it stays pure-spec.
2. **RELATED_DUMP legacy layout.** The reader accepts the 24-byte pre-C1 payload (without `target_hash`) as well as the spec-mandated 56-byte layout. The writer always emits the full 56-byte form.

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
| `0x1003` | `POINTER_GRAPH` | **MemDiver extension** — appendix block emitted *after* `END_OF_CAPTURE` (plaintext for unencrypted files; inside the AEAD envelope, still after EoC, for encrypted files). Outside the in-chain BLAKE3 prev_hash chain; carries its own optional self-integrity hash. See "POINTER_GRAPH appendix" below. |

Unknown block-type codes are preserved verbatim as `GenericBlock` so future spec revisions remain readable by older readers.

:::{note}
Kaitai Struct is used only for foreign binaries (ELF, PE, Mach-O) under `core/binary_formats/kaitai_compiled/`. The `.msl` format itself is hand-rolled, with `MslReader` / `MslWriter` as the reference implementations.
:::

## POINTER_GRAPH appendix (0x1003)

**MemDiver extension — proposed for upstream inclusion in the next spec revision.**

The POINTER_GRAPH block records analysis-derived pointer relationships (data references, call edges, module imports) discovered after capture. Because these relationships are derived rather than captured, the block is emitted as an *appendix* — written verbatim after the in-chain region, outside the BLAKE3 prev_hash chain.

### File layout with appendix

```
Unencrypted MSL:
  [ File Header | Block 0 | Block 1 | ... | EoC | POINTER_GRAPH (optional) ]
                                              ↑                 ↑
                                       chain ends here    appendix (plaintext)

Encrypted MSL (AEAD §10):
  [ Header 128B | KEM ct | AEAD( Block 0 … EoC | POINTER_GRAPH (optional) ) | Tag 16B ]
                                                      ↑
                              appendix lives INSIDE the encrypted region, after EoC
```

For encrypted files the appendix sits **inside** the AEAD envelope (after the EoC block in the plaintext that gets encrypted), not after the tag. This avoids two problems with a plaintext-after-tag layout: (1) the reader could not delimit where the ciphertext+tag ends and a plaintext appendix begins, and (2) emitting analysis-derived pointer-graph metadata in plaintext would defeat the confidentiality that encryption provides. The unified rule is: **the appendix is the block(s) after EoC in the (possibly-decrypted) block stream.**

### Reader/writer rules

- The appendix block uses the standard 80-byte block header (`BLOCK_MAGIC`, `block_type = 0x1003`) but its `prev_hash` field is **32 zero bytes** — this signals "appendix, not chained" to readers.
- `MslReader._iter_raw_blocks` stops after yielding the `END_OF_CAPTURE` block; `verify_chain` does the same. Existing collectors (regions, key hints, etc.) never see the appendix — fully backward compatible.
- Appendix-aware readers fetch the graph via `MslReader.collect_pointer_graphs()`, which walks `_iter_appendix_blocks` separately.
- For unencrypted files the appendix is plaintext after EoC. For encrypted files it is encrypted along with the rest of the block stream (inside the AEAD envelope, after EoC), so pointer-graph metadata is never exposed in plaintext. The reader recovers it from the decrypted stream.

### Payload layout

| Region | Offset | Size | Notes |
|---|---|---|---|
| **Header** | 0x00 | 4 | `node_count` (u32 LE) |
|  | 0x04 | 4 | `edge_count` (u32 LE) |
|  | 0x08 | 4 | `flags` (u32 LE) — bit 0 = `INTEGRITY_PRESENT` |
|  | 0x0C | 4 | reserved (zero) |
| **Node entries** (×`node_count`, 8-byte aligned) | +0x00 | 1 | `node_kind` (u8): `0x01`=address, `0x02`=offset, `0x03`=symbol |
|  | +0x01 | 1 | reserved |
|  | +0x02 | 2 | `label_len` (u16 LE) — UTF-8 byte length including NUL, or 0 |
|  | +0x04 | 8 | `value` (u64 LE) — address, offset, or symbol id |
|  | +0x0C | `pad8(label_len)` | UTF-8 + NUL, padded to 8 bytes |
| **Edge entries** (×`edge_count`) | +0x00 | 4 | `src_idx` (u32 LE) — index into nodes |
|  | +0x04 | 4 | `dst_idx` (u32 LE) — index into nodes |
|  | +0x08 | 1 | `edge_kind` (u8): `0x01`=pointer, `0x02`=call, `0x03`=import |
|  | +0x09 | 1 | reserved |
|  | +0x0A | 2 | `metadata_len` (u16 LE) |
|  | +0x0C | `pad8(metadata_len)` | UTF-8 + NUL, padded to 8 bytes |
| **Integrity trailer** (when `flags & 0x01` is set) | end | 32 | BLAKE3 of (header + nodes + edges) |

Writer encoder lives in `msl/writer.py:_build_pointer_graph_block`; reader decoder is `msl/decoders_ext.py:decode_pointer_graph`. The integrity trailer is independent of the main container's chain; verify it with `decoders_ext.verify_pointer_graph_integrity(graph, raw_payload)`.

### Storage relationship

Pointer relationships are stored independently in MemDiver's `ProjectDB` (DuckDB) so users can query them without ever exporting an MSL file. MSL export is one of several sinks (alongside Vol3 / YARA / JSON via `architect/`); the user opts in to inclusion at write time by calling `MslWriter.add_pointer_graph(nodes, edges)`. Future revisions of this section will document the `ProjectDB` schema (`pointer_graph_nodes`, `pointer_graph_edges` tables) once that integration lands.
