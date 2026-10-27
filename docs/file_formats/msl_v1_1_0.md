# Memory Slice (.msl) — Specification v1.1.0 (binary format 1.1)

MemDiver's native snapshot format. Container for memory regions, module tables, process identity, thread contexts, VAS maps, connection tables, handle tables, key hints, provenance metadata and appended extension segments with BLAKE3 integrity chaining.

This is the 1.1.0 mirror. The previous mirror, [msl_v1_0_0.md](msl_v1_0_0.md), describes the 1.0.0 document and the pre-1.1 MemDiver behaviour (header-count patching, 40-byte EoC, pointer-graph appendix); it is kept for reference only.

## Specification source

This document describes MemDiver's implementation of the Memory Slice format defined in the official specification:

- **Spec repository:** <https://github.com/MemorySlice/memslice-spec>
- **Spec document version:** 1.1.0 (Working Draft, 2026-10-23; §15 Revision History)
- **Binary format code** (file header offset `0x0A`): `0x0101` (major `0x01`, minor `0x01`; the spec calls this "v1.1")

With 1.1.0 the document version and the on-wire code finally agree on the minor number. The spec's version rule (§3.4) is: an unknown **major** SHOULD be rejected; an unknown **minor of a known major MUST parse**, because minor revisions only add block types, reserved-field semantics and optional structures that an older consumer skips by the usual rules (`BlockLength` for unknown types, reserved fields ignored). Files that use any 1.1 feature — extension segments, EoC `BlockCount`, `HashAlgo`, Thread Context, VAS Map `NameSource`, blocks `0x0054` / `0x0059`–`0x005B`, page state NotResident — SHOULD write `0x0101`; files written as `0x0100` remain valid and MemDiver reads both.

What changed between 1.0.0 and 1.1.0 (spec §15), in the order this mirror covers it: EoC `BlockCount` at `+0x28` with the header count never patched; extension segments and the End-of-Extension block `0x0FFE`; the VAS Map payload defined with `NameSource`; Thread Context `0x0011`; the new blocks `0x0059`–`0x005B` (and `0x0054` Connectivity Table); page state `11` = NotResident; the header `HashAlgo` selector.

MemDiver implements the spec's consumer requirements (§14.2) in full. Every reader path takes the *effective* VAS Map, the last one in file order across the capture segment and the verified (and verified sealed) extension segments (`MslReader.effective_vas_map()`; `collect_vas_map()` still returns the raw capture-segment list). The producer (§14.1) supports both Analysis-mode and Investigation-mode acquisition: Process Identity, Module List Index, Module Entry, System Context, Process/Connection/Handle/Connectivity tables, Memory Region (with the four-state page model), Key Hint, Related Dump, Import Provenance, VAS Map, and End-of-Capture; analysis-derived data (the pointer graph) goes into an extension segment. Per-block payload compression (§4.2.1) and full-container AEAD encryption (§10) are emitted by the writer and consumed by the reader.

## Implementation status

### MemDiver 1.1 migration

The 1.0.0 mirror documented behaviour that 1.1.0 changes. The new behaviour, per item:

| Area | MemDiver 1.0 behaviour | MemDiver 1.1 behaviour |
|---|---|---|
| Header `BlockCount` (`0x39`) | treated as reserved; count known only after patching / not written | the **exact** capture-segment count (EoC included) when known at header-write time, else `0`; **never patched** afterwards (header bytes are covered by Block 0's `prev_hash` and by `FileHash`) |
| EoC payload | 40 bytes (`file_hash` + `acq_end`) | **48 bytes**: `file_hash`, `acq_end`, `block_count` at `+0x28` (exact, always known at EoC time), 4 reserved. A 40-byte EoC from older files is still accepted and reads as count unknown |
| Pointer graph `0x1003` | "appendix" block after EoC with zero `prev_hash`, outside the chain | an **extension segment** chained from the EoC block (`prev_hash` = BLAKE3 of the EoC block; zero inside an encrypted container) and terminated by End-of-Extension `0x0FFE` |
| VAS Map names | trusted by inference (provenance marker / live capture) | trusted by **`NameSource`** (`Live` / `SourceMetadata`); the old inference is the fallback when `NameSource` is `Unspecified` (0), which is what every pre-1.1 file carries |
| `verify_chain` | `prev_hash` chain up to and including EoC | `prev_hash` chain, **`FileHash`**, both **block counts** (header and EoC, each when non-zero, against the parsed count), and then every **extension segment** (chain continuity, `SegmentHash`, `BlockCount`); a segment that fails or is unterminated is trailing data, never presented as verified |
| Header `version` | writes `0x0101` | writes `0x0101`; reads any `0x01xx` (minor MUST-parse rule) and rejects other majors |

**Encryption (§10).** Both cipher suites (AES-256-GCM, XChaCha20-Poly1305), both KDFs (raw key, Argon2id passphrase), and HKDF-BLAKE3 key derivation ship in the base install (`cryptography`, `PyNaCl`, `argon2-cffi`, `blake3`). KeyEncap=None and X25519 work out of the box. Post-quantum key encapsulation — ML-KEM-768, ML-KEM-1024, and the recommended X25519+ML-KEM-768 hybrid — requires the optional `[crypto]` extra (`liboqs-python`); without it those mechanisms report unavailable and raise a clean error. The reader exposes a `TagStatus` (`VALID` / `CORRUPTED` / `MISSING_KEY` / `NOT_ENCRYPTED`) so consumers can communicate the AEAD verification outcome. Per §10.6, encrypted files carry zero `PrevHash` on every block — capture segment and extension segments alike — and an EoC `FileHash` computed over plaintext; `verify_chain` skips the chain-continuity check for encrypted files (§14.2 rule 16) and relies on the AEAD tag, but still checks `FileHash`, the block counts and each segment's `SegmentHash` / `BlockCount` after decryption.

**Implementation note — verify once, then seek (no format change).** The reader no longer decrypts the container into RAM. On `open()` it verifies the single AEAD tag in one bounded, streamed pass over the memory-mapped ciphertext (1 MiB slices; AES-256-GCM via an incremental GCM decryptor whose output is discarded, XChaCha20-Poly1305 via Poly1305 over `AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths` without decrypting), and only after a valid tag serves plaintext ranges by decrypting them on demand with the AEAD's underlying stream cipher: AES-GCM (96-bit nonce) ciphertext block *i* uses counter block `nonce ‖ be32(2 + i)` with the GCM `inc32` rule; XChaCha20 uses ChaCha20 under the HChaCha20 sub-key with IETF nonce `0⁴ ‖ nonce[16:24]` and block counter `1 + i` (block 0 is the Poly1305 key). Limits follow the ciphers: 2^39 − 256 bits (≈64 GiB) per message for GCM, 64 × (2^32 − 1) bytes (≈256 GiB) for XChaCha20. Read-side RAM is O(cache) — a 16 × 256 KiB page LRU plus the requested range — instead of 1–2× the file size. A tampered ciphertext, tag or AAD still yields `TagStatus.CORRUPTED` with no plaintext exposed. Because decrypted bytes are re-read from the file after verification, the reader records `(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)` of the open descriptor before the verification pass and re-checks it after every ciphertext read, failing with `MslSourceChangedError` on any change. **Residual risk:** an in-place modification that leaves all of those fields unchanged (same-tick writes on coarse-timestamp filesystems, writes through another process's shared mapping not yet reflected in the inode, or a privileged actor manipulating the clock) is not detected, and such bytes would decrypt to unauthenticated plaintext; truncating the file under the mapping can raise `SIGBUS`, as for plaintext files. Reopening re-verifies. The legacy one-shot decrypt (`aead_decrypt` over the whole ciphertext) remains available for debugging via `MEMDIVER_MSL_DECRYPT_ONESHOT=1`. On the write side, in-memory `write()` (no streamed regions) still encrypts the full plaintext block stream in one shot; streamed writes do not buffer (next note).

**Update — streaming encryption on write.** The *writer* no longer needs the whole plaintext: `MslWriter.write_streaming()` (and `write()` whenever a region was registered with `add_memory_region_source()`) emits encrypted containers through an incremental AEAD (`msl/aead_stream.py`). AES-256-GCM uses the `cryptography` hazmat `Cipher(AES, GCM)` encryptor; XChaCha20-Poly1305 is composed from HChaCha20 (sub-key), the `cryptography` ChaCha20 stream cipher and its incremental Poly1305 MAC, byte-identical to libsodium's `crypto_aead_xchacha20poly1305_ietf`. The on-disk format is unchanged — still ONE AEAD over the whole block stream (`[Header 128B | KEM ct | ciphertext | Tag 16B]`, zero PrevHash, EoC FileHash over header + KEM ct + plaintext blocks, extension segments after EoC inside the ciphertext — nothing may follow the tag) — and for the same nonce the streamed file equals the in-memory one. Ciphertext is produced in 1 MiB slices, so writer peak RAM is O(1 MiB) independent of region size. Compression combined with streamed regions remains refused. *Decryption* on read is bounded too — see the verify-once-then-seek note above.

**Materializing an encrypted `.msl` (re-wrap).** A region-filtered copy (`import --materialize` / `materialize_msl`) of an encrypted source requires its key material (without it: "key material required"; with a wrong key: "decryption failed"; nothing is written either way). By default the copy is **re-encrypted** with the same content-encryption key and the same key wrapping — same KDF salt and Argon2id parameters, same KEM ciphertext, raw key unchanged — so the same key / passphrase / private key opens it. `dump_uuid` is preserved, which the KEM case requires (CEK = HKDF-BLAKE3(shared, salt=dump_uuid, info="MSL-CEK-v1")). The AEAD nonce is **always fresh** (CSPRNG); the writer refuses to reuse the source nonce, since nonce reuse under the same CEK is catastrophic. A plaintext copy is written only on explicit opt-in (`decrypt_output=True`, CLI `--decrypt-output`), and the import result carries a warning. The re-wrap handle (`MslReader._rewrap_material()`) is available only after a verified tag, has a redacted `repr`, and its CEK is zeroised (best effort) on `close()`.

The same inputs exist on every surface: CLI `import` / `import-dir` (`--key-file`, `--passphrase`, `--kem-key-file`, `--decrypt-output`), MCP `import_raw_dump` / `preview_import` (`key_file`, `passphrase`, `kem_key_file`, `decrypt_output`), and REST `POST /api/dumps/preview` and `/api/dumps/import-path` JSON bodies plus `/api/dumps/upload` form fields (`passphrase`, `key_hex`, `kem_key_hex`, `decrypt_output`). Key material is accepted in the request body / form only, never in the query string, and is never cached or logged. The import preview reports `encrypted` and `decrypted` flags.

Two reader-side compatibility quirks remain by design:

1. **SYSTEM_CONTEXT deviation tail (read-only).** The reader still parses an `uptime_ns` + `os_version` deviation tail past the spec-defined `CaseRef` field, for backward compatibility with files produced by older MemDiver builds. The current writer never emits this tail — it stays pure-spec.
2. **RELATED_DUMP legacy layout.** The reader accepts the 24-byte pre-C1 payload (without `target_hash`) as well as the spec-mandated 56-byte layout. The writer always emits the full 56-byte form.

## Design goals

- **Streaming-friendly** — writers finalize a BLAKE3 file hash without rewinding.
- **Compression-agnostic** — each block carries its own codec (`none`, `zstd`, `lz4`) via flag bits.
- **Forward-compatible** — unknown block types fall back to `GenericBlock`.
- **Integrity-first** — each block carries a BLAKE3 of the previous block, producing a per-file hash chain whose capture part is sealed by `END_OF_CAPTURE` and which continues unbroken through every extension segment.
- **Append-only enrichment** — derived data is added after the capture in self-delimiting, self-verifying extension segments; the header and the capture segment are never rewritten.

## Constants

| Constant | Value | Where |
|---|---|---|
| `FILE_MAGIC` | `b"MEMSLICE"` | `msl/enums.py:9` |
| `BLOCK_MAGIC` | `b"MSLC"` | `msl/enums.py:10` |
| `FILE_HEADER_SIZE` | `64` | `msl/enums.py:11` |
| `FILE_HEADER_ENC_SIZE` | `128` (encrypted files) | `msl/enums.py:12` |
| `BLOCK_HEADER_SIZE` | `80` | `msl/enums.py:13` |

## File header (64 bytes)

Layout per spec §3.1 (Table 3). The 1.0.0 reader (`msl/reader.py:90-122`) treated `0x39..0x3F` as reserved; 1.1 names them.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 8 | magic | `b"MEMSLICE"` |
| 0x08 | 1 | endianness | `0x01` little, `0x02` big |
| 0x09 | 1 | header_size | declared header length (64 or 128) |
| 0x0A | 2 | version | uint16; `major = hi byte`, `minor = lo byte`; `0x0101` for files using 1.1 features, `0x0100` still valid. Unknown minor of major 1 MUST parse |
| 0x0C | 4 | flags | `HeaderFlag` — `IMPORTED`, `INVESTIGATION`, `ENCRYPTED` |
| 0x10 | 8 | cap_bitmap | capability bitmap |
| 0x18 | 16 | dump_uuid | UUID |
| 0x28 | 8 | timestamp_ns | nanoseconds since epoch |
| 0x30 | 2 | os_type | `OSType` (Windows / Linux / macOS / Android / iOS / FreeBSD) |
| 0x32 | 2 | arch_type | `ArchType` (x86 / x86_64 / ARM64 / ARM32) |
| 0x34 | 4 | pid | process ID |
| 0x38 | 1 | clock_source | clock-source identifier |
| 0x39 | 4 | block_count | number of capture-segment blocks **including EoC**; `0` = unknown. **Never patched after writing.** Extension-segment blocks are never counted |
| 0x3D | 1 | hash_algo | integrity hash selector (spec Table 11a): `0x00` BLAKE3 (default, what MemDiver writes), `0x01` SHA-256, `0x02` SHA-512/256. Applies to `prev_hash`, `FileHash`, `SegmentHash`, `DiskHash`; never to HKDF-BLAKE3 key derivation |
| 0x3E | 2 | reserved | zero-filled |

**BlockCount semantics (spec §3.1).** A producer that does not know the count when it writes the header (streaming acquisition) MUST write `0` and MUST NOT patch the field later — the header is covered by Block 0's `prev_hash` and by the EoC `FileHash`, so a patch would invalidate both. The exact count is always known when the EoC block is written and goes into the EoC `BlockCount` (see below). Every non-zero count, header or EoC, MUST equal the number of capture-segment blocks actually parsed (EoC included); otherwise the file is truncated or corrupt (consumer rule 13). MemDiver writes the exact count in **both** places (it knows the block list before writing the header) and `verify_chain` checks both.

When the `ENCRYPTED` flag bit is set, `MslReader` does not raise: it opens the file (which must declare `HeaderSize=128`), parses the 64-byte encryption extension at 0x40, and tries to decrypt with the key material passed to the constructor (`key=`, `passphrase=`, `kem_private_key=`). The outcome is reported in `reader.tag_status`: `VALID` (tag verified, blocks readable), `MISSING_KEY` (no matching key material, or an unavailable algorithm such as ML-KEM without liboqs), or `CORRUPTED` (wrong key, tampered ciphertext/AAD, or a malformed header code). Only `VALID` exposes blocks; otherwise the block walk is empty.

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
| 0x30 | 32 | prev_hash | BLAKE3 (or the header's `hash_algo`) of the previous block on disk; Block 0 hashes the file header. The chain runs through `END_OF_CAPTURE` and continues into extension segments. All zero when `ENCRYPTED` |

Compression is encoded in `flags`, not in a dedicated codec field:

| `BlockFlag` bit | Meaning |
|---|---|
| `COMPRESSED` (bit 0) | payload is compressed |
| `COMP_ZSTD` (bit 1) | zstd |
| `COMP_LZ4` (bit 2) | lz4 |
| `HAS_KEY_HINTS` (bit 3) | block contains / references key hints |
| `HAS_CHILDREN` (bit 4) | block has child blocks |
| `CONTINUATION` (bit 5) | fragment of a larger logical block; merged by `MslReader` |

**Compressed payload framing (spec §4.2.1, Table 9).** When `COMPRESSED` is set, the on-disk payload is `u64 UncompressedSize` (LE) followed by the codec stream, and `block_length` = 80 + 8 + len(stream). The codec streams match memslicer byte for byte: zstd is one zstd frame; lz4 is one lz4 *block* with a 4-byte LE stored-size prefix (`lz4.block.compress(data, store_size=True)`), not an lz4 frame. The BLAKE3 chain covers these on-disk bytes. On read (`msl/compress.py`) the inflated length must equal `UncompressedSize` (consumer rule (20)); a mismatch, a short prefix or a malformed stream raises `MslParseError`. Trailing zero padding to 8 bytes (written by memslicer) is tolerated for both codecs.

**Legacy compressed payloads.** MemDiver versions before this fix wrote the bare codec stream with no size prefix (zstd frame, or lz4 *frame*). These files remain readable. Detection is deterministic: a payload is legacy when it starts with the lz4 frame magic `04 22 4D 18` and byte 4 (the lz4 FLG byte, never zero) is non-zero, or with the zstd frame magic `28 B5 2F FD` and offset 8 does not also hold that magic. A spec payload cannot match. For lz4, bytes 4..7 are the high half of `UncompressedSize`, which must be zero because the lz4 block's u32 stored size has to equal it. For zstd, the spec frame always carries the zstd magic at offset 8. The writer also checks every payload it frames and refuses one that would be classified as legacy. Pass-through copies (`add_raw_block`, materialize/re-wrap) keep a block's on-disk bytes unchanged, so a legacy block stays legacy and its hash chain stays valid.

## Block type registry (spec Table 11)

Source: `msl/enums.py:27-51`, plus the 1.1 additions marked **new**.

| Code | Name | Notes |
|---|---|---|
| `0x0000` | `INVALID` | sentinel |
| `0x0001` | `MEMORY_REGION` | primary payload — bytes + metadata |
| `0x0002` | `MODULE_ENTRY` | loaded module record |
| `0x0010` | `MODULE_LIST_INDEX` | index of module entries |
| `0x0011` | `THREAD_CONTEXT` | per-thread register file (spec §5.7, defined in 1.1); capture segment only. See "Thread Context" below |
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
| `0x0054` | `CONNECTIVITY_TABLE` | routing / ARP / socket-family aggregate (spec §6.6). Spec 1.1 assigns `0x0054`; the 1.0 enum used `0x0055` — the reader accepts both, the writer follows the spec |
| `0x0059` | `PHYSICAL_MEMORY_MAP` | **new** — host physical address ranges (spec §5.9); defined for stability, not yet emitted by any known producer. Capture or extension segment |
| `0x005A` | `MODULE_BUILD_ID_MANIFEST` | **new** — build IDs / disk hashes merged into the module list by `BaseAddr` (spec §5.10). Capture or extension segment |
| `0x005B` | `REGION_OMISSION_MANIFEST` | **new** — ranges the acquirer deliberately skipped, with scope / pattern and a per-row reason (spec §5.11). Capture or extension segment |
| `0x0FFE` | `END_OF_EXTENSION` | **new** — terminates an extension segment: `SegmentHash`, `WrittenAt`, `BlockCount`, `Producer` (spec §4.6). See "Extension segments" below |
| `0x0FFF` | `END_OF_CAPTURE` | ends the capture segment: `FileHash`, `AcqEnd`, and (1.1) the exact capture-segment `BlockCount` at `+0x28` (spec §4.5). See "End-of-Capture" below |
| `0x1001` | `VAS_MAP` | virtual-address-space map: one entry per enumerated range, with `NameSource` (spec §5.8, payload defined in 1.1). See "Layout and mapping names in VAS_MAP" below |
| `0x1003` | `POINTER_GRAPH` | producer-defined Structural payload (MemDiver's pointer graph). Spec 1.1 permits it **only in extension segments**. See "POINTER_GRAPH extension segment" below |

Unknown block-type codes are preserved verbatim as `GenericBlock` so future spec revisions remain readable by older readers. `0x0012`–`0x0015` remain reserved evidence types without a payload definition: producers MUST NOT emit them anywhere, and they are excluded from extension segments.

## End-of-Capture (0x0FFF) and block counts

Spec §4.5. The EoC block is the last block of the **capture segment** (the evidence: Block 0 through EoC, exactly as the acquirer or importer wrote it). A verified EoC MAY be followed by extension segments; bytes after the last verified segment are non-MSL trailing data.

| Offset | Size | Field | Notes |
|---|---|---|---|
| +0x00 | 32 | file_hash | hash (`hash_algo`) of all bytes from offset 0 through the last byte before this block. Computed over plaintext even when encrypted |
| +0x20 | 8 | acq_end | acquisition end, UTC ns since epoch |
| +0x28 | 4 | block_count | number of capture-segment blocks **including this EoC**; `0` = unknown. A producer SHOULD write the exact count — it is always known here |
| +0x2C | 4 | reserved | zero |

1.0.0 defined `+0x28`–`+0x2F` as reserved, and some 1.0.0 producers (MemDiver among them) wrote a 40-byte payload without those bytes. Consumers MUST accept a 40-byte EoC payload and treat its count as unknown.

**MemDiver 1.1 migration.** The writer emits the 48-byte payload with the exact count; the reader accepts 40 and 48 bytes. `verify_chain` checks `file_hash`, then compares every non-zero count (header and EoC) with the number of capture-segment blocks it parsed; a mismatch reports the file as truncated or corrupt.

## Extension segments and End-of-Extension (0x0FFE)

Spec §4.6. An `.msl` file is: file header, exactly one capture segment, zero or more **extension segments**, in that order.

```
File Header | Capture segment: Block 0 … EoC (0x0FFF) | [AEAD tag] | Extension segment 1 | … | Extension segment n | [trailing data]
                                                                     └─ blocks … End-of-Extension (0x0FFE) ─┘
```

An extension segment is a run of one or more blocks terminated by an End-of-Extension block. It lets producers other than the acquirer — enrichment tools, analysis frameworks, importers preserving third-party annotations — add blocks after the capture completed, without rewriting or re-hashing the capture segment and without patching the header. Each segment is self-delimiting and self-verifying, so a file stays usable if an appending tool is interrupted.

**Chain continuity.** The `prev_hash` chain does **not** stop at EoC: the first block of the first extension segment carries the hash of the EoC block, and the first block of segment *k*+1 hashes the End-of-Extension block of segment *k*. When `ENCRYPTED` is set, every `prev_hash` in an extension segment is zero, as in the capture segment.

**End-of-Extension payload (spec Table 12a).**

| Offset | Size | Field | Notes |
|---|---|---|---|
| +0x00 | 32 | segment_hash | hash (`hash_algo`) of all bytes from the start of the segment's first block through the last byte before this block |
| +0x20 | 8 | written_at | UTC ns since epoch; `0` if unknown |
| +0x28 | 4 | block_count | blocks in this segment **including** this one; MUST be exact (never 0) |
| +0x2C | 4 | reserved | zero |
| +0x30 | 2 | producer_len | length of `producer` incl. NUL; `0` = none |
| +0x32 | 6 | reserved | zero |
| +0x38 | var | producer | UTF-8, pad8; name and version of the appending tool (e.g. `memdiver/<version>`) |

**Forbidden in a segment** (evidence types): Memory Region `0x0001`, Module Entry `0x0002`, `0x0010`–`0x0015` (Module List Index, Thread Context, the reserved evidence types), Import Provenance `0x0030`, Process Identity `0x0040`, `0x0050`–`0x0058` (System Context and the investigation tables), End-of-Capture `0x0FFF`.

**Allowed in a segment:** Key Hint `0x0020`, Related Dump `0x0041`, `0x0059`–`0x005B`, and the whole Structural namespace `0x1000`–`0x1FFF` (VAS Map, Pointer Graph). Block types whose payload the spec does not define (Pointer Graph `0x1003`, other producer-defined Structural types) MAY appear **only** here. Segment blocks MAY reference capture-segment blocks or earlier segments by `parent_uuid` or payload-embedded UUID.

**Producer rules (§14.1 rules 33–37).** Never modify any byte of the header, the capture segment or an existing segment; terminate every segment with an End-of-Extension block carrying the exact `segment_hash` and `block_count`; continue the `prev_hash` chain from the last block already in the file (zero when encrypted); emit only the permitted types; on finding trailing data after the last verified segment, refuse to append rather than build on unverified bytes. In an encrypted container a segment must lie **inside** the AEAD ciphertext (written before the tag is finalized); nothing can be appended to a sealed container.

**Consumer rules (§14.2 rules 14, 23–25).** After verifying the EoC block (and the AEAD tag when encrypted), parse segments: read blocks until an End-of-Extension block, then verify (a) chain continuity from the preceding block (unencrypted files only), (b) `segment_hash`, (c) `block_count`. Only a segment passing all three is a *verified segment* whose blocks may be presented alongside the capture. A segment that fails, or is unterminated (EOF, non-magic bytes, or a framing failure before an End-of-Extension is found), is trailing data from its first byte to EOF and is never presented as verified. Unrecognised payloads inside a verified segment are skipped by `block_length`. The last VAS Map in file order wins; Module Build-ID Manifest rows merge into the module list by `BaseAddr`.

**MemDiver 1.1 migration.** `MslReader._iter_raw_blocks` still stops at EoC for the capture-segment collectors (regions, key hints, …), so they never see segment blocks. Segment-aware access walks the verified segments; `verify_chain` performs the three checks above per segment and reports unterminated or failing segments as trailing data. The writer appends its own blocks (today: the pointer graph) as one segment with `producer = memdiver/<version>`.

## Thread Context (0x0011)

Spec §5.7, Tables 19a / 19b. One block per captured thread: TID, start time, flags (`Current`, `Crashed`, `Suspended`, `Partial`), scheduling state, an optional `Arch` override (0 = header `arch_type`; e.g. a WOW64 x86 thread in an x86_64 process), an optional thread name, and `RegCount` self-describing register entries (`NameLen`, `Width`, flags marking program counter / stack pointer / frame pointer / flags / thread pointer / link register, lowercase canonical mnemonic, value in file byte order, pad8). Presence is advertised by `cap_bitmap` bit 2 (`ThreadContexts`); exactly one block SHOULD set `Current`, otherwise the first in file order counts as current. A producer MUST include at least the program counter and stack pointer.

Thread Context is **evidence**: it MUST be in the capture segment, never in an extension segment, and SHOULD precede the first Memory Region. Consumers MUST preserve registers they do not recognise and MAY use stack-pointer entries to attribute regions to threads. Importers MAY emit it from ELF core `NT_PRSTATUS` notes or minidump thread lists. Full field tables: spec §5.7 (Tables 19a and 19b).

**MemDiver 1.1 migration.** The reader decodes the block; the 1.0 enum row (`THREAD_CONTEXT`, "per-thread register snapshot") was a placeholder with no payload. `MslWriter.add_thread_context()` encodes it (lowercase names, pad8, sets CapBitmap bit 2), and the ELF-core (x86_64, aarch64 incl. `NT_ARM_TLS` → `tpidr_el0`) and minidump (AMD64 with TEB → `gs_base`, ARM64) importers emit one block per thread right after Block 0 / the module list, before the first Memory Region. Flags: `Suspended` always; `Partial` when the CONTEXT lacks register groups; `Crashed`+`Current` on the ELF crashed thread (first non-zero `pr_cursig`) or the minidump exception thread, else `Current` on the first emitted thread. Threads whose registers fail to decode or lack PC/SP are skipped; other architectures emit none. `ThreadState` is written as Stopped.

## Page state map (four states)

Spec §7 (renamed from the three-state model in 1.0.0). Each page of a `MEMORY_REGION` is 2 bits in the `PageStateMap`:

| Bits | State | Meaning | Data |
|---|---|---|---|
| `00` | Captured | read OK; stored | one page |
| `01` | Failed | mapped but unreadable | none |
| `10` | Unmapped | TOCTOU: absent at read time | none |
| `11` | NotResident | **new** — mapped but never touched at read time (anonymous, not present, not swapped); content is known to be zero. Emitted only by resident-only acquisition | none |

A NotResident page carries no data exactly like Failed and Unmapped. Readers that predate the state MUST treat it as a zero-content page (consumer rule 26) — never as a read failure; counting it as Failed is acceptable but overstates loss. MemDiver's reader materialises NotResident pages as zeros and reports them separately from Failed.

## Other 1.1 blocks (0x0059–0x005B)

Summaries; field tables are in spec §5.9–§5.11. All three may sit in the capture segment or in an extension segment and have `parent_uuid` zero.

- **Physical Memory Map (`0x0059`, §5.9).** Rows of `(Start, End inclusive, Label)` as in the top level of Linux `/proc/iomem`; rows are packed (not 8-byte aligned), `Label` has no NUL and no padding, walk by `LabelLen`. Defined for stability; no known producer emits it.
- **Module Build-ID Manifest (`0x005A`, §5.10).** Fixed 64-byte rows keyed by module `BaseAddr`: `BuildIdLen` (0 / 16 / 20), `BuildIdSource` (`None`, `Bridge`, `MapFiles`, `OnDisk`, `CapturedRegion`, `Retroactive`), flags (`Deleted`, `MemFd`, `AnonRWX`, `Unlinked`), 20-byte `BuildId`, 32-byte `DiskHash`. Readers merge rows into the module list; a non-zero `DiskHash` supersedes an all-zero one in the matching Module Entry; dangling rows are reported, never discarded.
- **Region Omission Manifest (`0x005B`, §5.11).** Preamble with the acquirer's `Scope` string (e.g. `heap,stack`) and newline-joined exclusion `Patterns`, then rows `(BaseAddr, Size, Protection, RegionType, Reason, Name)` with `Reason` `1` = ModuleExclude, `2` = Scope. Strings in this block carry **no NUL** (length counts UTF-8 bytes only, zero-padded to 8). Emitted only when at least one range was omitted; such ranges are absent from the region stream but present in the VAS Map. This is the spec-level counterpart of MemDiver's provenance selection segment (below), which records the same selection for imports.

:::{note}
Kaitai Struct is used only for foreign binaries (ELF, PE, Mach-O) under `core/binary_formats/kaitai_compiled/`. The `.msl` format itself is hand-rolled, with `MslReader` / `MslWriter` as the reference implementations.
:::

## Region types written by importers

`MEMORY_REGION.region_type` uses `RegionType` (`msl/enums.py`, spec §5.1). The ELF-core and minidump importers write `IMAGE` / `MAPPED_FILE` for file-backed ranges, `ANONYMOUS` for private memory, and `STACK` for an anonymous region identified as a thread stack (the PT_LOAD segment containing a thread's saved SP, or a minidump ThreadList stack range). Only `ANONYMOUS` regions are promoted to `STACK`; a stack range overlapping a region of any other stored type keeps that type.

Alignment keys (`anon:{TYPE}:{size}:{ordinal}`, `core/region_align.py`) fold such importer-derived `STACK` regions — those in a file whose `IMPORT_PROVENANCE.source_format` is ELF core or minidump — back into the `ANONYMOUS` key class, so `.msl` files imported before stacks were recorded (stack stored as `ANONYMOUS`) and after produce identical keys and ordinals. `STACK` regions written by a live producer (no such provenance) keep their own `anon:STACK:` key class.

Live memslicer captures whose mapping names are trusted (see "Trust rule" below; no `IMPORT_PROVENANCE`, `IMPORTED` flag clear, `VAS_MAP` present) are folded the same way: newer memslicer releases store name-based types (e.g. `HEAP` for `[anon:scudo:primary]`), older ones stored the type of the old path rules (`UNKNOWN` for that name). Alignment re-derives the old type from the stored name (`legacy_live_region_type` in `msl/region_names.py`) so both produce the same `anon:` keys. A filtered alignment that mixes dumps classified by mapping names with dumps classified by stored type only logs a classification-basis warning (`classification_basis_warning`, `DumpRegionMap.classification_basis` = `mapping_names` / `stored_type`, `core/region_align.py`), since a category filter can then keep a region in one dump and drop it in another.

**Regioned raw imports.** A raw `.bin` / `.dump` with a `/proc/<pid>/maps` sidecar (gdb_raw / lldb_raw / fridump layout; CLI `import --maps`, REST `/api/dumps/preview` / `import-path` `maps_path`, `/api/dumps/upload` optional second file field `maps`, MCP `maps_path`) is imported by `import_regioned_raw`: one `MEMORY_REGION` per maps entry at its real base address, `region_type` from the maps path (`[heap]` → `HEAP`, `[stack]` → `STACK`, libraries → `IMAGE`, other files → `MAPPED_FILE`, anonymous → `ANONYMOUS`, shared generic mappings → `SHARED_MEM`), protection from the `rwx` columns, file-backed paths in a Module List Index, and a truncated last entry keeps its listed size with the missing pages `FAILED`. Its `IMPORT_PROVENANCE.source_format` is `0xFFFF` (Other) with the origin field `source_format=regioned_raw` in the note (materialized copies carry `source_format=msl`); spec Table 40 fixes `0x0004` macOS core / `0x0005` ProcDump, which collided with MemDiver's former `0x04` MSL / `0x05` REGIONED_RAW. On read, 0x0004 / 0x0005 keep the legacy meaning only when the provenance `tool_name` is `memdiver`; from any other writer they are macOS core / ProcDump (`msl/source_format.py`, `effective_source_format`). Unchanged: `0x01` raw, `0x02` ELF core, `0x03` minidump. Unlike `RAW_DUMP`, these regions are classified normally at analysis time, and because `STACK` comes from an observed `[stack]` path (as with a live producer) it keeps its own `anon:STACK:` alignment key class. A sidecar that does not describe the bin exactly falls back to a plain raw import with a warning. The full maps path column (e.g. `[anon:scudo:primary]`, `[anon:dalvik-main space]`) is kept as the region's mapping name and stored in the `VAS_MAP` (see below); the stored `region_type` stays the path-derived one above.

**Header `os_type` written by importers.** The ELF-core and regioned-raw importers write `OSType.ANDROID` when any mapping name (ELF `NT_FILE` path or maps path) carries an unmistakable Android marker (`looks_android` in `msl/region_names.py`: e.g. `[anon:dalvik-`, `[anon:scudo:`, `[anon:stack_and_tls:`, `[anon:bionic`, `/dev/ashmem/`, `/apex/`, `/system/bin/linker`, `/system/bin/app_process`, `/system/lib64/`, `/system/framework/`, `/data/dalvik-cache/`, `/dev/__properties__`), and `OSType.LINUX` otherwise. The import preview reports the same decision as `platform` (`android` / `linux`) with `platform_source` `mapping_names` (Android markers found) or `format` (implied by the source format). Minidump imports report `windows` / `format`.

**Header `arch_type` written by importers.** The ELF-core importer maps the core's `e_machine` to `ArchType` (`EM_X86_64` → `X86_64`, `EM_386` → `X86`, `EM_AARCH64` → `ARM64`, `EM_ARM` → `ARM32`; any other machine → `UNKNOWN`, `0xFFFF`) via `machine_to_arch_type` (`core/binary_formats/elf_core_reader.py`). The minidump importer maps `MINIDUMP_SYSTEM_INFO.ProcessorArchitecture` the same way (`AMD64`, `INTEL`, `ARM64`, `ARM`; else `UNKNOWN`). Raw and regioned-raw imports carry no architecture in the source, so they write the caller-supplied `arch_type` (default `UNKNOWN`). `arch_type` is header metadata only: it does not enter alignment keys or region classification.

## Region selection on import: VAS_MAP and provenance

An import with a region selection (CLI `import` / `import-dir` `--regions` / `--exclude-regions`, MCP `import_raw_dump` `region_types` / `exclude_region_types`, REST `regions` / `exclude_regions`, or `--materialize` of an existing `.msl`) writes only the selected `MEMORY_REGION` blocks. Two blocks record what was dropped. Neither changes the binary format.

### Layout and mapping names in VAS_MAP (0x1001)

Spec §5.8 defines the payload in 1.1 (Table 19c): a preamble `Count` (u32) and `EntrySize` (u32; `0` = variable, each entry sized by its `PathLen`), then `Count` entries with a 24-byte head — `BaseAddr` u64, `RegionSize` u64, `Protection` u8, `RegionType` u8, `PathLen` u16, **`NameSource` u8 at `+0x14`**, 3 reserved bytes — followed by `MappedPath` (UTF-8, pad8) when `PathLen` is non-zero. The RECOMMENDED position is immediately before EoC; an analysis tool MAY add one in an extension segment; the **last** VAS Map in file order supersedes earlier ones. Consumers MUST NOT derive page states from it.

`NameSource` codes: `0x00` Unspecified (consumer infers; what every pre-1.1 file carries, since the byte was reserved zero), `0x01` Live (enumerated from the running process by the acquirer), `0x02` SourceMetadata (ELF `NT_FILE`, minidump module / memory-info streams, a maps sidecar), `0x03` Synthesized (derived by the producer from region boundaries or heuristics). Consumers SHOULD trust names for classification only from Live or SourceMetadata entries.

The **ELF-core and regioned-raw importers always** add **one** `VAS_MAP` block listing the **full** source layout with every region's full mapping name: every region, kept or excluded, sorted by `base_addr`, whether or not a selection was passed (`_add_named_vas_map` in `msl/importer.py`). Their provenance base note then carries the `region_names=1` marker segment (see "Trust rule" below).

The **minidump importer** is unchanged: it adds the `VAS_MAP` only when a selection excludes at least one region. No selection, `all`, a selection that excludes nothing, or a zero-byte fallback writes no `VAS_MAP` for a minidump. A plain raw import never writes one, since its single region is either kept or the selection falls back to `all`.

Each entry holds the source region's values as the importer's region preview sees them (`msl/writer.py` `add_vas_map`, decoded by `decode_vas_map` in `msl/decoders.py`):

| Field | Type | Value written for a selected/excluded region |
|---|---|---|
| `base_addr` | u64 | region start VA |
| `region_size` | u64 | region size in bytes: the full span its `MEMORY_REGION` would record, FAILED pages included |
| `protection` | u8 | `Protection` bits as the region would have been stored |
| `region_type` | u8 | `RegionType` as the region would have been stored (e.g. `STACK` for a thread stack) |
| `path_len` + `mapped_path` | u16 + NUL-terminated, 8-byte padded | ELF-core / regioned-raw: the full **mapping name** when the region has one (maps path column or `NT_FILE` path, e.g. `[heap]`, `[anon:scudo:primary]`, `/system/lib64/libc.so`), else the module path, else empty. Minidump: the module path. `path_len = 0` for unnamed anonymous ranges |
| `name_source` | u8 at `+0x14` | **1.1:** `SourceMetadata` (`0x02`) for every importer-written entry; `Live` (`0x01`) is what memslicer writes for live captures; materialize keeps the source entry's value and marks the entries it adds from `MEMORY_REGION` headers `Synthesized` (`0x03`). Pre-1.1 files read as `Unspecified` (`0x00`) |

**`mapped_path` semantics.** `mapped_path` is `name or module_path or ""`. For file-backed mappings the name and the module path are the same string. For named anonymous mappings (`[anon:X]`, `[heap]`, `[stack]`, `[vdso]`, `/dev/ashmem/...`) it is the bracketed / pseudo-path name as the source listed it. Readers use these names for classification only when the trust rule below allows it; they are always shown in the VAS view.

`VAS_MAP` has **no "captured" flag**. A reader tells the two kinds apart by overlap with stored regions: an entry whose `[base_addr, base_addr + region_size)` overlaps a `MEMORY_REGION` block (`reader.collect_regions()` / region headers) was captured (bytes present). An entry that overlaps no `MEMORY_REGION` is layout-only, meaning its range was excluded by the selection and its bytes were not stored. `MslReader.collect_vas_map()` returns the raw entries. The MCP / REST VAS view (`vas_regions_result` in `app/tools_inspect.py`) derives a per-entry boolean `captured` this way and omits it when no region header is readable (encrypted without key, or no regions).

`materialize` (region-filtered rewrite of a `.msl`) always writes a fresh, complete `VAS_MAP` that replaces any source one. It contains the entries of the source's effective `VAS_MAP` (the last one in file order, segments included; VAS maps inside re-emitted source segments are dropped so the fresh map stays effective) (names and `name_source` included) plus an entry for every source `MEMORY_REGION` whose `base_addr` no source entry covers, kept or excluded, with the same field semantics (`mapped_path` = trusted mapping name, else module path; `name_source` = `Synthesized`). When the source's names are trusted, the copy's materialize segment still carries `region_names=1` so the fallback rule below keeps them trusted in the copy.

### Trust rule for mapping names

Files written before names were stored may have a `VAS_MAP` whose `mapped_path` is only a module path, so a reader must not classify by it blindly. `msl_classification_context(reader)` (`msl/import_preview.py`) returns `(source_format, names_index, live_named)` and applies one rule, shared by the import preview, the analysis-time view filter and materialize.

**MemDiver 1.1 migration — `NameSource` first, inference as fallback.** The per-entry `name_source` decides when it is set:

| `name_source` | Names trusted |
|---|---|
| `Live` (`0x01`) or `SourceMetadata` (`0x02`) | yes |
| `Synthesized` (`0x03`) | no |
| `Unspecified` (`0x00`) — every pre-1.1 file | fall back to the 1.0 inference below |

The 1.0 inference, applied only to `Unspecified` entries:

| File | Names trusted when |
|---|---|
| has an `IMPORT_PROVENANCE` block | its `note` has a segment with `region_names=1` (ELF-core / regioned-raw imports, and materialized copies of trusted sources) |
| no `IMPORT_PROVENANCE`, header `IMPORTED` flag clear (live memslicer capture) | a `VAS_MAP` block exists |
| no `IMPORT_PROVENANCE`, `IMPORTED` set | never |

When names are not trusted, classification is byte-identical to the stored-type rules. `live_named` (trusted and not `IMPORTED`) enables the alignment fold described above. The helper reads only the provenance and `VAS_MAP` payloads, never region payloads.

### Mapping-name classification

Selection categories are never stored in the file. They are derived from the stored `region_type` / protection (`classify` / `classify_stored` in `msl/region_select.py`) and then, when a trusted mapping name is known, refined by `classify_mapping_name(name)` (`msl/region_names.py`). The function returns a category **override** or `None` ("the name adds nothing"); a trailing `" (deleted)"` is stripped first. The stored `region_type` never changes, so alignment keys do not either.

**Precedence.** The name override wins, except that a `heap` name on a region stored as `SHARED_MEM` stays `shared`.

| Mapping names | Category |
|---|---|
| `[heap]`, `[heap:N]`; `[anon:X]` where X contains `malloc` or starts with `scudo:`, `jemalloc`, `GWP-ASan`, `bionic_alloc`, `partition_alloc` | `heap` |
| ART heap spaces: `[anon:dalvik-… space]` and `/dev/ashmem/dalvik-… space` (main / region / large-object / non-moving / alloc / rosalloc), except zygote space and bitmaps / maps / live / mark stacks; app image `dalvik-/data/app/…base.art` | `heap` |
| `[stack]`, `[stack:N]`; `[anon:X]` where X starts with `stack_and_tls:`, `thread signal stack`, `bionic TLS`, `thread stack` | `stack` |
| `dalvik-zygote space`; boot images `dalvik-/{system,system_ext,product,vendor,apex}/…`, `dalvik-/data/dalvik-cache/…`; other `dalvik-*` metadata (bitmaps, card table, mark / live stacks, LinearAlloc, indirect ref table, `jit-code-cache`, `data-code-cache`); `/memfd:jit-*` | `runtime` |
| `[anon:X]` where X starts with `cfi shadow`, `linker_alloc`, `System property context nodes` | `runtime` |
| kernel mappings `[vdso]`, `[vvar]`, `[vvar_vclock]`, `[vsyscall]`, `[vectors]`, `[sigpage]`, `[uprobes]` | `runtime` |
| `/dev/__properties__*`, GPU / other `/dev/*` devices, `/dmabuf*`, `anon_inode:*` | `runtime` |
| boot code `.art` / `.oat` / `.vdex` / `.odex` under `/system/`, `/system_ext/`, `/product/`, `/vendor/`, `/apex/`, `/data/dalvik-cache/`, `/data/misc/apexdata/com.android.art/dalvik-cache/`; ICU data `/system/usr/icu/*`, `/apex/com.android.i18n/etc/icu/*` | `runtime` |

Deliberately **without** an override (they keep the category of the stored type; in particular they are not `runtime`):

- `[anon:.bss]`, because app native globals live there;
- `/dev/binder*` (any `*binder*` device), `/dev/shm/*`, `/dev/zero`, non-dalvik `/dev/ashmem/*`, and non-JIT `/memfd:*`;
- app files (`/data/app/**`) and unknown `[anon:X]` labels.

The kernel and device rules are not Android-specific: `[vdso]`, `[vvar]` and device mappings also classify as `runtime` on Linux files whose names are trusted (new ELF-core / regioned-raw imports and live memslicer captures).

**Normative test vectors.** `tests/fixtures/region_name_vectors.json` lists Android, Linux and macOS mapping names with the expected MemDiver category (`memdiver_category`; `null` = no override) next to memslicer's category and stored region type. The file is shared byte-identical with memslicer; both implementations must agree with it.

### IMPORT_PROVENANCE `note` grammar

`IMPORT_PROVENANCE.note` is UTF-8 text made of **segments** joined by `"; "` (semicolon + space). The first segment is the human-readable base note. Each later segment is a machine-readable list of `key=value` fields joined by `";"` (no space):

```text
note        = base-note *( "; " field-list )        ; base-note may be empty, then the "; " before the first field-list is omitted
field-list  = field *( ";" field )
field       = key "=" value                          ; value contains no ";"
```

Base notes written by importers:

| Importer | Base note |
|---|---|
| raw | `Imported from <file name>` |
| ELF core | `Imported from ELF core <file name>` |
| minidump | `Imported from minidump <file name>` |
| regioned raw | `Imported from <bin name> with memory map <maps name>` |
| materialize | the source file's `IMPORT_PROVENANCE.note` (empty when the source has none, e.g. a live capture) |

**Mapping-names marker segment.** The ELF-core and regioned-raw importers append a `region_names=1` segment to their base note (`Imported from ELF core t.core; region_names=1`). It states that the `VAS_MAP` `mapped_path` values are full mapping names. `parse_provenance_note` reports it as `ProvenanceNoteFields.region_names` (`true` when **any** base-note segment has `region_names=1`; key constant `REGION_NAMES_KEY` in `msl/region_select.py`). Materialize writes `region_names=1` inside its own segment when the source's names were trusted.

**Selection segment** (`msl/region_select.py` `selection_provenance_note`). It is appended only when a selection was passed, and it is always the **last** segment:

| Key | Always | Value |
|---|---|---|
| `regions` | yes, first key | `all`, or the selected categories, sorted and comma-separated (`heap`, `stack`, `image_code`, `image_data`, `mapped_file`, `shared`, `unclassified`, `runtime`; the alias `image` is stored expanded as `image_code,image_data`). `runtime` was added later; a stored list naming the seven older categories therefore means "all but `runtime`" |
| `writable` | only when set | `1`: writable-only filter |
| `modules` | only when set | module globs joined by `\|` |
| `excluded_regions` | yes | number of source regions not written |
| `excluded_bytes` | yes | captured bytes of those regions |
| `fallback` | only on fallback | `all`: the selection would have kept 0 captured bytes, so every region was imported (`regions=all`, `excluded_*=0`) |

Readers locate it as the substring after the **last** `"; regions="` (or the whole note when it starts with `regions=`). `split_provenance_note` / `selection_from_provenance_note` / `RegionSelection.from_note` implement this. `from_note` reads `regions`, `writable` and `modules` and ignores the other keys.

**Materialize segment** (`msl/materialize.py` `_provenance_note`). It is written for every materialized copy, between the inherited source note and the selection segment:

| Key | Always | Value |
|---|---|---|
| `source_format` | yes | `msl` |
| `materialized` | yes | `1` |
| `dropped_key_hints` | yes | KEY_HINTs whose target region was excluded (not re-created) |
| `region_names` | when the source's names are trusted | `1`: the copy's `VAS_MAP` names stay trusted |
| `orig_eoc_hash` | when non-zero | lower-case hex of the source `END_OF_CAPTURE.file_hash` (64 hex digits), which ties the copy to the exact source file |

The block's `source_format` field keeps the **source's** value (e.g. `0x02` ELF core) so stored-region classification is unchanged. `source_format=msl` in the note is what marks the rewrite.

Examples written by the code, for a synthetic ELF core imported in full, with `--regions heap,stack`, with a selection that keeps nothing (fallback), and materialized from the full import with `--regions heap` (hash shortened):

```text
Imported from ELF core t.core; region_names=1
Imported from ELF core t.core; region_names=1; regions=heap,stack;excluded_regions=2;excluded_bytes=8192
Imported from ELF core t.core; region_names=1; regions=all;excluded_regions=0;excluded_bytes=0;fallback=all
Imported from ELF core t.core; region_names=1; source_format=msl;materialized=1;dropped_key_hints=0;region_names=1;orig_eoc_hash=02ec36e0…a55a4ea61; regions=heap;excluded_regions=2;excluded_bytes=8192
```

ELF cores written by MemDiver releases before mapping names were stored carry the same notes without `region_names=1`; their `VAS_MAP` names are not used for classification.

## POINTER_GRAPH extension segment (0x1003)

**Producer-defined Structural payload.** Spec 1.1 registers `0x1003` Pointer Graph as a Structural block whose payload is producer-defined and which MAY appear **only in extension segments** (§4.3, §4.6). The payload below is MemDiver's.

The POINTER_GRAPH block records analysis-derived pointer relationships (data references, call edges, module imports) discovered after capture. Because these relationships are derived rather than captured, the block is never part of the capture segment: MemDiver writes it as an **extension segment** chained from the EoC block and terminated by an End-of-Extension block.

### File layout with the segment

```
Unencrypted MSL:
  [ File Header | Block 0 | … | EoC | POINTER_GRAPH | End-of-Extension (0x0FFE) ]
                                   ↑        ↑ prev_hash = H(EoC)       ↑ segment_hash, block_count = 2
                            capture ends     extension segment (chain continues unbroken)

Encrypted MSL (AEAD §10):
  [ Header 128B | KEM ct | AEAD( Block 0 … EoC | POINTER_GRAPH | End-of-Extension ) | Tag 16B ]
                                                      ↑
                              segment lives INSIDE the ciphertext, before the tag; prev_hash zero
```

For encrypted files the segment sits **inside** the AEAD envelope, written before the tag is finalized, never after it: the tag at EOF authenticates the whole stream, nothing can be appended to a sealed container, and pointer-graph metadata is never exposed in plaintext. The unified rule is: **the pointer graph is a block of a verified extension segment in the (possibly-decrypted) block stream after EoC.**

### Reader/writer rules

- The block uses the standard 80-byte block header (`BLOCK_MAGIC`, `block_type = 0x1003`). Its `prev_hash` is the hash of the EoC block (chain continuity, spec §4.6) — or **32 zero bytes inside an encrypted container**, like every other block there.
- The segment is closed by an End-of-Extension block (`0x0FFE`) with `segment_hash` over the pointer-graph block bytes, `block_count = 2`, and `producer = memdiver/<version>`.
- `MslReader._iter_raw_blocks` stops after yielding the `END_OF_CAPTURE` block. Existing collectors (regions, key hints, etc.) never see segment blocks — fully backward compatible.
- `verify_chain` continues past EoC: it verifies the segment's chain continuity (unencrypted files), `segment_hash` and `block_count`; a failing or unterminated segment is trailing data and `collect_pointer_graphs()` does not return a graph from it.
- Segment-aware readers fetch the graph via `MslReader.collect_pointer_graphs()`, which walks the verified extension segments.
- A writer appending the segment never touches the header or the capture segment, and refuses to append when unverified trailing data already follows the last verified segment.

**MemDiver 1.1 migration.** Files written by the 1.0 writer carry the pointer graph as an unterminated "appendix" (zero `prev_hash`, no End-of-Extension). Under the 1.1 rules that is trailing data: it is not presented as verified and `verify_chain` reports it as such. Re-exporting from `ProjectDB` produces a proper segment.

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

Writer encoder lives in `msl/writer.py:_build_pointer_graph_block`; reader decoder is `msl/decoders_ext.py:decode_pointer_graph`. The integrity trailer is independent of the container's chain and of the segment's `segment_hash` (it is kept so a graph payload extracted on its own can still be checked); verify it with `decoders_ext.verify_pointer_graph_integrity(graph, raw_payload)`.

### Storage relationship

Pointer relationships are stored independently in MemDiver's `ProjectDB` (DuckDB) so users can query them without ever exporting an MSL file. MSL export is one of several sinks (alongside Vol3 / YARA / JSON via `architect/`); the user opts in to inclusion at write time by calling `MslWriter.add_pointer_graph(nodes, edges)`. Future revisions of this section will document the `ProjectDB` schema (`pointer_graph_nodes`, `pointer_graph_edges` tables) once that integration lands.
