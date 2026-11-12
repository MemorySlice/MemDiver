# The .msl Layer

A Memory Slice (`.msl`) is MemDiver's container for a live-process capture: regions with per-page states, a module list, thread contexts, key hints and a hash chain. This page describes how stock Volatility 3 reads one, so that `vol -f capture.msl <plugin>` works with any plugin. The format itself is specified in [MSL v1.1.0](../file_formats/msl_v1_1_0.md).

## Why a layer

A synthesized plugin is trained on `.msl` slices and then run on full images; the in-repo samples are `.msl` files. For both, Volatility must see the capture as a memory layer, with MemDiver's offsets, so a hit at one offset means the same byte in both tools.

## Stacking

```bash
vol -p "$(memdiver vol3 plugin-dir)" -f capture.msl regexscan.RegExScan --pattern <hex-or-regex>
```

`MslStacker` (stacking order 10) recognises the 8-byte `MEMSLICE` magic and stacks three layers on the file:

| Layer | Content |
|---|---|
| `FileLayer` | the `.msl` container on disk |
| `MslVasLayer` | the flat "vas" stream: the CAPTURED page runs concatenated in region base-address order, followed by one zero region that backs NotResident pages. Offsets equal MemDiver's own `view="vas"` offsets byte for byte |
| `MslLayer` | the captured process's virtual address space: one segment per CAPTURED run mapped at its virtual address, NotResident pages mapped onto the zero region |

### Page-state semantics

| State | Reads | Scans |
|---|---|---|
| Captured | the bytes | found |
| NotResident | zeros | found, in zeros |
| Failed, Unmapped | `InvalidAddressException` | never reported: a scan cannot find a hit in bytes the capture did not hold |

The layer's metadata carries `msl`, `msl_os`, `msl_arch`, `architecture` and `pid`, and deliberately **no `os` key**: a process slice is not a kernel image, so the Windows stacker and the OS symbol automagic must leave it alone.

### Known limitation

Volatility's scanners do not carry their overlap across a segment whose stream offsets are not contiguous with the previous one. A captured run and the NotResident pages that follow it are adjacent in virtual address but not in the stream, so a scan misses a match that starts in captured bytes and ends in NotResident zeros. Reads across that edge are correct. Abutting CAPTURED runs that are contiguous in the stream are joined and scan as one range. This limit is documented and pinned by a test.

## Encrypted captures

An encrypted container opens only with key material, taken from the layer options `key_file` and `kem_key_file`, or the environment: `MEMDIVER_MSL_KEY_FILE`, `MEMDIVER_MSL_KEM_KEY_FILE` and `MEMDIVER_MSL_PASSPHRASE`. Nothing is read unless the capture is actually encrypted. A key file path from the environment is written into the layer configuration only after it opened the capture, and the passphrase is read from the environment only, so `--save-config` never records a secret. A locked container fails with one log line that names the remedy.

```bash
MEMDIVER_MSL_KEY_FILE=samples/gocryptfs_aes_encrypted.msl.key \
    vol -p "$(memdiver vol3 plugin-dir);samples/plugins" -f samples/gocryptfs_aes_encrypted.msl \
    memdiver_gocryptfs.MemDiverSynthGocryptfs --oracle-sample samples/gocryptfs_aes.oracle
```

The demo file uses zstd-compressed regions and AES-256-GCM container encryption (specification section 10, raw key). Claim `C-MSL2` checks that it yields the same rows as the plaintext slice and that without the key no row is proven.

## Without MemDiver: the slim reader

Installing MemDiver into Volatility's Python is the preferred setup. When `import memdiver` fails, `vol3plugins/msl_slim.py` (standard library only, no Volatility import) opens the capture behind the same two layers, with the same layer names, stream offsets, virtual addresses and unreadable pages. One INFO line per capture names the reader (`MSL reader: msl_slim`).

| Slim reader | |
|---|---|
| Supports | plaintext, uncompressed, little-endian containers, format major version 1; all four page states; process identity; VAS map; continuation blocks; module entries and index, thread contexts, key hints, import provenance, end-of-capture; the hash chain and extension segments (`hashlib` for SHA-256 and SHA-512/256) |
| Refuses, with `pip install memdiver` | encrypted containers and zstd or lz4 compressed regions (the specification has no stdlib-decodable codec); BLAKE3 chains (unless a `blake3` module is available) |
| Does not do | integrity verification at stack time (the same as the MemDiver layer path) |

Evidence of equivalence: 95 captures and 10,512 regions with identical structure, and 1.78 GB sampled with identical SHA-256, against MemDiver's reader; 123 tests including 300 random corruptions; JSON output of `msl.info` byte-identical between an environment with MemDiver and one without, on 6 captures. Under a bare Volatility the in-repo gocryptfs sample still gives `Scope = msl:65219`.

`--parallelism processes` needs MemDiver importable in the workers.

## The msl.* plugins

| Plugin | Purpose |
|---|---|
| `msl.info` | process identity, OS, architecture, region and page-state totals, integrity |
| `msl.vasmap` | region table |
| `msl.pagemap` | page-state runs per region |
| `msl.modules` | module list with base, size, path and disk hash |
| `msl.keyhints` | key hints recorded by the capturing tool, optionally dumped |
| `msl.threads` | thread state, program counter, stack pointer, frame pointer, registers |
| `msl.verify` | per-block hash-chain check and a verdict (`valid`, `tampered`, `not verified`) |

Columns and options are in [Usage](USAGE.md#the-msl-plugins).

**Parity evidence.** Seven plugins by eleven files by three Volatility trees all exit 0, and 2.27.0 output equals 2.28.2 output on all 77 outputs; under the bare Volatility the table plugins give rows identical to the stock one. Claim `C-MSL4` compares the plugins' rows with what MemDiver's own reader decodes.

**Tamper demo.** One byte of the first in-memory copy of the gocryptfs key is flipped (offset 778,208, xor 0x01). `msl.info` then reports `Integrity BROKEN`; `msl.verify` ends in `tampered` and names the link that broke: the VAS_MAP block that follows MEMORY_REGION block 13, plus the end-of-capture file hash. The synthesized plugin prints that copy as `rejected` while the intact copy stays `oracle:gocryptfs-gcm`.

Limits: the in-repo samples use the default BLAKE3 chain, so the tamper demo's `msl.verify` verdict needs MemDiver or the `blake3` package; on a bare Volatility it says `not verified`. No real `KEY_HINT` data exists in the corpus, so `msl.keyhints` is tested on constructed captures only. On a bare Volatility an encrypted file logs a misleading "primary layer is not an MSL capture layer" line next to the install hint.
