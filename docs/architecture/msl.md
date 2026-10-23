# msl/

Memory Slice (`.msl`) format — a hand-rolled, mmap-backed, struct-based container for process-memory snapshots. See [](../file_formats/msl_v1_1_0.md) for the on-disk spec (Memory Slice Specification v1.1.0, binary format 1.1; the superseded 1.0.0 mirror is [](../file_formats/msl_v1_0_0.md)).

- `MslReader` — mmap, endian-aware, decrypts encrypted containers when key material is supplied (`tag_status` reports the outcome), zstd/lz4 block decompression, BLAKE3 prev-hash chain integrity, cached per-block collectors.
- `MslWriter` — MemDiver is a first-class writer; `END_OF_CAPTURE.file_hash` finalized via streaming digest.
- `importer` — `import_dump` converts foreign dumps (ELF core, Windows minidump, legacy raw `.dump`; existing `.msl` is passed through) to `.msl`, mapping `CryptoSecret` → `MslKeyType` / `MslProtocol`.
- Block types: `MEMORY_REGION`, `MODULE_ENTRY`, `KEY_HINT`, `PROCESS_IDENTITY`, `VAS_MAP`, `PROCESS_TABLE`, `CONNECTION_TABLE`, `HANDLE_TABLE`, `RELATED_DUMP`, `IMPORT_PROVENANCE`, `END_OF_CAPTURE`, plus a `MslGenericBlock` fallback for forward compatibility.

:::{note}
Kaitai Struct is used only for foreign binaries (ELF, PE, Mach-O) under `core/binary_formats/kaitai_compiled/`. The `.msl` format itself is hand-rolled.
:::
