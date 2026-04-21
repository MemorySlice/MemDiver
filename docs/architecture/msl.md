# msl/

Memory Slice (`.msl`) format — a hand-rolled, mmap-backed, struct-based container for process-memory snapshots. See [](../file_formats/msl_v1_1_0.md) for the on-disk spec.

- `MslReader` — mmap, endian-aware, encrypted-flag rejection, zstd/lz4 block decompression, BLAKE3 prev-hash chain integrity, cached per-block collectors.
- `MslWriter` — MemDiver is a first-class writer; `END_OF_CAPTURE.file_hash` finalized via streaming digest.
- `MslImporter` — converts legacy `.dump` files to `.msl`, maps `CryptoSecret` → `MslKeyType` / `MslProtocol`.
- Block types: `MEMORY_REGION`, `MODULE_ENTRY`, `KEY_HINT`, `PROCESS_IDENTITY`, `VAS_MAP`, `PROCESS_TABLE`, `CONNECTION_TABLE`, `HANDLE_TABLE`, `RELATED_DUMP`, `IMPORT_PROVENANCE`, `END_OF_CAPTURE`, plus a `GenericBlock` fallback for forward compatibility.

:::{note}
Kaitai Struct is used only for foreign binaries (ELF, PE, Mach-O) under `core/binary_formats/kaitai_compiled/`. The `.msl` format itself is hand-rolled.
:::
