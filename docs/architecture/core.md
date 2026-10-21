# core/

Dependency-light data layer (stdlib plus numpy, which `entropy` and `variance` use for vectorized math). Every other subsystem imports `core.*`.

Key modules:

- `models` — dataclasses: `CryptoSecret`, `KeyOccurrence`, `DumpFile`, `RunDirectory`, `ComparisonRegion`.
- `discovery` — `RunDiscovery` walks a dataset and materializes run-directory records; `DatasetScanner` summarizes a dataset root.
- `dataset_metadata` — parses a run's `meta.json` into `DatasetMeta` (`load_run_meta` returns `None` for legacy runs without one).
- `dump_io` — `DumpReader` with mmap-backed page iteration.
- `dump_source` — `open_dump` factory with `ViewMode` (`raw`, `vas`, `va`), the `DumpSource` protocol and the priority-ordered `register_dump_source` registry; concrete gcore / gdb_raw / lldb_raw sources live in `dump_sources/`.
- `needle` — `parse_needle` turns typed search input (hex, UTF-8 text, UTF-16LE, base64, or a u32/u64 integer such as a pointer) into the bytes to search for.
- `entropy` — Shannon entropy, sliding-window profile, incremental O(1) updates.
- `variance` — chunked two-pass + online Welford estimator; `classify_variance` with the 4-class threshold ladder (`INVARIANT`, `STRUCTURAL`, `POINTER`, `KEY_CANDIDATE`).
- `region_align` — ASLR-invariant region alignment, `AlignedSlice`, `align_dumps`.
- `phase_normalizer` — canonicalizes per-library phase naming differences.
- `kdf_base` + `kdf` + `kdf_registry` + `kdf_tls` + `kdf_ssh` — auto-discovered KDF plugin system (`BaseKDF` subclasses in `core/kdf_*.py`; TLS 1.2 PRF, TLS 1.3 HKDF, SSH2 KDF; add your own).
- `plugin_discovery` — shared subclass-scanning and entry-point loading used by the algorithm, KDF, format, dump-source, pipeline-stage and oracle registries.
- `keylog` + `keylog_templates` — CSV/NSS keylog parsing with per-library templates.
- `binary_formats/` — Kaitai Struct adapters for ELF, Mach-O, PE, and a compiled-parser cache; the `FormatDescriptor` registry (`format_descriptor.py`); mmap-only ELF-core and Windows minidump readers.
- `artifact_util` — `register_artifact` / `sha256_streamed` shared by the TaskManager worker runners.
- `process_guard` — parent-death watchdog (`install_parent_death_watchdog`, `start_guarded_sync_manager`) so spawned worker/Manager processes do not outlive a killed server.
