# core/

Stdlib-only data layer. Every other subsystem imports `core.*` to stay dependency-light.

Key modules:

- `models` — dataclasses: `CryptoSecret`, `KeyOccurrence`, `DumpFile`, `RunDirectory`, `ComparisonRegion`.
- `discovery` — `RunDiscovery` walks a dataset and materializes run-directory records.
- `dump_io` — `DumpReader` with mmap-backed page iteration.
- `dump_source` — `open_dump` factory with `ViewMode` (`raw` vs `vas`).
- `entropy` — Shannon entropy, sliding-window profile, incremental O(1) updates.
- `variance` — chunked two-pass + online Welford estimator; `classify_variance` with the 4-class threshold ladder (`INVARIANT`, `STRUCTURAL`, `POINTER`, `KEY_CANDIDATE`).
- `region_align` — ASLR-invariant region alignment, `AlignedSlice`, `align_dumps`.
- `phase_normalizer` — canonicalizes per-library phase naming differences.
- `kdf` + `kdf_registry` + `kdf_tls` + `kdf_ssh` — auto-discovered KDF plugin system (TLS 1.2 PRF, TLS 1.3 HKDF, SSH2 KDF; add your own).
- `keylog` + `keylog_templates` — CSV/NSS keylog parsing with per-library templates.
- `binary_formats/` — Kaitai Struct adapters for ELF, Mach-O, PE, and a compiled-parser cache.
