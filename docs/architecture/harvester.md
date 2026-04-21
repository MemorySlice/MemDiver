# harvester/

Data ingestion layer. Maps on-disk dataset trees into `RunDirectory` records the engine can consume.

- `DumpIngestor` — wraps `core.discovery.DatasetScanner` + `RunDiscovery` + `DumpReader`. Accepts datasets laid out as `TLS{version}/{scenario}/{library}/{run_dir}/`.
- `SidecarParser` — reads `.json` (dict root) and `.meta` (key=value) sidecars. Filenames starting with `keylog` or `timing` are skipped (they are parsed by dedicated readers).
- `MetadataStore` — in-memory record list; materializes an eager `polars.DataFrame` on demand (no `LazyFrame`) and flattens scalar sidecar fields into `meta_*` columns.

Filename conventions recognized:

- Dump: `^(\d{8}_\d{6}_\d+)_(pre|post)_(.+)\.(dump|msl)$` — timestamp, phase prefix, phase name.
- Run dir: `^(.+?)_run_(\d+)_(\d+)$` — library, protocol version, run number.
- Keylog: `keylog.csv` (configurable via `--keylog-filename`).

`PhaseNormalizer` canonicalizes phase names across libraries with different conventions.
