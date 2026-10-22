# MCP tool reference

MemDiver exposes **48 tools** to MCP-speaking agents. All tools are thin wrappers around the same pure functions used internally by the engine, so responses are identical whether you invoke them over MCP, through the CLI, or through the FastAPI backend.

```{admonition} Analysis-time region filter (`region_filter`)
:class: note

`consensus`, `aligned_window`, `consensus_regions`, `analyze_candidates`, `n_sweep`, `experiment`, `read_hex` and `read_hex_raw` take an optional `region_filter`: a comma list of region categories (e.g. `"heap,stack"`; categories as for `import_raw_dump`'s `region_types`), or `"all"` for no filter. It applies to `.msl` inputs only and is a non-destructive **view filter**: each dump is read as if only the selected regions existed, so offsets are filtered-view offsets and the result records `region_filter`. If you leave it out, the session's region filter applies (none by default; set it with `set_region_filter`, read it with `get_region_filter`). An explicit value, `"all"` included, always takes precedence over the session's filter.

The downstream stages `search_reduce`, `brute_force`, `auto_floor` and `emit_plugin` also take `region_filter`. Left out, they reuse the filter the upstream stage recorded in its artifact (`consensus.json` / `candidates.json` / `hits.json`), so offsets stay consistent across the chain. Pass a value only to override that filter, or `"all"` to clear it. `aligned_window` / `consensus_regions` always use the filter a built consensus recorded. An unknown category name is rejected as invalid input.
```

```{admonition} Memory budget (`force_memory`)
:class: note

`analyze_library`, `analyze_candidates`, `consensus`, `aligned_window`, `consensus_regions`, `export_pattern` and `experiment` build a consensus over every input dump, and that build is checked against a memory budget first (a safety fraction of the host's available memory, capped by `MEMDIVER_MEMORY_BUDGET_MB` when set). When the estimated peak exceeds it, the tool does no work and returns a structured error instead:

    {"error": "<estimate vs budget and suggestions>", "code": "memory_budget_exceeded",
     "category": "PRECONDITION", "estimate_bytes": <int>, "budget_bytes": <int>,
     "details": {"estimate_bytes": ..., "budget_bytes": ..., "operation": ..., "breakdown": ..., "source": ...}}

Every one of these tools takes `force_memory: bool = False`. Fewer or smaller dumps (or a `region_filter`) are the safe fix; re-calling with `force_memory=true` runs the build anyway (a warning is logged). Any other tool error that carries `details` now includes them under `details` too.
```

## Dataset inspection

| Tool | Purpose |
|---|---|
| `scan_dataset` | Enumerate libraries + phases under a dataset root. |
| `list_phases` | List canonical phases for a specific library directory. |
| `list_protocols` | Enumerate supported protocols (TLS12, TLS13, SSH2, …). |
| `set_region_filter` | Set the session's default `region_filter` (e.g. `"heap,stack"`); `"all"` or omitting it clears it. Returns the normalised `region_filter` note (`null` = every region) and `active`. An unknown category is rejected as invalid input. |
| `get_region_filter` | Return the session's current `region_filter` and `active`. |

## Analysis

| Tool | Purpose |
|---|---|
| `analyze_library` | Run selected algorithms against a library run set. |

## Dump inspection

| Tool | Purpose |
|---|---|
| `read_hex` | Hex-dump a range of bytes. |
| `read_hex_raw` | Read raw bytes from a dump file, returned base64-encoded. |
| `get_entropy` | Shannon entropy profile with configurable window / threshold. |
| `analyze_region` | Investigate one offset: byte value, local entropy band, strings. |
| `extract_strings` | ASCII/UTF-8 string extraction. |
| `search_bytes` | Search a dump for every occurrence of a byte pattern. |
| `detect_format` | Detect the binary format at an offset in a dump's raw container. |
| `get_session_info` | MSL session metadata (PID, module list, connection table). |
| `get_cross_references` | Cross-references between MSL blocks. |
| `identify_structure` | Best-match structure overlay at an offset. |

## MSL structure

| Tool | Purpose |
|---|---|
| `vas_regions` | List the per-dump VAS region layout from an MSL file. |
| `resolve_va` | Translate a virtual address to file and VAS offsets for an MSL dump. |
| `get_page_states` | Surface the MSL three-state page model (CAPTURED/FAILED/UNMAPPED). |
| `get_processes` | List processes captured in an MSL file (pid/ppid/uid/exe/cmdline). |
| `get_modules` | List loaded modules in an MSL file (path/base_addr/size/version). |
| `get_handles` | List open handles/fds in an MSL file (pid/fd/type/path). |
| `get_connections` | List network connections in an MSL file (pid/family/protocol/addrs). |
| `get_module_index` | List MODULE_LIST_INDEX entries in an MSL file (uuid/base/size/path). |
| `get_import_provenance` | IMPORT_PROVENANCE records with the note parsed (kept/excluded regions, materialized copy + original EoC hash, `region_names`: the VAS map stores trusted mapping names); empty for non-`.msl`. |
| `get_blocks` | List all blocks in an MSL file grouped by category. |

## Format conversion

| Tool | Purpose |
|---|---|
| `import_raw_dump` | Convert a dump (raw, ELF core, minidump, `.msl`) → `.msl`. Optional `region_types` / `exclude_region_types` (e.g. `"heap,stack"`) restrict the regions imported (default: all). Categories: `heap`, `stack`, `image_code`, `image_data`, `mapped_file`, `shared`, `unclassified`, `runtime` (alias `image`). `runtime` holds regions classified by mapping name as runtime / system memory (Android zygote / boot-image ART spaces, ART metadata, JIT caches; kernel and device maps such as `[vdso]`, `[vvar]`, `/dev/*` on Android and Linux). It is not in the interactive default (`heap`, `stack`, `unclassified`), so name it or pass `"all"` to keep it; a list of the seven older categories means "all but `runtime`". `materialize=true` writes a filtered copy of a `.msl` input instead of a verbatim one. Encrypted `.msl`: `key_file` / `passphrase` / `kem_key_file` supply key material (required for `materialize`); the filtered copy is re-encrypted with the same key wrapping and a fresh nonce, unless `decrypt_output=true` opts into a plaintext copy (result carries a warning). Raw dumps: `maps_path` names a `/proc/<pid>/maps`-style memory map (default: a `.maps` sidecar with the same name) that splits the dump into real regions; a map that does not match the dump size is ignored with a warning. |
| `preview_import` | Metadata-only preview of an import: regions with their category, per-category counts/bytes, and what a `region_types` selection would keep/exclude. Writes nothing. Accepts `key_file` / `passphrase` / `kem_key_file` so an encrypted `.msl` lists its regions; the result has `encrypted` / `decrypted` flags. `layout` is `native`, `maps` (raw dump + memory map, `maps_path` or an auto-detected sidecar) or `none` (raw dump: one unclassified region). `platform` is the target platform (`android`, `linux`, `windows`, …; `null` when unknown) and `platform_source` how it was determined (`mapping_names`: Android markers in the mapping names; `header`: the `.msl` header `os_type`; `format`: implied by the source format). Each entry of `regions` carries its mapping `name` (`null` when the source has none or an older `.msl` does not mark its names as trusted). `runtime_count` / `runtime_bytes` total the `runtime` regions, which the default selection drops; a `notes` entry says so when any exist. |
| `export_pattern` | Auto-detect a volatile region and export a YARA/JSON/Vol3 pattern. |
| `manual_export_pattern` | Export a YARA/JSON/Vol3 pattern from a KNOWN offset + length. |
| `export_keylog` | Emit a Wireshark-loadable NSS key log from recovered TLS secrets. |

## Consensus

| Tool | Purpose |
|---|---|
| `consensus` | Build a per-byte consensus variance vector; writes `variance.npy`. |
| `aligned_window` | Read ONE window in EVERY dump at the address the consensus aligned. |
| `consensus_regions` | List EVERY occurrence of a consensus class, paginated and jumpable. |

## Known secret &amp; detectors

| Tool | Purpose |
|---|---|
| `locate_key` | Locate a secret you ALREADY HOLD across N dumps — honest three-valued (found / absent / nothing searched). See [Locating a known key](locate_key.md). |
| `locate_field_across_pairs` | Search N dumps for a handshake field, each from ITS OWN capture. |
| `export_key_pattern` | Turn a KNOWN secret's location into a scanning signature. |
| `scan_yara_rule` | Compile ONE YARA rule set and scan N dumps with it. |
| `verify_vol3_plugin` | RUN a MemDiver-emitted Volatility3 plugin over N dumps. |
| `score_detector_matches` | Score detector firings against the key's known-true intervals. |

## Pipeline stages

| Tool | Purpose |
|---|---|
| `analyze_candidates` | Rank candidate regions across N dumps — NO oracle, NO capture needed. |
| `search_reduce` | Variance + alignment + entropy candidate reducer. Returns the ranked regions inline (`regions`, each with `rank`, `score` and its `score_components`), capped at `max_returned` and flagged with `regions_truncated`; `candidates_path` still holds them all. |
| `brute_force` | Iterate candidates through a decryption oracle. |
| `n_sweep` | N-curve sweep with convergence reporting. |
| `auto_floor` | Automated oracle-arbitrated variance-floor selection → verdict. |
| `emit_plugin` | Synthesize a Volatility3 plugin from a verified hit. |

## Verification &amp; experiments

| Tool | Purpose |
|---|---|
| `inspect_pcap` | Summarise the TLS sessions in a capture (the pcap arm/validate step). |
| `verify` | Verify a candidate key read at an offset decrypts a known ciphertext. |
| `experiment` | Run the full spawn→dump→consensus→verify→emit experiment. |

See each tool's input schema via the MCP client's tool picker, or read the implementations in `mcp_server/server.py` (registrations) and `mcp_server/tools.py` / `mcp_server/tools_inspect.py` / `mcp_server/tools_pipeline.py` / `mcp_server/tools_xref.py`.
