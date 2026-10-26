# MCP tool reference

MemDiver exposes **120 tools** (plus 8 prompts and 4 resources, below) to MCP-speaking agents. All tools are thin wrappers around the same pure functions used internally by the engine, so responses are identical whether you invoke them over MCP, through the CLI, or through the FastAPI backend.

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

```{admonition} Heap awareness (`allocator`, `heap_policy`)
:class: note

`consensus`, `aligned_window`, `consensus_regions`, `analyze_candidates` and `locate_key` take `allocator: str = "auto"`: the heap allocator used to label each byte's heap role (`auto` detects it; `ptmalloc2`, `dlmalloc`, `scudo`, `mallocng`, `jemalloc` and `generic` force one; `off` turns heap analysis off). This is non-destructive. `consensus` reports the result under `heap` (and writes `heap_roles.npz` beside `variance.npy`), `aligned_window` returns `heap_roles`, and each `locate_key` hit gets a `heap` entry naming its chunk. A hit in a `free`, `cached` or `quarantined` chunk is a residual copy.

`analyze_candidates` and `search_reduce` also take `heap_policy: str = "annotate"`:

- `"annotate"` (default) is non-destructive. Each region gets a `heap` block (`chunk`, `residual`, `role_counts`), and the ranking stays the same.
- `"mask"` removes allocator metadata (chunk headers, free-list links) from the candidates before they are reduced. The number of bytes removed is in `stages.heap_masked`. It fails with a PRECONDITION error when no heap annotation is available.
- `"off"` turns heap analysis off.

`search_reduce` reads the heap roles from the `heap_roles.npz` that `consensus` wrote beside the variance file.
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

## Heap analysis

Allocator-aware heap parsing for ptmalloc2 (glibc), dlmalloc, scudo (Android), mallocng (musl), jemalloc (partial: slab level only) and a `generic` heuristic fallback. Every tool takes `allocator` (`"auto"` detects), works on `.msl` (with key material when encrypted) and raw dumps, and `base_va` places a flat raw dump without a `.maps` sidecar. `summary`/`chunks`/`chunk_at`/`free_lists`/`roles` also take `regions` (parse only these mappings) and `max_chunks` (walk cap). Bad input (unknown allocator/state/view, a VA window together with an offset window) returns the structured `{"error", ...}` body.

| Tool | Purpose |
|---|---|
| `heap_detect` | Rank allocator candidates with their evidence and the detected platform. Start here. |
| `heap_summary` | Whole-heap overview: regions, chunk counts/bytes by state, size histogram, bytes per role (`chunk_header`, `user_data`, `free_link`, `free_data`, `allocator_meta`, `top`, `slack`), coverage, diagnostics. |
| `heap_chunks` | One page of the chunk table, filtered by `state`, `min_size`/`max_size` and either a `va_start`/`va_end` or an `offset`/`length` window in `view` (`vas`/`raw`/`va`); rows carry `view_offset`. |
| `heap_chunk_at` | The chunk containing a `va` (or `offset` in `view`), the role of that byte, offsets in chunk/user data and the neighbouring chunks. |
| `heap_free_lists` | Walked free lists (tcache, fastbins, …) optionally of one `kind`, with `cycle` and `corrupt` flags. |
| `heap_roles` | Byte-role runs of an `offset`/`length` window in `view` (`vas`/`raw`/`va`; `length` max 1 MiB): `runs` of `{offset, length, role}` in view offsets (sorted, non-overlapping, coalesced; bytes in no chunk omitted), `chunk_starts` in the window, and the allocator's `partial`/`heuristic` flags. |

## Case data lake

Tabular results live as Parquet tables in a case directory, queryable with read-only SQL, with a versioned annotation record beside them. The schema is also served as the MCP resource `memdiver://case/{case_dir}/schema` (URL-encode the directory).

| Tool | Purpose |
|---|---|
| `case_init` | Create (or re-open) a case; a bare name means `~/.memdiver/cases/<name>`. |
| `case_status` | Manifest, tables (runs, row counts) and annotation captures. |
| `case_schema` | Columns, types, location mappings, runs and rows per table. |
| `case_query` | ONE read-only SELECT (DuckDB SQL), `?` bindings via `params`, rows capped at `limit` (default 200). |
| `case_export` | Export a dump (`.mdview` view or `.msl`) into case tables: view regions, MSL regions, page states, heap chunks (`what`, default `auto`; heap skipped when no allocator is found). |
| `keyfinders_list` | The key finders (structure-based key recognisers) with the `params` each reads. |
| `keyfinders_scan` | Scan the captured bytes of a dump (`.msl`, `.mdview`, raw) with key finders (default `aes_schedule`); rows carry `addr`+`space`+`location`, heap/region context, `coverage`, `truncated` and `candidates` (verify/brute_force input); `case_dir` files the `key_hits` table and `key_hit` annotations. |
| `yara_check` | Compile a YARA rule without scanning: `valid`, `rule_names`, and `errors: [{line, message}]` for a rule that does not compile (an answer, not an error). |
| `yara_scan_dump` | Scan the captured bytes of one dump (`.msl`, `.mdview`, raw) with a YARA rule, optionally a `view`/`offset`/`length` window; rows carry `addr` + `space` + `va`, `coverage` and `truncated` qualify them. Never reads across a capture gap. |
| `yara_rule_list` | List stored YARA rules of the per-user library and, with `case_dir`, the case; each row has `scope`, `version`, `compiles`, `modified_externally`, and `shadows` for a case rule hiding a library one; an unreadable rule is a row with `error`, a missing `case_dir` sets `case_error` and keeps the library rows. |
| `yara_rule_get` | One stored YARA rule with its source; `scope` is `library`, `case` or `auto` (default: the case, when `case_dir` is given, wins over the library). |
| `yara_rule_put` | Store a YARA rule by `name` in `scope` (`library` or `case` + `case_dir`; omitted = `case` when `case_dir` is given, else `library`); compile-checked, a non-compiling draft is saved and flagged. The previous version goes to history. `yara_check` / `yara_scan_dump` then accept `rule_name` (+ `case_dir`) instead of `rule_source`. |
| `yara_rule_delete` | Remove a stored YARA rule from exactly the named scope (same default as put; not found if it lives only in the other scope); its last source is archived to history. |
| `detector_fixtures_run` | Run a detector's fixtures (positive controls + decoys): verdict `pass` / `fail` / `indeterminate` (no fixtures is `indeterminate`, never a pass). `artifact_kind` `keyfinder` (finder name; `aes_schedule` ships synthetic AES-schedule fixtures) or `yara` (rule source); `case_dir` adds stored fixtures and stores `last_verdict`. |
| `detector_fixtures_add` | Store a fixture in a case: finder / YARA rule name, a sample (`hex`, `base64` or a wholly captured `dump_path` range) and `expect` (`matches` with sample-relative offsets, or `no_match` for a decoy). |
| `detector_fixtures_list` | Bundled and stored detector fixtures with their `last_verdict`. |
| `detector_fixtures_remove` | Retire a stored fixture (archived under `history/`). |
| `strings_table` | The printable strings of the captured bytes of a dump, one row each (`ascii`/`utf-8`/`utf16le`); rows carry `addr`+`space`+`location`, `encoding`, `value`, `iocs` badges and `region`; a string never crosses a capture gap; `truncated`/`coverage` always present; `case_dir` files the `strings` table (then `vol3_query` `saved="strings_iocs"`). |
| `context_at` | Everything containing a `location` (table rows and current annotations, outermost first), with read coverage when `dump_path` is given. |

## Memory images

Full-image views of a memory image (LiME, ELF core, ...) via Volatility 3 (`pip install "memdiver[image]"`). A view is a small `.mdview` descriptor file that opens like any dump. The MCP server has no job queue, so slow steps (image hashing, pakunoda) block the call; the REST API runs them as tasks.

| Tool | Purpose |
|---|---|
| `image_probe` | Size, physical layer chain, versions and cached-profile status; never hashes the image or runs pakunoda. `banners=true` also scans for Linux banners. |
| `image_profile` | Resolve the kernel profile (ISF): explicit, cache, pakunoda, vol3 symbol dirs. |
| `image_open_view` | Write a `.mdview` for a `physical`, `kernel` or `process` (needs `pid`) view. |
| `image_processes` | `pslist` of a kernel or process view (pid, ppid, comm, uid, has_mm, `kernel_va` Location); zero tasks is an error. |
| `image_extract_process` | Extract a process view into an `.msl` file. |
| `vol3_plugins` | Bundled Volatility 3 plugins of an OS family. |
| `vol3_describe` | A plugin's user requirements (bundled name, or `source` text). |
| `vol3_run` | Run a plugin over a `.mdview` inline (blocks; no TaskManager in the stdio process); `case_dir` registers the table `vol3__<os>_<plugin>`. `limit`, `timeout_s`, `max_rows`, `column_map`. `source` plugins run **unsandboxed in-process** (SHA-256 logged). |
| `vol3_query` | Read-only `sql` or a `saved` query over a case; neither lists the saved queries. |
| `vol3_annotate` | One `plugin_row` annotation per row of a registered run's location column. |
| `vol3_scaffold` | Source text of a new plugin (kernel module, optional `pid` filter). |
| `vol3_check` | Load plugin `source` (unsandboxed) and report its description or a structured failure; with `view_path` also the unsatisfied requirements. |
| `vol3_import` | Register an external vol3 output (Parquet/CSV/JSON) as a run of a `vol3__*` table. |
| `vol3_write_config` | Write a `vol` `config.json` reproducing the view's layer stack. |
| `vol3_source_list` | Stored user plugin sources of a case (name, sha256, size, updated, version). |
| `vol3_source_get` | One stored plugin source; `modified_externally` flags a hand edit. |
| `vol3_source_put` | Store plugin source as `<case>/plugins/<name>.py` (previous version kept in `plugins/history`) and return the `vol3_check` outcome. `vol3_run`/`vol3_describe`/`vol3_check` accept `source_name` + `case_dir` instead of `source`. |
| `vol3_fixture_put` | Store a plugin fixture (plugin or stored source, view, args, row predicates) under `<case>/fixtures/vol3/`. |
| `vol3_fixture_list` | Stored plugin fixtures of a case. |
| `vol3_fixture_run` | Run a fixture: verdict `pass`/`fail`/`indeterminate` with per-predicate results, filed as a `fixture_verdict` annotation. |

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

## Semantic-workbench tools by workflow

Tools added with the memory-image / case workbench. Image, `vol3_*`, case, YARA, detector-fixture, key-finder and heap tools are tabled in their sections above; this section adds the rest, grouped by workflow. List every tool with `tools/list` in your MCP client; the playbook prompts below say in which order to call them.

**Case inventory and annotations**

| Tool | Purpose |
|---|---|
| `case_manifest` | Inventory of a case: views, images (exists/size), `.msl` captures, annotations, ISF drafts/exports, plugins, tables. |
| `annotations_list` | What has been concluded about a capture (its analysis record). |
| `annotations_add` | Record a conclusion about a capture (append-only, never edits history). |
| `annotations_supersede` | Correct an entry: append a replacement that supersedes `entry_id`. |
| `annotations_retract` | Withdraw an entry (a retraction is appended; nothing is deleted). |

**ISF profile workbench** (see [](isf_workbench.md))

| Tool | Purpose |
|---|---|
| `isf_probe` | Run one pakunoda probe on a full image (`viability`, `banner`, `vmcoreinfo`, ...). |
| `isf_draft_create` / `isf_draft_list` / `isf_draft_get` | Create an empty draft for a capture, list drafts, read a materialized summary. |
| `isf_draft_set` | One draft operation: `op` is symbol, struct, field, base_type, enum or remove. |
| `isf_draft_import` | Import (a subset of) an ISF JSON file into the draft; records its sha256. |
| `isf_draft_retract` / `isf_draft_versions` / `isf_draft_diff` | Retract an entry, read the version history, diff against an older version or an ISF file. |
| `isf_draft_validate` | Validate the draft as an ISF document and report per-plugin readiness. |
| `isf_draft_export` | Write the draft (at `version`) as an ISF file; returns path, size and sha256. |
| `isf_try` | Try a draft or an ISF file on the image, with a ground-truth diff. |
| `code_evidence` | Decode which struct fields a kernel function touches. |
| `disasm` | Disassemble `length` bytes at `address` of a dump; captured stretches only. |

**N-dump structure and object models** (see [](object_model.md))

| Tool | Purpose |
|---|---|
| `anchor_consensus` | Consensus keyed by DELTA from each dump's own anchor (e.g. the key). |
| `xref_pointers` | Who points here: captured words holding a pointer into a target. |
| `propose_layout` | Propose field boundaries around a verified anchor, learned from N dumps. |
| `artifact_model_build` | Learn a layout and build the artifact model. |
| `artifact_model_export` | Export an artifact model (JSON) as a Volatility3 plugin. |
| `artifact_model_validate` | Validate a model's plugin on held-out captures against ground truth. |

## Prompts (playbooks)

The server registers 8 MCP prompts. Each renders a numbered procedure naming the exact tools and parameters, what to check in each result, and the traps hit on real data. All arguments are optional; given values are substituted into the steps.

| Prompt | Arguments | For |
|---|---|---|
| `memdiver_start` | none | What MemDiver is, the playbook list, the resources and conventions. Fetch this first. |
| `vol3_inside_memdiver` | `image_path`, `case` | Open an image, resolve a profile, run Volatility 3 plugins, query and annotate rows. |
| `vol3_plugin_dev` | `case`, `view_path` | Scaffold, store, check, run and fixture-test a Volatility 3 plugin. |
| `isf_workbench` | `image_path`, `case`, `draft` | Hand-build an ISF kernel profile when automatic resolution fails. |
| `image_to_process_keys` | `image_path`, `case`, `pid` | Process, `.msl`, heap, key finders, oracle verification. |
| `n_image_variance` | `corpus_dir` | Cohorts, consensus and anchor consensus across N dumps. |
| `object_model_from_keylog` | `corpus_dir`, `keylog` | Key log, layout, artifact model, exported plugin, held-out validation. |
| `code_evidence` | `image_path`, `function` | Which struct fields a kernel function touches, joined to an ISF. |

## Resources

Four read-only resource templates serve case state as JSON. URL-encode the case directory. They run the same read sandbox as the tools ([](sandbox.md)) and return the same structured JSON error on a denial.

| URI | Content |
|---|---|
| `memdiver://case/{case_dir}/manifest` | Inventory of a case (as `case_manifest`). |
| `memdiver://case/{case_dir}/schema` | Schema of a case (as `case_schema`). |
| `memdiver://case/{case_dir}/annotations/{capture}` | Current annotations of one capture. |
| `memdiver://case/{case_dir}/isf/{capture}/{draft}` | Materialized summary of one ISF draft. |

See each tool's input schema via the MCP client's tool picker, or read the implementations in `mcp_server/server.py` (registrations) and `mcp_server/tools.py` / `mcp_server/tools_inspect.py` / `mcp_server/tools_pipeline.py` / `mcp_server/tools_xref.py`.
