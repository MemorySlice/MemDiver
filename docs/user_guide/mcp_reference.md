# MCP tool reference

MemDiver exposes **45 tools** to MCP-speaking agents. All tools are thin wrappers around the same pure functions used internally by the engine, so responses are identical whether you invoke them over MCP, through the CLI, or through the FastAPI backend.

## Dataset inspection

| Tool | Purpose |
|---|---|
| `scan_dataset` | Enumerate libraries + phases under a dataset root. |
| `list_phases` | List canonical phases for a specific library directory. |
| `list_protocols` | Enumerate supported protocols (TLS12, TLS13, SSH2, …). |

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
| `get_blocks` | List all blocks in an MSL file grouped by category. |

## Format conversion

| Tool | Purpose |
|---|---|
| `import_raw_dump` | Convert `.dump` → `.msl`. |
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
