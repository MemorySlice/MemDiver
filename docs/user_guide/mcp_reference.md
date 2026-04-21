# MCP tool reference

MemDiver exposes **15 tools** to MCP-speaking agents. All tools are thin wrappers around the same pure functions used internally by the engine, so responses are identical whether you invoke them over MCP, through the CLI, or through the FastAPI backend.

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
| `get_entropy` | Shannon entropy profile with configurable window / threshold. |
| `extract_strings` | ASCII/UTF-8 string extraction. |
| `get_session_info` | MSL session metadata (PID, module list, connection table). |
| `get_cross_references` | Cross-references between MSL blocks. |
| `identify_structure` | Best-match structure overlay at an offset. |

## Format conversion

| Tool | Purpose |
|---|---|
| `import_raw_dump` | Convert `.dump` → `.msl`. |

## Pipeline stages

| Tool | Purpose |
|---|---|
| `search_reduce` | Variance + alignment + entropy candidate reducer. |
| `brute_force` | Iterate candidates through a decryption oracle. |
| `n_sweep` | N-curve sweep with convergence reporting. |
| `emit_plugin` | Synthesize a Volatility3 plugin from a verified hit. |

See each tool's input schema via the MCP client's tool picker, or read the implementations in `mcp_server/tools.py` / `mcp_server/tools_inspect.py` / `mcp_server/tools_pipeline.py`.
