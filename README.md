# MemDiver

Interactive platform for identifying and analyzing data structures in memory dumps.

## What It Does

MemDiver is a browser-based analysis platform for exploring binary memory dumps. The primary interface is a [FastAPI](https://fastapi.tiangolo.com) backend + [React](https://react.dev) frontend with an IDA-Pro-style dockable workspace, complemented by an optional [Marimo](https://marimo.io) research sandbox for interactive custom analysis. It combines known-key search, entropy-based scanning, and cross-run differential analysis to locate and classify data structures in memory.

- **General purpose**: designed for identifying known and unknown data structures in binary memory dumps
- **Current focus**: cryptographic key identification in TLS library memory dumps
- **Research context**: analyzed ~30K dumps from 13 TLS libraries across TLS 1.2 and 1.3
- **Key finding**: TLS 1.3 "missing keys" explained — libraries like BoringSSL zero handshake secrets after use; only EXPORTER_SECRET and traffic secrets survive

## Use Cases

- Forensic analysis of cryptographic keys in memory dumps
- Understanding which secrets survive at which lifecycle phase
- Comparing key retention behavior across TLS libraries
- Generating YARA rules from discovered memory patterns
- Entropy-based scanning for unknown high-entropy regions (keys, nonces, IVs)
- Cross-run differential analysis to isolate key-sized variable regions

## Features

**7 analysis algorithms:**
- Exact match — search for known secret byte sequences using ground truth
- Entropy scan — Shannon entropy sliding window for key-sized regions
- Change-point detection — CUSUM-based entropy plateau detection
- Differential analysis — cross-run byte variance (DPA-inspired)
- Constraint validator — TLS KDF relationship verification for candidates
- User regex — custom pattern matching
- Pattern loader — structural pattern matching from JSON definitions

**9 visualization views:**
- Key presence heatmap — which secrets survive at which phase per library
- Hex viewer — color-coded byte classification (key/structural/dynamic)
- Entropy profile — Shannon entropy vs byte offset with threshold overlay
- Cross-run variance map — byte variance across N runs with classification bands
- Phase lifecycle — key presence across all phases for one library
- Cross-library comparison — side-by-side hex panels for same secret
- Differential diff — two-run XOR diff with color-coded changed bytes
- Consensus view — multi-algorithm agreement visualization
- Pattern Architect — YARA rule and JSON signature generation

**Web application:**
- FastAPI backend + React frontend with IDA-Pro-style dockable workspace
- Light/dark/system theme with high-contrast accessibility mode
- Wizard-driven onboarding (input type, data selection, ground truth, analysis mode)
- Resizable panel layout: hex viewer, investigation panel, navigation tree, bookmarks
- REST API with OpenAPI docs + WebSocket progress streaming
- MCP server for AI assistant integration (Claude Code, etc.)
- Optional Marimo research sandbox for interactive custom analysis

**Additional capabilities:**
- Testing mode (quick validation) vs Research mode (deep exploration)
- Phase normalization across libraries with different naming conventions
- Plugin system: drop-in algorithm extensibility
- TLS 1.2 PRF and TLS 1.3 HKDF implementations for key derivation verification

## Installation

MemDiver ships as a single PyPI package with just two optional extras:

```bash
pip install memdiver                # full web UI + CLI analysis (everything you need)
pip install memdiver[experiment]    # adds frida-tools + memslicer for dump collection
pip install memdiver[dev]           # adds pytest + test helpers (contributors only)
```

The base install already includes `marimo`, `nicegui`, `mcp`, and
`kaitaistruct` — the web UI, the legacy NiceGUI shell, the MCP server, and
the Marimo research sandbox all work out of the box.

### The experiment flow and native tools

`memdiver experiment` spawns target processes and collects memory dumps via
one or more backends. Install the `[experiment]` extra to pull the
Python-installable pieces (`frida-tools`, `memslicer`). The `lldb` backend is
optional and must be installed via your operating system — Xcode on macOS,
`apt install lldb` on Debian/Ubuntu, etc. If none of the backends are
available, `memdiver experiment` exits with an install hint rather than
crashing.

## Quick Start

```bash
# Launch the web application (FastAPI + React)
memdiver

# Marimo research notebook
memdiver ui

# Headless CLI
memdiver analyze <library_dirs> --phase pre_abort --protocol-version TLS13
memdiver scan --root /path/to/dataset
memdiver batch --config batch.json

# MCP server for AI integration
memdiver mcp

# Experiment flow (requires: pip install memdiver[experiment])
memdiver experiment --target path/to/target.py --num-runs 10
```

## Release process (maintainers)

1. Bump `version` in `pyproject.toml`.
2. Move the `Unreleased` block in `CHANGELOG.md` under a new version heading.
3. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `.github/workflows/publish.yml` builds the React bundle, runs
   `python -m build`, and publishes to PyPI via OIDC trusted publishing.
   No API token is needed — the first release requires one-time setup of a
   pending trusted publisher on pypi.org (and test.pypi.org) pointing at
   this repository and the `publish.yml` workflow.
5. For a pre-release dry-run, use `gh workflow run publish.yml` — the
   `workflow_dispatch` trigger publishes to test.pypi.org via the `testpypi`
   environment.

## Dataset Structure

MemDiver expects memory dumps organized by TLS version, scenario, library, and run:

```
TLS{12,13}/{scenario}/{library}/{library}_run_{12,13}_{N}/
  ├── *.dump          # Memory dumps at lifecycle phases
  ├── keylog.csv      # Ground truth TLS secrets
  └── timing_*.csv    # Timing data
```

Configure the dataset root path via `config.json` or the UI file browser.

## Development

```bash
git clone https://github.com/2026-success/memdiver.git
cd memdiver
pip install -e ".[dev]"
pytest tests/ -v

# Start the FastAPI backend (serves built React frontend)
memdiver

# Frontend development (hot-reload)
cd frontend && npm install && npm run dev

# Start the Marimo research sandbox (optional)
memdiver ui
```

### Architecture

```
api/            FastAPI backend (routers, config, WebSocket, task management)
frontend/       React + Vite frontend (TypeScript, Tailwind, Zustand)
core/           Stdlib-only data layer (models, discovery, parsing, entropy, KDF)
engine/         Differential Engine (ConsensusVector, SearchCorrelator, DiffStore)
algorithms/     Plugin system with auto-discovery via pkgutil
harvester/      Data ingestion (DumpIngestor, SidecarParser, MetadataStore)
architect/      Pattern Architect (static checker, pattern generator, YARA/JSON export)
msl/            Memory Slice (.msl) format parser
mcp_server/     MCP server + pure tool functions for AI integration
ui/             Legacy UI layer (Marimo research sandbox, NiceGUI optional)
```

### Adding Algorithms

Drop a `.py` file in `algorithms/known_key/` or `algorithms/unknown_key/` with a class extending `BaseAlgorithm`. It auto-discovers via the registry.

## License

MIT
