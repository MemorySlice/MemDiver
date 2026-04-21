<p align="center">
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/logo_readme.png"
       alt="MemDiver logo: a diver descending toward a golden key inside a teal memory blob" width="320"/>
</p>

<p align="center"><em>Interactive platform for identifying and analyzing data structures in memory dumps.</em></p>

<p align="center">
  <a href="https://github.com/MemorySlice/MemDiver/actions/workflows/ci.yml"><img alt="CI status on main" src="https://github.com/MemorySlice/MemDiver/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/memdiver/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/memdiver.svg"></a>
  <a href="https://pypi.org/project/memdiver/"><img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/memdiver.svg"></a>
  <a href="LICENSE"><img alt="License Apache-2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <a href="https://memoryslice.github.io/MemDiver/"><img alt="Documentation" src="https://img.shields.io/badge/docs-gh--pages-brightgreen.svg"></a>
  <img alt="MCP enabled" src="https://img.shields.io/badge/MCP-enabled-8A2BE2.svg">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/04_workspace_default.png"
       alt="MemDiver workspace — hex viewer, sidebar, detail panel, and analysis tab in dark theme" width="900"/>
</p>

## What it does

MemDiver is a browser-based workbench for exploring binary memory dumps. A FastAPI backend drives a React IDA-Pro-style dockable workspace; an optional Marimo sandbox hosts deeper research workflows; an MCP server exposes the same analysis engine to AI assistants. It combines known-key search, entropy scanning, change-point detection, structural parsing, and cross-run differential analysis to locate and classify data structures in memory.

## Why it exists

MemDiver is the research artifact accompanying a submission to the **IMF conference** (IT Security Incident Management &amp; IT Forensics). The accompanying study analyzed ~30K memory dumps across 13 TLS libraries (TLS 1.2 and 1.3) to answer a concrete forensic question: *which TLS secrets survive in process memory, and for how long?* The toolkit generalizes to any "find the structure in the blob" problem — cryptographic keys today, kernel objects or game state tomorrow.

## At a glance

| Surface | Count | Location |
|---|---|---|
| Detection algorithms | **8** | [`algorithms/`](algorithms/) — `exact_match`, `entropy_scan`, `change_point`, `differential`, `constraint_validator`, `user_regex`, `pattern_match`, `structure_scan` |
| CLI subcommands | **20** | [`cli.py`](cli.py) |
| FastAPI routers | **12** + WebSocket | [`api/routers/`](api/routers/) |
| MCP tools | **15** | [`mcp_server/`](mcp_server/) |
| Exporters | YARA · JSON · Volatility3 | [`architect/`](architect/) |
| Dump backends | `memslicer` · `lldb` · `fridump` (Frida; *not* friTap) | [`core/dump_driver.py`](core/dump_driver.py) |
| Visualization views | 4 SPA + 5 Marimo research-mode | [`frontend/`](frontend/) + [`ui/`](ui/) |

Under the hood: DuckDB `ProjectDB`, `.memdiver` `SessionStore`, Welford incremental consensus, Aho-Corasick multi-pattern scan, Kaitai Struct binary-format parsers, ASLR-aware region alignment, auto-discovered KDF plugins, BYO decryption oracles, first-class Volatility3 plugin emission.

## Install

```bash
pip install memdiver                 # web UI + CLI + MCP server (everything runtime-side)
pip install "memdiver[experiment]"   # + frida-tools, memslicer for dump collection
pip install "memdiver[docs]"         # + Sphinx toolchain for building the docs site
pip install "memdiver[dev]"          # + pytest and contributor tooling
```

LLDB is installed via your operating system — Xcode Command Line Tools on macOS, `apt install lldb` on Debian/Ubuntu. `memdiver experiment` exits gracefully with an install hint when no backend is present.

## Quick start

```bash
# 1. Web app (FastAPI + React SPA, opens on http://127.0.0.1:8080)
memdiver                 # or: memdiver web

# 2. One-shot CLI analysis
memdiver analyze <library_dirs> --phase pre_abort --protocol-version TLS13

# 3. MCP server (stdio transport) — wire into AI assistants
memdiver mcp

# 4. Collect fresh dumps from a target process
memdiver experiment --target path/to/target.py --num-runs 10

# 5. Marimo research sandbox (houses the 5 deeper visualization views)
memdiver ui
```

### Wire MemDiver into Claude Desktop / Claude Code

Add this block to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS:

```json
{
  "mcpServers": {
    "memdiver": { "command": "memdiver", "args": ["mcp"] }
  }
}
```

Restart the MCP client — the 15 MemDiver tools (`scan_dataset`, `analyze_library`, `get_entropy`, `brute_force`, `emit_plugin`, …) appear in the tool picker.

## Power-user CLI

All 20 subcommands exposed by [`cli.py`](cli.py):

| Detection &amp; analysis | Consensus (Welford) | Pipeline (Phase-25) | Format conversion | Runtime shells |
|---|---|---|---|---|
| `analyze` · `scan` · `batch` · `verify` | `consensus` · `consensus-begin` · `consensus-add` · `consensus-finalize` | `search-reduce` · `brute-force` · `n-sweep` · `emit-plugin` | `export` · `import` · `import-dir` | `web` · `ui` · `app` · `mcp` · `experiment` |

Run `memdiver <cmd> --help` for any of them, or see the full [CLI reference](https://memoryslice.github.io/MemDiver/user_guide/cli_reference.html).

## Screenshots

| [Workspace](https://memoryslice.github.io/MemDiver/user_guide/web_ui_tour.html#workspace-default-layout) | [Hex + overlay](https://memoryslice.github.io/MemDiver/visualizations/hex.html) | [Entropy](https://memoryslice.github.io/MemDiver/visualizations/entropy.html) | [Consensus](https://memoryslice.github.io/MemDiver/visualizations/consensus.html) |
|---|---|---|---|
| <img alt="Workspace thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/04_workspace_default.png" width="220"> | <img alt="Hex viewer thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/05_hex_with_overlay.png" width="220"> | <img alt="Entropy profile thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/06_entropy_tab.png" width="220"> | <img alt="Consensus view thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/07_consensus_tab.png" width="220"> |

Screenshots regenerate deterministically via the Playwright harness under [`docs/screenshots/`](docs/screenshots/).

## Where to go next

- **Full documentation** — <https://memoryslice.github.io/MemDiver/>
- **Architecture deep-dive** — <https://memoryslice.github.io/MemDiver/architecture/index.html>
- **Algorithm reference** — <https://memoryslice.github.io/MemDiver/algorithms/index.html>
- **Contributing** — <https://memoryslice.github.io/MemDiver/contributing/index.html>
- **Changelog** — [CHANGELOG.md](CHANGELOG.md)

## Architecture

```
api/            FastAPI backend — 12 routers + WebSocket, OpenAPI docs at /docs
frontend/       React + Vite SPA (TypeScript, Tailwind, Zustand) — dockable workspace
core/           Stdlib-only data layer (models, discovery, parsing, entropy, KDF, variance, ASLR alignment)
engine/         Differential Engine — ConsensusVector (Welford), SearchCorrelator, DiffStore,
                ProjectDB (DuckDB), SessionStore (.memdiver), oracle loader, Vol3 plugin emission
algorithms/     8 algorithms auto-discovered via pkgutil registry
harvester/      Data ingestion — DumpIngestor, SidecarParser, MetadataStore
architect/      Pattern Architect — static checker + generator + YARA / JSON / Volatility3 exporters
msl/            Memory Slice (.msl) v1.1.0 — hand-rolled container with BLAKE3 integrity chain
mcp_server/     MCP server — 15 tools exposed to AI assistants
ui/             Marimo research sandbox (houses the 5 deeper views) + legacy NiceGUI shell
docs/           Sphinx site (Read the Docs theme), published to GitHub Pages via docs.yml
```

## Release process (maintainers)

1. Bump `version` in `pyproject.toml` and move the `[Unreleased]` block in `CHANGELOG.md` under a new version heading.
2. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/publish.yml` builds the React bundle, runs `python -m build`, and publishes to PyPI via OIDC trusted publishing (no token).
4. `.github/workflows/docs.yml` rebuilds the Sphinx site and deploys to <https://memoryslice.github.io/MemDiver/>.
5. For a pre-release dry run: `gh workflow run publish.yml` — the `workflow_dispatch` trigger publishes to test.pypi.org via the `testpypi` environment.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Citation

If MemDiver supports your research, please cite the accompanying IMF conference submission. Author attribution is withheld during double-blind review; this entry will be updated once camera-ready.

```bibtex
@software{memdiver2026,
  author = {Anonymous},
  title  = {MemDiver: Interactive Memory-Dump Structure Analysis},
  year   = {2026},
  url    = {https://github.com/MemorySlice/MemDiver},
  note   = {Artifact accompanying an IMF (IT Security Incident Management \& IT Forensics) conference submission}
}
```
