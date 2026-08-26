<p align="center">
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/wordmark.svg"
       alt="MemDiver" height="90" align="middle"/>
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/logo_readme.png"
       alt="MemDiver logo: a diver descending toward a golden key inside a teal memory blob"
       width="220" align="middle"/>
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
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/12_workspace_loaded_dark.png"
       alt="MemDiver workspace with an MSL capture loaded — dark theme" width="49%"/>
  <img src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/13_workspace_loaded_light.png"
       alt="MemDiver workspace with an MSL capture loaded — light theme" width="49%"/>
</p>
<p align="center"><sub>MemDiver workspace with a sample <code>.msl</code> capture loaded — dark and light themes side by side.</sub></p>

# MemDiver

MemDiver is a browser-based workbench for exploring binary memory dumps. A FastAPI backend drives a React dockable workspace, with an optional Marimo sandbox for deeper research workflows and an MCP server that exposes the same analysis engine to AI assistants. For automation and integration into existing pipelines, the same engine is available through non-interactive CLI subcommands ("headless" use — no separate mode or flag, just the CLI without a UI).

It combines known-key search, entropy scanning, change-point detection, structural parsing, and cross-run differential analysis to locate and classify data structures in memory.

## Features

- **Interactive workspace** — React-based dockable UI for hands-on exploration
- **Research sandbox** — Optional Marimo environment for reproducible notebooks and custom analysis
- **AI-assisted analysis** — MCP server integration for use with Claude and other assistants
- **Headless use** — the same engine via non-interactive CLI subcommands (no separate mode or flag) for CI/CD, batch processing, and forensic pipelines
- **Python library** — `import memdiver` to open dumps, convert to `.msl`, parse containers, and run analysis programmatically (see [library quickstart](docs/quickstart/library.md))
- **Analysis engine** — Known-key search, entropy scanning, change-point detection, structural parsing, and cross-run differential analysis
- **Pcap verification oracle** — prove a recovered TLS secret by decrypting records from a real packet capture (first-party, built in), then export it as a Wireshark-loadable NSS key log


## Install

```bash
pip install memdiver                 # everything: CLI, library, web UI, MCP server,
                                     # pcap oracle, dump collection, post-quantum KEM
pip install "memdiver[marimo]"       # + Marimo notebook UI (memdiver ui) -- the one opt-in interface
pip install "memdiver[all]"          # every interface (= the default install + marimo)
pip install "memdiver[docs]"         # + Sphinx toolchain for building the docs site
pip install "memdiver[dev]"          # + pytest and contributor tooling
```

The default install is the **complete product**: `memdiver web`, `memdiver mcp` and
the pcap verification oracle all work with no extras. Only the Marimo notebook UI is
opt-in, because it alone costs ~164 MB — more than four times every other interface
combined.

`memdiver[api]`, `[mcp]`, `[pcap]`, `[experiment]` and `[crypto]` still resolve as
no-op aliases, so existing pinned commands keep working. Note that Python extras can
only *add* dependencies, never subtract them, so there is deliberately no install
smaller than the default.

**What pip cannot install for you.** Three capabilities ship by default but need a
native runtime piece, so a successful `pip install` does not by itself mean they will
run. Each one reports the OS-level action rather than a misleading `pip install`
hint:

| Capability | Needs |
| --- | --- |
| ML-KEM / hybrid MSL encryption | the **liboqs C library**. `liboqs-python` builds it into `~/_oqs` on first use, so **cmake + a C compiler** must be present. Without them, ML-KEM reports unavailable and only `KeyEncap=None` and X25519 are offered. |
| `memdiver experiment` (Frida) | an **attachable target process**, plus platform support for Frida. |
| `memdiver experiment` (LLDB) | **LLDB from your OS** — Xcode Command Line Tools on macOS, `apt install lldb` on Debian/Ubuntu. |
Every command that needs something missing says exactly what to run — a `pip install`
hint when a Python package is genuinely absent, and the OS-level action when the
missing piece is native (see the table above). `memdiver experiment` exits gracefully
when no backend is present.

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

## Verify against a real capture

The strongest proof that a recovered byte range *is* a TLS key: derive record
keys from the candidate and AEAD-decrypt records from a **real packet capture**.
This is a first-party, trusted oracle (TLS 1.3, TLS 1.2 GCM, TLS 1.2 CBC) — the
capture is only ever parsed as data, never executed, so it runs without the
untrusted-oracle sandbox that bring-your-own oracle scripts need.

It works in two steps: **arm** the capture — enumerate the TLS sessions it holds
and their `client_random` values — then **run** brute-force against it, which
answers whether any candidate actually decrypts those records.

```bash
# 1. Arm — which TLS sessions does this capture hold?
memdiver inspect-pcap /abs/path/to/traffic.pcap

# 2. Run — confirm a candidate decrypts real captured records
memdiver brute-force --candidates candidates.json --dump reference.msl \
    --pcap /abs/path/to/traffic.pcap --key-sizes 32 -o hits.json

# 3. Export the confirmed secret as a Wireshark-loadable NSS key log
memdiver export-keylog --secrets secrets.json -o session.keylog
```

| Surface | Arm (inspect) | Run (confirm) |
|---|---|---|
| **CLI** | `memdiver inspect-pcap <capture>` | `memdiver brute-force --pcap …` |
| **Web** | `POST /api/pcaps/upload` → `POST /api/pcaps/validate` | `POST /api/pipeline/run` (`pcap_path`, `tls_client_random`) |
| **MCP** | `inspect_pcap` tool | `brute_force` tool (`pcap_path`) |
| **Library** | `memdiver.services.inspect_pcap(pcap_path=…)` | `memdiver.services.brute_force(pcap_path=…)` |

The `dpkt` parser ships in the default install, so the oracle works out of the box.
(If it is force-uninstalled, the arm step returns an `INVALID_INPUT` capability error
and pcap runs are unavailable.)

**The `--key-sizes` trap:** the oracle recovers the *secret* and derives record
keys from it, so the candidate length must match the secret, not the record key
— `32` for a TLS 1.3 traffic secret (the default), **`48` for a TLS 1.2 master
secret**. A TLS 1.2 run left at the default `32` will never find its key.

A hit confirmed this way is recorded with `confirmed_by: "pcap"` and shown in
the web UI as *"Verified via pcap capture"*.

Full walkthrough — the `--stride` coverage trap, restricting to a single
session, the web uploader, and `--persist-ground-truth` — in
[docs/oracle/pcap_oracle.md](docs/oracle/pcap_oracle.md).

## API authentication

The FastAPI backend is **open by default** (no login, matching its localhost
single-user design) unless you set `MEMDIVER_API_TOKEN`:

```bash
export MEMDIVER_API_TOKEN="a-long-random-secret"
memdiver web
```

Once a token is configured, every data route — everything under `/api/`,
`/ws/`, and `/notebook` — requires it. Send it as either:

- `Authorization: Bearer <token>` (HTTP), or
- `X-API-Key: <token>` (HTTP), or
- `?token=<token>` query param (WebSocket only — browsers can't set custom
  headers on the WS handshake)

A missing or wrong token gets a `401` on HTTP routes, or a WebSocket close
with code `1008` (policy violation). All comparisons are constant-time
(`hmac.compare_digest`), so response timing can't be used to guess the token.
The health check (`/health`), the OpenAPI/docs endpoints (`/docs`, `/redoc`,
`/openapi.json`), and the static frontend bundle stay reachable without a
token even when one is set.

**Bind guardrail:** `memdiver web` refuses to start if `MEMDIVER_HOST` is set
to anything other than `127.0.0.1` / `::1` / `localhost` and no
`MEMDIVER_API_TOKEN` is configured — binding a forensic-data API to the
network with zero auth is refused outright. Set a token, or override with
`MEMDIVER_API_ALLOW_INSECURE=1` (logs a loud warning on every startup).

## At a glance

| Surface | Count | Location |
|---|---|---|
| Detection algorithms | **8** | [`algorithms/`](algorithms/) — `exact_match`, `entropy_scan`, `change_point`, `differential`, `constraint_validator`, `user_regex`, `pattern_match`, `structure_scan` |
| CLI subcommands | **24** | [`cli/`](cli/) |
| FastAPI routers | **15** + WebSocket | [`api/routers/`](api/routers/) |
| MCP tools | **34** | [`mcp_server/`](mcp_server/) |
| Exporters | YARA · JSON · Volatility3 | [`architect/`](architect/) |
| Dump backends | `memslicer` · `lldb` · `fridump` (Frida; *not* friTap) | [`core/dump_driver.py`](core/dump_driver.py) |
| Visualization views | 4 SPA + 5 Marimo research-mode | [`frontend/`](frontend/) + [`ui/`](ui/) |

Under the hood: DuckDB `ProjectDB`, `.memdiver` `SessionStore`, Welford incremental consensus, Aho-Corasick multi-pattern scan, Kaitai Struct binary-format parsers, ASLR-aware region alignment, auto-discovered KDF plugins, BYO decryption oracles, first-class Volatility3 plugin emission.

### Wire MemDiver into Claude Desktop / Claude Code

Add this block to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS:

```json
{
  "mcpServers": {
    "memdiver": { "command": "memdiver", "args": ["mcp"] }
  }
}
```

Restart the MCP client — the 34 MemDiver tools (`scan_dataset`, `analyze_library`, `get_entropy`, `brute_force`, `emit_plugin`, …) appear in the tool picker.

## Power-user CLI

All 24 subcommands exposed by [`cli/`](cli/):

| Detection &amp; analysis | Consensus (Welford) | Pipeline (Phase-25) | Format conversion | Runtime shells |
|---|---|---|---|---|
| `analyze` · `scan` · `batch` · `verify` · `inspect` · `inspect-pcap` | `consensus` · `consensus-begin` · `consensus-add` · `consensus-finalize` | `search-reduce` · `brute-force` · `n-sweep` · `auto-floor` · `emit-plugin` | `export` · `export-keylog` · `gen-kem-key` · `import` · `import-dir` | `web` · `ui` · `mcp` · `experiment` |

Run `memdiver <cmd> --help` for any of them, or see the full [CLI reference](https://memoryslice.github.io/MemDiver/user_guide/cli_reference.html).

## Screenshots

| [Workspace](https://memoryslice.github.io/MemDiver/user_guide/web_ui_tour.html#workspace-default-layout) | [Hex + overlay](https://memoryslice.github.io/MemDiver/visualizations/hex.html) | [Entropy](https://memoryslice.github.io/MemDiver/visualizations/entropy.html) | [Consensus](https://memoryslice.github.io/MemDiver/visualizations/consensus.html) |
|---|---|---|---|
| <img alt="Workspace thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/04_workspace_default.png" width="220"> | <img alt="Hex viewer thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/05_hex_with_overlay.png" width="220"> | <img alt="Entropy profile thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/06_entropy_tab.png" width="220"> | <img alt="Consensus view thumbnail" src="https://raw.githubusercontent.com/MemorySlice/MemDiver/main/docs/_static/screenshots/07_consensus_tab.png" width="220"> |

Screenshots regenerate deterministically via the Playwright harness under [`docs/screenshots/`](docs/screenshots/). Pipeline shots 09 and 10 use precomputed n-sweep fixtures produced by [`scripts/precompute_pipeline_fixtures.py`](scripts/precompute_pipeline_fixtures.py) against the gocryptfs reference dataset.

### Chart backend

The four analysis charts — Entropy, Variance Map, VAS, and the Pipeline Survivor Curve — ship with two interchangeable renderers:

- **Plotly** (default) — full interactive experience with pan/zoom/legend-toggle and a ~2.3 MB bundle.
- **SVG** — hand-rolled React + SVG with hover tooltips but no pan/zoom, zero runtime dependencies, code-split so users who stay on SVG never download the Plotly chunk.

Switch via **Settings → Display → Chart backend**. The preference persists per-browser. No reload required. Both backends share the same theme tokens so dark/light/high-contrast behaviour is identical.

## Where to go next

- **Full documentation** — <https://memoryslice.github.io/MemDiver/>
- **Architecture deep-dive** — <https://memoryslice.github.io/MemDiver/architecture/index.html>
- **Algorithm reference** — <https://memoryslice.github.io/MemDiver/algorithms/index.html>
- **Contributing** — <https://memoryslice.github.io/MemDiver/contributing/index.html>
- **Changelog** — [CHANGELOG.md](CHANGELOG.md)

## Architecture

```
api/            FastAPI backend — 15 routers + WebSocket, OpenAPI docs at /docs
frontend/       React + Vite SPA (TypeScript, Tailwind, Zustand) — dockable workspace
core/           Stdlib-only data layer (models, discovery, parsing, entropy, KDF, variance, ASLR alignment)
engine/         Differential Engine — ConsensusVector (Welford), SearchCorrelator, DiffStore,
                ProjectDB (DuckDB), SessionStore (.memdiver), oracle loader, Vol3 plugin emission
algorithms/     8 algorithms auto-discovered via pkgutil registry
harvester/      Data ingestion — DumpIngestor, SidecarParser, MetadataStore
architect/      Pattern Architect — static checker + generator + YARA / JSON / Volatility3 exporters
msl/            Memory Slice (.msl) v1.1.0 — hand-rolled container with BLAKE3 integrity chain
mcp_server/     MCP server — 34 tools exposed to AI assistants
ui/             Marimo research sandbox (houses the 5 deeper views)
docs/           Sphinx site (Read the Docs theme), published to GitHub Pages via docs.yml
```

## Memory Slice format

MemDiver reads and writes the open **Memory Slice (.msl)** container — a
self-describing, integrity-chained snapshot format for process memory and
sidecar metadata. The on-disk layout, capability bits, and conformance
fixtures live in the dedicated specification repository so other tools can
interoperate without depending on MemDiver itself:

- **Specification & fixtures** — <https://github.com/MemorySlice/memslice-spec>

The Python reader/writer in `msl/` tracks that spec; see
[docs/file_formats/msl_v1_0_0.md](docs/file_formats/msl_v1_0_0.md) for the
in-repo summary used by this codebase.

## Release process (maintainers)

1. Bump `version` in `pyproject.toml` and move the `[Unreleased]` block in `CHANGELOG.md` under a new version heading.
2. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/publish.yml` builds the React bundle, runs `python -m build`, and publishes to PyPI via OIDC trusted publishing (no token).
4. `.github/workflows/docs.yml` rebuilds the Sphinx site and deploys to <https://memoryslice.github.io/MemDiver/>.
5. For a pre-release dry run: `gh workflow run publish.yml` — the `workflow_dispatch` trigger publishes to test.pypi.org via the `testpypi` environment.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Citation

A formal citation (DOI) will be minted when the accompanying study is
published. Until then, please cite the GitHub Releases page for the specific
MemDiver version you used:

  https://github.com/MemorySlice/MemDiver/releases

and reference the project URL `https://github.com/MemorySlice/MemDiver`.
