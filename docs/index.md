---
myst:
  html_meta:
    "description lang=en": "Interactive platform for identifying and analyzing data structures in memory dumps."
---

# MemDiver

```{image} _static/logo_simple.svg
:alt: MemDiver logo
:width: 200px
:align: center
```

**Interactive platform for identifying and analyzing data structures in memory dumps.**

:::{note}
MemDiver is the research artifact accompanying a submission to the **IMF conference** (IT Security Incident Management &amp; IT Forensics). The accompanying study analyzed ~30K memory dumps across 13 TLS libraries (TLS 1.2 and 1.3) to answer a concrete forensic question: *which TLS secrets survive in process memory, and for how long?*
:::

## What it does

MemDiver is a browser-based workbench for exploring binary memory dumps. A FastAPI backend drives a React IDA-Pro-style dockable workspace; an optional Marimo sandbox hosts deeper research workflows; an MCP server exposes the same analysis engine to AI assistants. It combines known-key search, entropy scanning, change-point detection, structural parsing, and cross-run differential analysis to locate and classify data structures in memory.

## Get started

::::{grid} 2
:gutter: 3

:::{grid-item-card} 🚀 Quick start
:link: quickstart/index
:link-type: doc

Install MemDiver and run the web UI, CLI, MCP server, or experiment harness in under five minutes.
:::

:::{grid-item-card} 🧭 User guide
:link: user_guide/web_ui_tour
:link-type: doc

Tour the workspace, learn the CLI, wire the MCP server into Claude Code, and reproduce the hero screenshots.
:::

:::{grid-item-card} 🏗️ Architecture
:link: architecture/index
:link-type: doc

Walk through the ten subsystems: `core`, `engine`, `harvester`, `msl`, `architect`, `algorithms`, `api`, `mcp_server`, `ui`, `frontend`.
:::

:::{grid-item-card} 🔬 Algorithms &amp; views
:link: algorithms/index
:link-type: doc

Reference pages for the eight detection algorithms and nine visualization views shipped today.
:::

::::

## At a glance

| Surface | Count | Location |
|---|---|---|
| Detection algorithms | **8** | `algorithms/` |
| CLI subcommands | **20** | `cli.py` |
| FastAPI routers | **12** + WebSocket | `api/routers/` |
| MCP tools | **15** | `mcp_server/` |
| Exporters | YARA · JSON · Volatility3 | `architect/` |
| Dump backends | `memslicer` · `lldb` · `fridump` | `core/dump_driver.py` |
| Visualization views | 4 SPA + 5 research-mode (Marimo) | `frontend/` + `ui/` |

Under the hood: DuckDB `ProjectDB`, `.memdiver` `SessionStore`, Welford incremental consensus, Aho-Corasick multi-pattern scan, Kaitai Struct parsing, ASLR-aware region alignment, auto-discovered KDF plugins, BYO decryption oracles, first-class Volatility3 plugin emission.

```{toctree}
:maxdepth: 2
:caption: Getting started
:hidden:

quickstart/index
```

```{toctree}
:maxdepth: 2
:caption: User guide
:hidden:

user_guide/web_ui_tour
user_guide/cli_reference
user_guide/mcp_reference
```

```{toctree}
:maxdepth: 2
:caption: Architecture
:hidden:

architecture/index
```

```{toctree}
:maxdepth: 1
:caption: Reference
:hidden:

algorithms/index
visualizations/index
file_formats/msl_v1_1_0
file_formats/dataset_layout
oracle/interface
oracle/examples
api_reference/index
```

```{toctree}
:maxdepth: 1
:caption: Project
:hidden:

contributing/index
release_notes
languages/index
```
