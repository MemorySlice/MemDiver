# Quick start

Five ways to use MemDiver, ordered by increasing scope.

::::{grid} 2
:gutter: 3

:::{grid-item-card} Web UI
:link: web
:link-type: doc

Launch the FastAPI + React dockable workspace on `http://127.0.0.1:8080` with a single command.
:::

:::{grid-item-card} Command line
:link: cli
:link-type: doc

Run one-shot analysis, batch jobs, and pipeline stages from the terminal.
:::

:::{grid-item-card} MCP server
:link: mcp
:link-type: doc

Expose 15 analysis tools to Claude Code, Claude Desktop, or any MCP-speaking agent.
:::

:::{grid-item-card} Experiment harness
:link: experiment
:link-type: doc

Spawn target processes and collect memory dumps via `memslicer`, `lldb`, or `fridump` backends.
:::

:::{grid-item-card} Python library
:link: library
:link-type: doc

`import memdiver` — open dumps, convert to `.msl`, parse containers, and run analysis programmatically.
:::
::::

## Install

```bash
pip install memdiver                 # lean core: CLI + Python library (import memdiver)
pip install "memdiver[api]"          # + FastAPI/uvicorn web UI & REST API (memdiver web)
pip install "memdiver[mcp]"          # + MCP server for AI agents (memdiver mcp)
pip install "memdiver[all]"          # every interface (api + mcp + nicegui + marimo)
pip install "memdiver[experiment]"   # + frida-tools, memslicer for dump collection
pip install "memdiver[docs]"         # + Sphinx toolchain for building this site
pip install "memdiver[dev]"          # + pytest and contributor tooling
```

The web UI (`api`), MCP server (`mcp`), and the legacy NiceGUI (`nicegui`) / Marimo (`marimo`)
UIs are opt-in extras — a plain `pip install memdiver` keeps the library/CLI footprint small.

LLDB is installed via the operating system (Xcode on macOS, `apt install lldb` on Debian/Ubuntu). `memdiver experiment` exits gracefully with an install hint when no backend is present.

```{toctree}
:hidden:

web
cli
mcp
experiment
library
```
