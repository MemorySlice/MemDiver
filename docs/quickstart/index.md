# Quick start

Four ways to run MemDiver, ordered by increasing scope.

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
::::

## Install

```bash
pip install memdiver                 # web UI + CLI + MCP server (everything runtime-side)
pip install "memdiver[experiment]"   # + frida-tools, memslicer for dump collection
pip install "memdiver[docs]"         # + Sphinx toolchain for building this site
pip install "memdiver[dev]"          # + pytest and contributor tooling
```

LLDB is installed via the operating system (Xcode on macOS, `apt install lldb` on Debian/Ubuntu). `memdiver experiment` exits gracefully with an install hint when no backend is present.

```{toctree}
:hidden:

web
cli
mcp
experiment
```
