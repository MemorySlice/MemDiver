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
pip install memdiver                 # everything: CLI, library, web UI, MCP server,
                                     # pcap oracle, dump collection, post-quantum KEM
pip install "memdiver[marimo]"       # + Marimo notebook UI (memdiver ui) -- the one opt-in interface
pip install "memdiver[all]"          # every interface (= the default install + marimo)
pip install "memdiver[docs]"         # + Sphinx toolchain for building this site
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

LLDB is installed via the operating system (Xcode on macOS, `apt install lldb` on Debian/Ubuntu). `memdiver experiment` exits gracefully with an install hint when no backend is present.

```{toctree}
:hidden:

web
cli
mcp
experiment
library
```
