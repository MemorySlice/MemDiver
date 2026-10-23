# Architecture

MemDiver is composed of eleven subsystems. The web UI, CLI, and MCP server all route through the same analysis engine — there is no "GUI-only" or "CLI-only" capability.

The allocator layer (`heap/`) sits beside the engine. It parses a dump's heap
into chunks, free lists and per-byte roles, and the engine projects those roles
onto consensus and candidates. See [heap/](heap.md).

```{mermaid}
flowchart TB
    subgraph UX
        Web[React SPA<br/>4 wired views + 7 feature panels]
        CLI[memdiver CLI<br/>35 subcommands]
        MCP[MCP server<br/>56 tools]
        Marimo[Marimo sandbox<br/>+5 research views]
    end
    subgraph API[FastAPI · 19 routers + WS]
        Routers[dataset · analysis · inspect ·<br/>sessions · tasks · dumps · path ·<br/>structures · architect · consensus ·<br/>oracles · pipeline · heap]
    end
    subgraph Engine[Engine &amp; Algorithms]
        Pipeline[pipeline · pipeline_runner]
        Consensus[ConsensusVector<br/>Welford · MSL-aware]
        Oracle[BYO oracle<br/>sha256 audit]
        Algos[8 algorithms<br/>auto-discovered]
        Architect[Pattern Architect<br/>YARA · JSON · Vol3]
        Heap[heap<br/>allocator detect · chunk walk · byte roles]
    end
    subgraph Storage[Storage &amp; IO]
        Harvester[harvester<br/>ingestor · sidecar · metadata]
        MSL[msl<br/>reader · writer · importer]
        ProjectDB[DuckDB ProjectDB]
        Sessions[.memdiver SessionStore]
    end
    Web --> API
    CLI --> Engine
    MCP --> Engine
    Marimo --> Engine
    Nice --> API
    API --> Engine
    Engine --> Algos
    Engine --> Oracle
    Engine --> Architect
    Engine --> Heap
    Engine --> Harvester
    Harvester --> MSL
    Engine --> ProjectDB
    Engine --> Sessions
```

```{toctree}
:hidden:

core
app
engine
harvester
msl
architect
algorithms
api
mcp_server
heap
ui
frontend
```
