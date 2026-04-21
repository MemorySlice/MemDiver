# Architecture

MemDiver is composed of eleven subsystems. The web UI, CLI, and MCP server all route through the same analysis engine — there is no "GUI-only" or "CLI-only" capability.

```{mermaid}
flowchart TB
    subgraph UX
        Web[React SPA<br/>4 wired views + 7 feature panels]
        CLI[memdiver CLI<br/>20 subcommands]
        MCP[MCP server<br/>15 tools]
        Marimo[Marimo sandbox<br/>+5 research views]
        Nice[NiceGUI shell<br/>legacy]
    end
    subgraph API[FastAPI · 12 routers + WS]
        Routers[dataset · analysis · inspect ·<br/>sessions · tasks · dumps · path ·<br/>structures · architect · consensus ·<br/>oracles · pipeline]
    end
    subgraph Engine[Engine &amp; Algorithms]
        Pipeline[pipeline · pipeline_runner]
        Consensus[ConsensusVector<br/>Welford · MSL-aware]
        Oracle[BYO oracle<br/>sha256 audit]
        Algos[8 algorithms<br/>auto-discovered]
        Architect[Pattern Architect<br/>YARA · JSON · Vol3]
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
    Engine --> Harvester
    Harvester --> MSL
    Engine --> ProjectDB
    Engine --> Sessions
```

```{toctree}
:hidden:

core
engine
harvester
msl
architect
algorithms
api
mcp_server
ui
frontend
```
