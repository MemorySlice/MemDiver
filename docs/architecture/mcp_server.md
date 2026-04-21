# mcp_server/

Model Context Protocol server built on `FastMCP` (official Python SDK). Exposes 15 tools — no resources, no prompts.

- `server.py` — registers `@mcp.tool` handlers, delegating to pure functions under `tools.py`, `tools_inspect.py`, `tools_xref.py`, `tools_pipeline.py`.
- `session.py` — module-level `ToolSession` cache (dataset root, scan cache, protocol version).
- Transport: `stdio` by default; `--sse --port` for Server-Sent Events.
- No authentication (local-only). SSE port must not be exposed publicly.
- Shares `api.services.reader_cache` for dump/MSL caching.

Tool catalogue: see [](../user_guide/mcp_reference.md).
