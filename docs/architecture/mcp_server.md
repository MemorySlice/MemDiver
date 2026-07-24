# mcp_server/

Model Context Protocol server built on `FastMCP` (official Python SDK). Exposes 15 tools — no resources, no prompts.

- `server.py` — registers `@mcp.tool` handlers, delegating to the surface-agnostic **producers** in the [`app/`](app.md) layer.
- `presenters.py` — the MCP presenter: turns a producer's `ServiceResult` into the MCP tool response (inlining any lock diagnostic with the MCP parameter names).
- `session.py` — re-export shim for `memdiver.app.session.ToolSession` (dataset root, scan cache, protocol version).
- `tools.py`, `tools_inspect.py`, `tools_xref.py`, `tools_pipeline.py` — **re-export shims**. The producers moved to `memdiver.app.*` in the presentation-separation refactor; each of these modules now just aliases itself to the relocated `memdiver.app.<module>` so existing `memdiver.mcp_server.tools_inspect` imports keep working. Prefer importing from `memdiver.app.*` (or the public `memdiver.services` facade) in new code.
- Transport: `stdio` by default; `--sse --port` for Server-Sent Events.
- No authentication (local-only). SSE port must not be exposed publicly.
- Shares `api.services.reader_cache` for dump/MSL caching.

Tool catalogue: see [](../user_guide/mcp_reference.md).
