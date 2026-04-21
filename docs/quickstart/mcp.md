# MCP server quickstart

MemDiver ships a first-class Model Context Protocol (MCP) server. It exposes **15 analysis tools** to MCP-speaking agents (Claude Code, Claude Desktop, Cursor, Continue) over stdio or SSE transports.

## Stdio (default — recommended for Claude Desktop / Claude Code)

```bash
memdiver mcp
```

## Server-Sent Events transport

```bash
memdiver mcp --sse --port 8080
```

## Claude Desktop / Claude Code configuration

Add this block to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS / editor:

```json
{
  "mcpServers": {
    "memdiver": {
      "command": "memdiver",
      "args": ["mcp"]
    }
  }
}
```

Restart the MCP client. The 15 MemDiver tools appear in the tool picker.

## Tool catalogue

See [](../user_guide/mcp_reference.md) for the full list of tools, input schemas, and example prompts.

## Security notes

- The MCP server is **local-only**. No authentication is performed; do not expose the SSE port to untrusted networks.
- Tools that load user Python (`brute_force`, `n_sweep`) call through `engine.oracle.load_oracle`, which refuses world-writable paths and prints a sha256 fingerprint of the loaded oracle on stderr.
