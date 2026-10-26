# MCP server quickstart

MemDiver ships a first-class Model Context Protocol (MCP) server. It exposes **120 tools** (list them with your client's tool picker, or `tools/list`), **8 playbook prompts** and **4 case resources** to MCP-speaking agents (Claude Code, Claude Desktop, Cursor, Continue) over stdio or SSE transports.

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

Restart the MCP client. The MemDiver tools appear in the tool picker.

## Playbooks: start with `memdiver_start`

The server publishes MCP prompts: numbered, copy-able procedures that name the exact tools, the checks to make on each result, and the traps hit on real data. Fetch `memdiver_start` first (what MemDiver is, the playbook list, the resources, the conventions), then the one that fits your task: `vol3_inside_memdiver`, `vol3_plugin_dev`, `isf_workbench`, `image_to_process_keys`, `n_image_variance`, `object_model_from_keylog`, `code_evidence`. Arguments, URIs and the case resources are listed in [](../user_guide/mcp_reference.md).

Working on a full memory image rather than a dump? See [](image.md), [](../user_guide/vol3.md), [](../user_guide/isf_workbench.md), [](../user_guide/keyfinders.md) and [](../user_guide/object_model.md).

## Tool catalogue

See [](../user_guide/mcp_reference.md) for the full list of tools, input schemas, and example prompts.

## Security notes

- Set `MEMDIVER_ALLOWED_ROOTS` to confine every path the agent can read or write; see [](../user_guide/sandbox.md).
- The MCP server is **local-only**. No authentication is performed; do not expose the SSE port to untrusted networks.
- Tools that load user Python (`brute_force`, `n_sweep`) call through `engine.oracle.load_oracle`, which refuses world-writable paths and prints a sha256 fingerprint of the loaded oracle on stderr.
