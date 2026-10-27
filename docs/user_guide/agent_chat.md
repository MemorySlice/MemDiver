# Agent chat panel

The agent chat panel is a chat column in the web workspace where you ask Claude questions about the open case and dumps. The model works through MemDiver's own MCP tools (the same ones an external agent gets, see [](mcp_reference.md)); the panel is a **client of the MCP server**, not a new analysis surface. It uses the Claude Agent SDK, but removes every built-in tool: the model has **no shell, no file and no web tools**, only `mcp__memdiver__*` tools.

The panel is an optional extra and is off until the SDK is installed and credentials are configured on the server.

## Install

```bash
pip install "memdiver[agent]"
```

The extra installs `claude-agent-sdk`, which bundles the Claude Code runtime it drives. No Node.js is needed. If the SDK is missing the panel shows an install hint; if the bundled runtime is missing, reinstall with `pip install --force-reinstall "memdiver[agent]"`.

## Credentials

Credentials are read from the **server environment only**, never from the browser and never stored by MemDiver. Set one of these before starting `memdiver web`, then restart:

- `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`)
- `CLAUDE_CODE_USE_BEDROCK=1`, `CLAUDE_CODE_USE_VERTEX=1` or `CLAUDE_CODE_USE_FOUNDRY=1`, plus that platform's own environment

Signing in with a claude.ai account is not supported: third-party applications may not offer it. `GET /api/agent/status` reports `{available, backend, credentials}` and never any secret value.

## Security model

- **Read tools run automatically; write tools need your approval.** The READ/WRITE split is derived from each tool's parameters (`mcp_server/tool_policy.py`): a tool with a write-path parameter, a case parameter (outside the read-only case tools) or a parameter that executes, compiles or loads caller-supplied code or rules, or picks an executable (`CODE_EXEC_KEYS`: `source`, `plugin_path`, `plugin_source`, `oracle_path`, `source_name`, `vol_bin`, `vol_python`, `rule_source`, `rule_paths`, `rules`) is WRITE. A few tools without such a parameter are listed explicitly with a reason (`image_profile` runs pakunoda and writes the ISF cache; `analyze_candidates` writes the project database). `set_region_filter` stays READ: it only changes in-memory session state. A tool the policy does not know is treated as WRITE. Currently 65 tools are READ and 55 are WRITE (including `capture_dump`, which is never offered).
- **Approval scopes.** An approval card shows the full tool input and offers **Allow once**, **Allow for this chat** (that tool, until the chat ends) and **Deny**, with an optional note to the model. "Allow for this chat" is keyed by tool name only, so it is offered **only for WRITE tools that do not run caller-supplied code**. Tools with a `CODE_EXEC_KEYS` parameter (`verify_vol3_plugin`, `vol3_run`, `brute_force`, `scan_yara_rule`, ...) are once-only: the card has no chat button, the server sends `scopes: ["once"]`, and a chat-scoped answer is treated as once, so every call with new code or a new binary prompts again. Unanswered approvals are denied when the chat closes.
- With the optional result budget (`MEMDIVER_MCP_RESULT_BUDGET`), an oversized structured error keeps its `error` and `code` but has its long strings truncated and carries `_result_budget`; small errors are unchanged.
- **`capture_dump` is never available** to the chat, even with approval. Start captures from the Capture UI.
- The model runs with `permission_mode="default"`, no project or user Claude settings, and its own config directory under the MemDiver home.
- The MCP child is started **sandboxed**. Its read roots are `MEMDIVER_ALLOWED_ROOTS` if you set it, otherwise the MemDiver home, the upload directory, the chat's case directory and the parent directory of each dump passed to the chat. Writes stay confined to the MemDiver home and the upload directory (see [](sandbox.md)).
- **Credentials are not passed to the MCP child**: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `MEMDIVER_API_TOKEN` are removed from its environment.
- The chat **refuses to run on a non-loopback bind without `MEMDIVER_API_TOKEN`**. `MEMDIVER_ALLOW_INSECURE=1` does not lift this rule. With a token set, the WebSocket needs `?token=` as `/ws/tasks` does.
- **Prompt injection:** tool results and dump contents are attacker-controllable data (strings in memory, process names, ISF text). The system prompt tells the model to treat them as data, never instructions, and write tools always need your click. Read every approval card before allowing.

## Settings

Stored server-side per user (`GET`/`PUT /api/agent/settings`). Defaults are deliberately low; raise them in the panel's Settings form. Out-of-range values are rejected (422).

| Setting | Default | Allowed |
|---|---|---|
| Model | `claude-opus-5-5` | `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5` |
| Effort | `low` | `low`, `medium`, `high` |
| Max turns | 8 | 1 to 200 |
| Max budget (USD) | 0.50 | 0.05 to 50 |
| Result budget (bytes) | 20000 | 2000 to 500000 |

Max budget is an **SDK-side estimate** and can overshoot; the meter labels cost as estimated. The result budget is passed to the MCP child as `MEMDIVER_MCP_RESULT_BUDGET`: a tool result above it is shrunk (lists keep their first items with `<key>__truncated: {kept, total}`, the largest values become `{"omitted_bytes": n}`, text is cut with a marker line) and always carries a top-level `_result_budget` object. The tool-call card shows a `truncated` badge, and the model is told to narrow the call (`limit`/`offset`, `detail="summary"`, `case_query`) instead of repeating it. See [](mcp_reference.md).

## Evidence labels

The system prompt requires every factual claim to be tagged `[seen]` (cite the tool and the offset, row or run id), `[inferred]` (state the reasoning) or `[unknown]`. "Not found" means unknown, never absent, and uncaptured bytes are absent, not zero. The panel highlights the tags. The point is to keep model claims separable from tool evidence in a forensic context.

The prompt's output and budget rules are adapted from ideas in [leanrea](https://github.com/aicodeking/leanrea): capped outputs with expansion handles, evidence labels, a call budget, and cheap recon first (`case_manifest`, `case_schema`, then `case_query`) before expensive tools.

## Using the panel

- **Start chat** opens a chat bound to the open case and dumps; **End chat** closes it. Enter sends, Shift+Enter adds a line, **Interrupt** stops the running turn.
- **Start from playbook** lists the MCP playbooks, fills in their arguments and puts the rendered text in the composer. The chosen playbook text travels in the first user message, not the system prompt.
- Tool calls appear as collapsible cards labelled read or write. Results that name a dump plus a `va` or `offset` get an **Open in hex** link (up to 10 per result); it works only for dumps open in the workspace.

## Demo and test backend (no model)

`MEMDIVER_AGENT_BACKEND=scripted` replaces the model with a scripted stand-in for the Claude Code runtime. **There is no model, no API key and no network**; tools still run for real on the sandboxed MCP server, and approvals go through the real gate. The panel shows a "Demo/test backend" badge.

```bash
MEMDIVER_AGENT_BACKEND=scripted MEMDIVER_AGENT_SCRIPT=demo.json memdiver web
```

```json
{"turns": [
  [{"text": "Checking the case."},
   {"tool": "case_manifest", "input": {"case_dir": "/path/to/case"}},
   {"text": "Done. [seen] manifest above."}],
  [{"text": "Second message reply."}]
]}
```

Each inner list is the reply to one user message; each step (`text` or `tool`) counts as one turn against Max turns. Tool names may omit the `mcp__memdiver__` prefix. Further messages get `(script exhausted)`. `MEMDIVER_AGENT_BACKEND` accepts `sdk` (default) or `scripted`; the scripted backend is unavailable without `MEMDIVER_AGENT_SCRIPT`. See [](configuration.md).

## Limits

- One WebSocket per chat (a second attach is rejected with `already_attached`); the browser does not reconnect automatically, so a dropped connection ends the chat.
- At most 4 open chats.
- A chat that no WebSocket attaches to within 120 s is closed.
- One turn at a time; a message sent while busy gets a `busy` error.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| 503 on creating a chat, or the panel banner | Runtime unavailable: SDK not installed (`pip install "memdiver[agent]"`), unknown `MEMDIVER_AGENT_BACKEND`, or scripted backend without `MEMDIVER_AGENT_SCRIPT`. |
| Banner says no credentials | Set `ANTHROPIC_API_KEY` or a Bedrock/Vertex/Foundry flag in the server environment and restart. |
| 403 | Non-loopback bind without `MEMDIVER_API_TOKEN`. Set a token or bind loopback. |
| 429 | 4 chats are already open; end one. |
| 422 | A path (case or dump) does not exist, or a setting is out of bounds. |
