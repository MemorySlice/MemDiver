# app/

The **application / producer layer** — surface-agnostic services shared by every
MemDiver surface (the Python library, the CLI, the FastAPI web app, and the MCP
server). Relocated from `mcp_server/` in the presentation-separation refactor so
no surface owns the compute.

## What a producer is

Every user-facing capability is backed by exactly one **producer**: a plain Python
function that performs the compute and knows nothing about how the result will be
displayed. There is no `report_key_status`-style presentation flag in a producer;
each surface is a thin *presenter* that routes to the same producer and renders the
outcome in its own idiom. This is what lets the surfaces disagree on *presentation*
without ever forking the *compute*.

Modules:

- `tools_inspect.py` — the `*_result` inspect producers: `read_hex_result`,
  `read_hex_raw_result`, `resolve_va_result`, `search_bytes_result`,
  `entropy_result`, `strings_result`, `detect_format_result`,
  `session_info_result`, `page_states_result`, `processes_result`,
  `modules_result`, `handles_result`, `connections_result`,
  `module_index_result`, `blocks_result`. (The legacy `read_hex` / `get_*`
  dict-returning siblings are kept only as deprecated backward-compat shims.)
- `tools_xref.py` — `get_cross_references_result`, `identify_structure_result`,
  `apply_structure_result`.
- `tools_pipeline.py` — the pipeline stages (`consensus`, `search_reduce`,
  `brute_force`, `n_sweep`, `auto_floor`, `emit_plugin`, `export_pattern`) plus
  `verify_key_result` and `experiment_result`.
- `tools.py` — dataset / analysis producers: `scan_dataset`, `list_protocols`,
  `list_phases`, `analyze_library`, `import_dump`.
- `session.py` — `ToolSession`, the stateful context (dataset root, scan cache,
  protocol version) passed to the inspect / xref / dataset producers.
- `capabilities.py` — the declarative `Capability(name, producer, surfaces)`
  registry that maps each capability to its producer and the surfaces wired to
  it. `tests/test_architecture_invariants.py` consumes it as a **parity ratchet**.

## The ServiceResult / CapabilityError contract

- The `*_result` producers return a
  {class}`~memdiver.core.service_result.ServiceResult`: a `payload` (the data) plus
  a `status` {class}`~memdiver.core.service_result.StatusBlock` that carries
  key/decrypt state. An encrypted dump opened without a valid key is reported
  explicitly through `status.key` / `status.resolution` — it never masquerades as
  a genuinely empty result.
- The pipeline / dataset producers return their native payloads (JSON-able dicts,
  written-artefact paths).
- Hard errors are **raised** as
  {class}`~memdiver.core.service_errors.CapabilityError` subclasses
  (`FileNotFoundServiceError`, `OffsetOutOfRangeError`, `UnsupportedFormatError`,
  `EncryptedDumpLockedError`, …) — never returned as `{"error": ...}` dicts. Each
  surface funnels that single typed error into its own idiom (HTTP status, MCP
  error JSON, CLI exit code).

## The per-surface presenter model

```
                       app/ producer  ──►  ServiceResult / raises CapabilityError
                             │
      ┌──────────────┬───────┴────────┬───────────────┐
      ▼              ▼                ▼               ▼
 library         CLI presenter   web presenter    MCP presenter
 (services.py:   (cli.py)        (api/routers/*)  (mcp_server/
  ServiceResult                                    presenters.py)
  as-is)
```

- **Library** — `memdiver.services` re-exports the producers directly, so a library
  user receives the `ServiceResult` unchanged. See
  [Library quickstart](../quickstart/library.md).
- **CLI** — `present_inspect_cli` (and siblings) turn the result into
  `(payload, exit_code, stderr_msg)`, inlining any lock diagnostic augmented with
  the CLI flag names.
- **Web** — the API routers return the `payload`; a locked read reads back empty
  (the API's empty-means-locked contract) and hard errors become HTTP status codes
  at the single exception handler.
- **MCP** — `present_inspect_mcp` inlines the lock diagnostic augmented with the MCP
  parameter names.

Because all four presenters consume the *same* producer output, the neutral
surface-agnostic hint text lives in the producer's status block, while each
surface's remedy wording (CLI flags vs. MCP parameters) lives in its own presenter.

## Parity

`app/capabilities.py` records which surfaces are wired to each producer, and the
`test_cross_surface_capability_parity` ratchet holds every capability to every
in-scope surface (`library`, `cli`, `web`, `mcp`) except a documented, non-stale
set of gaps. For the **library** surface, "wired" means *re-exported through the
public `memdiver.services` facade* — not merely importable from a deep
`memdiver.app.*` module.
