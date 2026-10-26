# Path sandbox

By default MemDiver is a local tool: the CLI and the MCP server read and write wherever your shell can, and the REST API trusts its (localhost) client for reads. Set `MEMDIVER_ALLOWED_ROOTS` to turn on an **opt-in read sandbox** for every surface that takes a client-supplied path, for example when an agent drives the MCP server or the web UI is reachable by others.

```bash
export MEMDIVER_ALLOWED_ROOTS="/data/dumps:/data/images"   # os.pathsep-separated (';' on Windows)
memdiver web        # or: memdiver mcp
```

Unset (the default) means the policy is OFF and nothing below applies to reads.

## What it covers

When the variable is set, a path must resolve (symlinks followed) inside an admitted root:

- every REST path parameter and body field (query params and JSON keys, at any depth, including mapping keys such as `needles={dump_path: hex}`);
- every MCP tool argument that names a path (`dump_path`, `msl_path`, `image_path`, `view_path`, `case_dir`, `keylog_path`, `oracle_path`, ...);
- the MCP resources `memdiver://case/{case_dir}/...` ([](mcp_reference.md));
- session save and load.

A bare case name (for `case_dir`) or a sha256 (`capture_id`) is not a path and is admitted as is; only a path-shaped value is checked.

## Admitted roots

The roots you configure, plus these implicit ones whenever the sandbox is ON:

- the directory the server was started in (captured once at startup);
- the system temp directory and `$TMPDIR`;
- the loaded dataset root (configured `dataset_root` or the one you opened);
- the upload directory and the MemDiver home (`~/.memdiver`);
- the file-browser favourites.

## A denial and how to admit a path

REST returns `403`; MCP tools and resources return the usual JSON error with `code=path.outside_sandbox`:

```text
read path '/srv/x.msl' is outside the read sandbox (MEMDIVER_ALLOWED_ROOTS is set).
Admitted roots: ... To admit it, add its directory to MEMDIVER_ALLOWED_ROOTS
(os.pathsep-separated), or add it as a favourite in the file browser.
```

Fix the path or admit the directory; do not retry the same call.

## Write confinement

- **REST** always confines its writes, with or without the sandbox: to the MemDiver home and the upload directory, or per endpoint to a case root.
- **MCP, sandbox ON**: output paths (`out_path`, `output_path`, `out_dir`, `output_dir`, `candidates_out`, `output`) must lie in the same write roots (MemDiver home plus upload dir). A path-shaped `case_dir` of a case-**writing** tool is confined the same way. Read-only case tools (`case_status`, `case_manifest`, `case_schema`, `case_query`, `context_at`, `annotations_list`, `isf_draft_get`, `vol3_query`, ... the set `CASE_READ_ONLY_TOOLS` in `mcp_server/path_guard.py`) only need a read root. `case_init`'s `case` is treated the same way (bare name or write-root path). A bare `case_dir` is resolved the way `Case.open` does: an existing `<startup cwd>/<name>/case.json` wins over `~/.memdiver/cases/<name>`, and the RESOLVED directory is what is confined (write roots for writing tools, read roots for read-only ones). `case_manifest` does not stat image paths outside the read roots (`exists: null` plus a warning). REST `POST /api/experiment/capture` confines a client `output` the same way.
- **Sandbox OFF**: the CLI and MCP write wherever the operator's shell can. The sandbox is not a defence for that mode. Tools never overwrite: an `out_path` must be a new file.

## For contributors

Which argument names carry paths is one shared list in `core/path_sandbox.py`: `READ_PATH_KEYS` and `WRITE_PATH_KEYS` (plus the mapping-key sets). `tests/test_path_key_coverage.py` fails when a REST or MCP parameter looks like a path but is in neither set. A new path parameter must be added to the right one, or it bypasses the sandbox.

See also [](configuration.md) for the full environment-variable table.
