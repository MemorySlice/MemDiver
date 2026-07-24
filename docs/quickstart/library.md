# Library quickstart

Beyond the CLI, web UI, and MCP server, MemDiver can be used as a **Python library**.
After installation the top-level `memdiver` package re-exports a supported public API for
opening dumps, converting them to the `.msl` container format, parsing containers, and
running analysis — without reaching into internal modules.

The library is at **full feature parity** with the other surfaces: the same
surface-agnostic producers that back the CLI, web, and MCP surfaces are re-exported under
`memdiver.services` (and the most-used ones are lifted onto the `memdiver` top level). See
[Structured services](#structured-services-full-feature-parity) below.

```bash
pip install memdiver   # lean: pulls only the library/CLI core, not the web/MCP/UI stack
```

The plain install is all a library user needs — the FastAPI web UI, MCP server, and the
Marimo UI live behind the `[api]`, `[mcp]`, `[marimo]` extras.

```python
import memdiver
print(memdiver.__version__)
print(memdiver.__all__)   # the supported public surface
```

:::{note}
Only the names in `memdiver.__all__` are the supported API. Everything else under
`memdiver.*` (e.g. `memdiver.api`, `memdiver.engine.*` internals) is an implementation
detail and may change between releases.
:::

## Open a dump

`open_dump()` auto-detects the format (raw / ELF core / gdb-raw / lldb-raw / `.msl`) and
returns a context-managed `DumpSource`. Key material transparently decrypts an encrypted
`.msl` (spec §10) and is ignored for other formats.

```python
from pathlib import Path
import memdiver

with memdiver.open_dump(Path("capture.msl")) as src:
    print(src.format_name, src.size)
    chunk = src.read_range(0x1000, 256)          # bytes at a memory offset
    hits = src.find_all(b"BEGIN PRIVATE KEY")    # list of offsets

# Encrypted container — key / passphrase / kem_private_key are bytes:
with memdiver.open_dump(Path("secret.msl"), passphrase=b"hunter2") as src:
    data = src.read_all()
```

`read_range`/`read_all`/`find_all`/`size` also accept a `view` argument (`"raw"` or
`"vas"`) to switch between the file bytes and the flattened captured-memory projection.

## Import a raw dump into `.msl`

```python
from pathlib import Path
import memdiver

result = memdiver.import_dump(Path("core.1234"), Path("capture.msl"), pid=1234)
print(result)   # ImportResult

# Format-specific entry points are also exported:
# memdiver.import_elf_core, memdiver.import_minidump, memdiver.import_run_directory
```

Need to sniff a format without importing? `detect_format(head_bytes)` returns the detected
format name:

```python
import memdiver
fmt = memdiver.detect_format(open("core.1234", "rb").read(512))
```

## Parse an `.msl` container directly

`MslReader` is a memory-mapped, context-managed parser exposing structured collectors:

```python
from pathlib import Path
import memdiver

with memdiver.MslReader(Path("capture.msl")) as reader:
    header  = reader.file_header()
    modules = reader.collect_modules()
    procs   = reader.collect_processes()
    hints   = reader.collect_key_hints()
    for hdr, payload in reader.iter_blocks():
        ...
```

Read minidumps directly (no `.msl` conversion) with `MinidumpReader`, and write containers
with `MslWriter`.

## Run auto-floor analysis

`run_auto_floor()` computes the ground-truth-free variance-floor verdict. It needs a
precomputed variance array, the reference dump bytes, the number of dumps, and an oracle
callback (see `memdiver.AutoFloorResult` for the return shape):

```python
import memdiver
result = memdiver.run_auto_floor(variance, reference_data, num_dumps, oracle, ...)
print(result)   # AutoFloorResult
```

`run_auto_floor` is the low-level primitive for when you already hold a variance array and
an oracle. For the full end-to-end orchestration (consensus/variance construction,
candidate reduction, oracle wiring) — the same compute the CLI's `auto-floor` subcommand
runs — call the `memdiver.services.auto_floor` producer described next.

(structured-services-full-feature-parity)=
## Structured services (full feature parity)

Every MemDiver capability is backed by one **producer** function shared by all surfaces.
The library reaches the whole set through `memdiver.services` (and the most-used producers
are lifted onto the top level, e.g. `memdiver.session_info_result`). This is the same
compute the CLI/web/MCP presenters route to — the library is not a reduced subset.

The `*_result` producers return a `ServiceResult`: a `payload` plus a `status` block that
records key/decrypt state, so an encrypted-but-locked dump is reported explicitly instead
of masquerading as an empty result. Hard errors raise a `memdiver.CapabilityError`
subclass rather than returning an `{"error": ...}` dict.

```python
import memdiver

# The inspect / xref / dataset producers take a ToolSession (it caches
# dataset scans across calls); pipeline / verify / experiment are keyword-only.
session = memdiver.ToolSession()

result = memdiver.session_info_result(session, "capture.msl")
# equivalently: memdiver.services.session_info_result(session, "capture.msl")

if result.status.key.decrypted:
    print(result.payload["region_count"])   # the data
else:
    # Encrypted dump we could not open — surfaced, not silently empty.
    print(result.status.key.hint)            # neutral, surface-agnostic hint

# Encrypted container: pass key material just like the CLI flags do.
locked = memdiver.session_info_result(session, "secret.msl", passphrase="hunter2")
```

Handling hard errors:

```python
import memdiver

session = memdiver.ToolSession()
try:
    memdiver.entropy_result(session, "/does/not/exist.dump")
except memdiver.CapabilityError as exc:
    print(exc.category, exc)   # single typed error funnel across all surfaces
```

The pipeline / verify / experiment producers are keyword-only and return their native
payloads (JSON-able dicts / written-artefact paths):

```python
import memdiver

report = memdiver.consensus(dump_paths=["a.msl", "b.msl"], output_dir="out/")
sweep  = memdiver.n_sweep(source_paths=["a.msl", "b.msl"], oracle_path="oracle.py",
                          output_dir="out/", n_values=[2, 4])
```

`memdiver.services.__all__` lists every producer available on the library surface.

## Dependency notes

The base install is lean: `pip install memdiver` pulls only the library + CLI core (numpy,
the container codecs, the crypto stack, DuckDB/Polars for analysis) — **not** the web/MCP/UI
stack. The FastAPI web UI (`[api]`), MCP server (`[mcp]`), and the Marimo (`[marimo]`)
UI are opt-in extras (`[all]` installs every interface). The
dependency-light building blocks — `memdiver.detect_format`, `memdiver.MslReader`,
`memdiver.MinidumpReader` — only need `numpy` and the container codecs at runtime.
