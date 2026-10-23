# CLI reference

MemDiver exposes a single `memdiver` console script with the subcommands listed below. This page is auto-generated from the argparse parser — every flag listed here matches the installed version.

```{admonition} Common flags
:class: tip

Most subcommands accept:

- `-v`, `--verbose` — enable DEBUG logging.
- `-o PATH`, `--output PATH` — write JSON results to *PATH*.

The `experiment` subcommand's Python dependencies (`frida-tools` + `memslicer`) ship in the default `pip install memdiver`. What pip cannot provide is the runtime side: Frida needs an attachable target process, and the LLDB backend is installed via your OS package manager.
```

```{admonition} Dump-path arguments
:class: note

Commands that take several dump paths (`consensus`, `scan-yara`, `export`, `locate-key`, …) accept files and directories. A directory is expanded to the `*.dump`, `*.msl`, `*.gcore.core`, `*.core`, `*gdb_raw.bin` and `*lldb_raw.bin` files directly inside it. Neither kind of omission is silent:

- A path that does not exist prints `memdiver: WARNING — skipping non-existent path: PATH` on stderr and is skipped. `locate-key` is the exception: there a missing path is an error (exit `2`, no payload), see [Locating a known key](locate_key.md#dump-inputs).
- Other files in a directory print one `memdiver: note — skipped N file(s) in DIR with unrecognised extensions (e.g. …)` line per directory. Dotfiles and common sidecars (`.json`, `.txt`, `.log`, `.pcap`, `.pcapng`, `.yar`, `.yara`, `.npy`, `.md`) are not counted. Pass a file by name to include it.
```

```{admonition} Import region selection (`import`, `import-dir`)
:class: note

By default `memdiver import` / `import-dir` import **every** region, exactly as before. Region flags narrow that:

- `--regions LIST|all` — keep only these categories, e.g. `--regions heap,stack`. Categories: `heap`, `stack`, `image_code`, `image_data`, `mapped_file`, `shared`, `unclassified`, `runtime` (alias `image` = `image_code,image_data`).
- `--exclude-regions LIST` — drop categories (alone: everything except LIST).
- `--list-regions` — dry run: per-category region counts and bytes (every region with `-v`, JSON with `--json`); nothing is written. When the platform is known the report starts with a `platform:` line, e.g. `platform: android (mapping_names)` or `platform: linux (format)`, and the category table has a `runtime` row (number `8`). A note line states how many regions and bytes are classified `runtime` and therefore dropped by the default selection.
- `--materialize` — `.msl` input only. A `.msl` is otherwise copied **verbatim** and the selection is applied at analysis time; with `--materialize` a filtered copy holding only the selected regions is written.
- `-y`, `--yes` — never prompt. This is the non-interactive behaviour: import everything unless `--regions` / `--exclude-regions` is given. It does *not* accept the interactive preselection.

**The `runtime` category.** `runtime` holds regions that are classified **by mapping name** as runtime or system memory rather than app data: on Android the zygote / boot-image ART spaces, ART GC metadata, JIT caches, `linker_alloc`, `cfi shadow` and property areas; on Android and Linux the kernel mappings (`[vdso]`, `[vvar]`, `[vsyscall]`, …) and device mappings (`/dev/*` other than binder / shm / zero, `/dmabuf*`, `anon_inode:*`). It is **not** in the default selection and is never preselected in the prompt (number `8`); name it (`--regions heap,stack,runtime`) or use `all` to keep it. Name classification needs mapping names: ELF cores and raw dumps with a maps sidecar have them, and so do live memslicer captures that store a VAS map. Older `.msl` files without stored names classify exactly as before. The full rules are in the [`.msl` specification](../file_formats/msl_v1_1_0.md#mapping-name-classification). A selection stored before `runtime` existed (a provenance note or a filter that names all seven older categories) means "all but `runtime`".

**Interactive vs. non-interactive.** Only when stdin and stdout are both terminals and no region flag is given does `import` show the categories and prompt, with `heap`, `stack` and `unclassified` preselected (`[x]`). Answer with numbers (`1,2,7`), names (`heap,stack`), `all`, or Enter for the defaults. For `.msl` input a second `[y/N]` question offers the `--materialize` opt-in. Pipes, scripts and CI never prompt and keep importing everything. `import-dir` prompts **once**, from the first dump's regions, and applies that choice to every dump in the directory.

The prompt, the per-import selection summary and all warnings go to **stderr** — including `N keylog secret(s) found only in excluded regions` when `--keylog` secrets would be lost — so stdout stays the JSON summary, which gains `selection`, `excluded_region_count`, `excluded_bytes`, `secrets_only_in_excluded` and `warnings` when a selection was applied. A bad category name exits `2`; cancelling the prompt (Ctrl-D / Ctrl-C) exits `1` without writing.
```

```{admonition} Raw dumps and memory maps (`import`, `import-dir`)
:class: note

A raw dump (`.dump`, `.bin`) is just bytes: nothing in it says which bytes were heap, stack or a library, and there is no reliable way to tell from the content alone. Without layout metadata it imports as **one** `unclassified` region at address 0, so region selection cannot separate categories: `--list-regions` reports `layout: none`, and the interactive prompt is skipped with a one-line note.

Give the importer a `/proc/<pid>/maps`-style memory map and the dump is split into one region per maps entry, at its real virtual address:

- `--maps PATH` (`import`) — the memory map of the dump. Without it, a sidecar with the same name is picked up automatically: `foo.gdb_raw.bin` → `foo.gdb_raw.maps`, else `foo.maps` (the gdb_raw / lldb_raw convention).
- The dump bytes must be the maps regions concatenated **in maps order** (the `offset` column is ignored). Only the last region may be cut short (its missing pages are recorded as failed). If the region sizes do not add up to the file size, or entries overlap or are not page-aligned, the map is ignored with a warning and the dump imports as one raw region.
- Categories come from the maps path: `[heap]` → `heap`, `[stack]` → `stack`, libraries (`*.so*`, `/lib/`, `/usr/`) → `image_code` / `image_data` (by write permission), other files → `mapped_file`, anonymous private memory → `heap`, shared (`s`) anonymous or file mappings → `shared`. Protection comes from the `rwx` columns. File-backed entries also make up the module list, so `--regions` module globs work.
- The full path column is also used as the mapping name, which refines these categories: Android heaps such as `[anon:scudo:*]` or `[anon:dalvik-main space]` → `heap`, `[anon:stack_and_tls:*]` → `stack`, ART runtime / kernel / device maps → `runtime` (see above). A heap name on a shared mapping stays `shared`. The names are stored in the `.msl` VAS map, so `inspect` and later analysis see them too. When the names look like Android, the `.msl` header records Android as the OS and `--list-regions` shows `platform: android (mapping_names)`.
- `import-dir` imports `*.gdb_raw.bin` / `*.lldb_raw.bin` and any other `*.bin` that has a `.maps` sidecar, besides `*.dump` / `*.dmp` / `*.core`. A run `meta.json` may name one map for raw files without their own sidecar: `"maps": "layout/target.maps"` (relative to the run directory; absolute or `..` paths are ignored).
- The `lldb` and `fridump` dump backends of `experiment` and `capture` write this sidecar themselves (lldb: the regions actually read, with permissions and mapped names; fridump: one entry per chunk at its base address, split at mapping boundaries and named from the target's `/proc/<pid>/maps` or Frida's ranges when available, else unnamed `r--p`). The sidecar only lists bytes present in the bin; regions that were not captured are listed in a `<name>.capture.json` manifest beside the dump, and `import` / the import preview repeat them as warnings (plus a warning when the sidecar has no region names).

The resulting `.msl` records `source_format` = regioned raw in its import provenance, so the analysis-time region filter treats its categories as real (unlike a plain raw import, which stays `unclassified`).
```

```{admonition} Capturing a running process (`capture`)
:class: note

`memdiver capture <pid|name> <dump_path> [--tool memslicer|lldb|fridump] [--device SPEC]` takes one dump of a process that is already running and prints a JSON capture report (`-o` writes it to a file instead).

- `--device`: `local` (default), `usb` (the first USB device Frida sees, memslicer `-U`), `usb:<frida-device-id>` such as `usb:emulator-5554` (memslicer `-D`; use it when several devices are attached), or `remote:<host>[:<port>]` (memslicer `-R`; default port 27042). `lldb` is local only; `fridump` supports `local` and `usb`.
- A target given by name must be the name Frida lists (`frida-ps -U`). For an Android app that is the app label (for example `RC4 Demo`), not the package name, so a pid is usually the safer choice.
- lldb reads every readable region in 8 MiB chunks, so regions of any size are captured. A failed chunk is retried page by page, so an unreadable page only costs that page. Non-writable regions of 100 MiB or more (on macOS, the dyld shared cache, several GB per process) are skipped by default; `--include-large-readonly` captures them too. `--max-region-size BYTES` skips regions of at least that size (memslicer and lldb; fridump ignores it).
- Nothing is dropped silently. The report lists every region that was not captured under `skipped` (base, size, reason: `unreadable`, `read_failed`, `short_read`, `size_cap`, `large_readonly`, `timeout`) and repeats it on stderr. The same list is saved in `<dump>.capture.json`.
- `--timeout SECONDS` sets the backend timeout (defaults: memslicer and fridump 300 s, lldb 600 s). If lldb times out, the bin is cut back to what the `.maps` sidecar lists, the region being read is reported as `timeout`, and the command exits `1`.
- Exit `0` when the capture succeeded, `1` when it failed or the input was invalid. The same capture is available as REST `POST /api/experiment/capture`, MCP `capture_dump`, the "Capture a running process" form in the web UI's Experiment panel, and `memdiver.capture_result()`.
```

```{admonition} Encrypted `.msl` input (`import`, `import-dir`)
:class: note

`import` and `import-dir` accept the same decryption flags as the inspect commands: `--key-file PATH` (raw 32-byte key), `--passphrase TEXT` (Argon2id) and `--kem-key-file PATH` (X25519 / ML-KEM / hybrid private key). Which one is used is decided by the container header. With a key, `--list-regions` and the interactive prompt show the encrypted file's regions, and the summary counts them.

- `--materialize` on an encrypted `.msl` needs key material. The filtered copy is **re-encrypted** with the same content key and key wrapping (same KDF salt/parameters, same KEM ciphertext, same `dump_uuid`) and always a **fresh nonce**, so the same key / passphrase / private key opens it. Without a key it fails with `key material required`; a wrong key fails with `decryption failed`. Nothing is written in either case.
- `--decrypt-output` — explicit opt-in to write the materialized copy as **plaintext**. A warning goes to stderr and the JSON summary sets `decrypted_output: true` (otherwise `reencrypted: true`). It applies only to a materialized copy; a verbatim staging stays encrypted, with a warning.
- If the input is an encrypted `.msl`, `--materialize` is requested, no key flag is given and stdin is a terminal, the passphrase is asked for with a hidden `getpass` prompt. Scripts and pipes never prompt.

Key material is used for this request only: it is never cached, logged or written to the summary.
```

```{admonition} Analysis-time region filter (`consensus`, `consensus-window`, `consensus-regions`)
:class: note

These commands accept the same `--regions LIST|all` / `--exclude-regions LIST` flags as `import`, but nothing is rewritten: the region selection is a **view filter** applied while analysing, so each `.msl` is read as if only the selected categories existed. The flags only affect `.msl` inputs, and leaving both out keeps the unfiltered behaviour.

- Offsets in the output are **filtered-view offsets**, and the JSON gains a `region_filter` key (e.g. `"regions=heap,stack"`) that says which filter produced them. Use the same filter when you read those offsets back.
- A bad category name prints `Invalid region selection: …` on stderr and exits `2` without running.
```

```{admonition} Memory budget and `--force-memory` (`consensus`, `consensus-window`, `consensus-regions`, `analyze-candidates`, `analyze`, `batch`, `export --auto`, `experiment`)
:class: note

Before building a consensus, MemDiver estimates the peak memory the build needs and compares it with the memory budget: 70 % of available RAM, capped by `MEMDIVER_MEMORY_BUDGET_MB` when set. If the estimate is over the budget, the command **refuses** before allocating anything. It prints the estimate, the budget and suggestions on stderr, followed by `Re-run with --force-memory to proceed anyway.`, and exits `2` (`experiment` exits `1`). Nothing is written.

- `--force-memory` — override the refusal and run anyway. A warning is logged; the run may exhaust RAM or swap heavily.
- To get under the budget instead: narrow the input with `--regions heap,stack` (`.msl` inputs), pass fewer dumps, or raise `MEMDIVER_MEMORY_BUDGET_MB`.
- `batch` applies `--force-memory` to every job in the config.
```

```{eval-rst}
.. argparse::
   :module: cli
   :func: build_parser
   :prog: memdiver
```
