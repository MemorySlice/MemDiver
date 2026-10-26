---
myst:
  html_meta:
    "description lang=en": "Run Volatility 3 plugins over full memory images inside MemDiver: profiles, views, tables, highlights, plugin development, extraction."
---

# Volatility 3 inside MemDiver

MemDiver reads a full memory image through Volatility 3 and files every result
as a table in a *case*. The same operations exist in the web UI, the CLI
(`memdiver image …`, `memdiver vol3 …`, `memdiver case …`) and MCP. For the
five-minute version, see [Memory images in five minutes](../quickstart/image.md).

Install the extra first: `pip install "memdiver[image]"`.

## Cases

`memdiver case init NAME` creates a case directory (a bare name means
`~/.memdiver/cases/NAME`). The case keeps views, extracted `.msl` files,
annotations, ISF drafts, stored plugins and a DuckDB-backed table for every
plugin run. `case status` and `case manifest` inventory it.

## The profile chain

A kernel profile (ISF) tells Volatility 3 where kernel structures live.
`memdiver image profile IMAGE` resolves one in this order and stops at the
first hit:

1. **Explicit** — the file you pass with `--isf`.
2. **Cache** — a profile resolved earlier for the same image.
3. **pakunoda** — reconstructs an ISF from the image (BTF, kallsyms, banner).
   Skip it with `--no-pakunoda`.
4. **Volatility 3 symbol directories**.

The result names its `origin` and `isf_name`. A failed or unloadable
extraction is never cached. If the chain finds nothing, build the profile by
hand with the [ISF workbench](isf_workbench.md).

:::{warning}
A profile with wrong offsets does not fail in Volatility 3. It loads and
returns plausible wrong rows. Only a profile resolved by the chain, or a draft
that passed a ground-truth try, should be trusted.
:::

## Views

`memdiver image open IMAGE --view {physical,kernel,process}` writes a
`.mdview` descriptor. The descriptor is a small JSON file. It records the
image, the view kind and the profile variant. Every hex, search, regions and
plugin tool accepts it like any dump.

| View | Address space | Use |
|---|---|---|
| `physical` | physical offsets | raw physical memory |
| `kernel` | kernel virtual addresses | kernel structures, process list |
| `process` (with `--pid`) | that process's virtual addresses | one process; plugins scope `pid` automatically |

Every address is a `Location` that carries its coordinate system (`physical`,
`kernel_va`, `process_va`) and the capture it belongs to. A bare integer is
never passed between tools. Kernel addresses are canonical (`0xff42…`), not
the width-masked form Volatility 3 prints.

Default view file names differ per profile variant, so opening the same image
with a different profile never overwrites an earlier view:
`<stem>.kernel.isf-<sha8>.mdview`, `<stem>.kernel.noprofile-<pgd>.mdview`,
`<stem>.kernel.draft-<name>-<state8>.mdview`, and
`<stem>.process.pid<N>.<variant>.mdview`. Re-opening the same variant returns
the same path.

`--no-profile` opens a kernel view with no ISF at all, by walking the page
tables directly (x86_64 and aarch64). Pass `--pgd`, `--arch` and `--va-bits`
to name the paging root, or let MemDiver search for a verified one. See the
[ISF workbench](isf_workbench.md#a-kernel-view-without-an-isf).

`memdiver image processes VIEW` lists pid, ppid, name and uid of a kernel
view. An empty list is reported as an error (wrong profile or paging depth),
never as success.

## Plugins

```bash
memdiver vol3 list --os linux
memdiver vol3 describe --plugin linux.pslist
memdiver vol3 run --view kernel.mdview --plugin linux.pslist --case demo
memdiver vol3 run --view proc.mdview --plugin linux.lsof --arg pid=[22176] --case demo
```

`describe` shows the requirements to pass as `--arg KEY=VALUE` (repeatable,
JSON values). `run` is inline and blocks. The result carries `truncated` and
`stop_reason`, and a truncated run is explicitly not the complete result.
`--limit` (default 100,000 rows) and `--timeout` (default 300 s) are the caps,
and `--max-rows` (default 1,000) limits the rows echoed back, not stored.
Plugin file outputs go to `--out-dir`.

Every Volatility 3 call in a process is serialized behind one lock per
image. Volatility 3 contexts are not thread-safe, and concurrent use produced
wrong run tables in testing. Expect concurrent requests to queue.

## Tables, queries and context

Each run registers a table `vol3__<os>_<plugin>`. Besides the plugin's own
columns, it carries standard ones (`capture_id`, `image_sha256`, `pid`,
`space`, `addr`, `size`, `run_id`). Plugin columns that hold addresses are
detected automatically. Override the detection with
`--column-map '{"Column": "kernel_va"}'`.

```bash
memdiver case schema --case demo
memdiver case query --case demo --sql "SELECT * FROM vol3__linux_pslist WHERE pid = ?" --param 22176
memdiver vol3 query --case demo            # lists the built-in saved queries
memdiver vol3 query --case demo --saved <name>
memdiver case context-at --case demo \
  --location '{"space":"kernel_va","value":18446612691240591360,"capture_id":"<sha256>"}'
```

`case query` runs exactly one read-only `SELECT` over every table: plugin rows,
regions, heap chunks, key hits and annotations. `context-at` answers "what
contains this address": table rows, VMAs, heap chunks and annotations,
outermost layer first, with read coverage when you pass `--dump`.

An output file produced by stock `vol` can be registered as a table with
`memdiver vol3 import FILE --case … --table … --capture-id …`.

## Highlights and annotations

`memdiver vol3 annotate --case demo --table T --run-id R --column COL` files
one `plugin_row` annotation per row that has an address in `COL` (rows
without an address are skipped). `--rows` selects row indexes and
`--label-column` names the label. Manual notes use `memdiver annotations add`.
Annotations are append-only: fix with `supersede`, withdraw with `retract`.

In the web UI, the **Volatility 3** panel shows each result as a table. Pick
an address column under **Treat COLUMN as** (physical, kernel VA, process VA or
not an address). A row click jumps the hex viewer to that address when the
active view can show it. If it cannot, the UI says why: wrong address space,
a different pid, or an uncaptured address. **Highlight column** paints the
column in the hex view, and **Save as annotations** files them. Saving needs a
case directory.

## Writing your own plugin

The **Editor** mode of the Volatility 3 panel, and the CLI below, cover the
whole loop.

```bash
memdiver vol3 scaffold my_plugin > my_plugin.py      # --kernel-only drops the pid filter
memdiver vol3 source put my_plugin --case demo --file my_plugin.py --view kernel.mdview
memdiver vol3 check --source-name my_plugin --case demo --view kernel.mdview
memdiver vol3 run --view kernel.mdview --source-name my_plugin --case demo
memdiver vol3 source list --case demo
```

- `source put` stores the text under `<case>/plugins/` and checks it. An
  overwrite keeps the old text under `plugins/history`. A plugin that fails to
  load is still saved, and you get the structured failure (error type and
  line).
- `check` with `--view` also lists requirements the view leaves unsatisfied.
- Keep `addr`, `size` and `space` columns where it makes sense. Rows without
  an address column cannot be highlighted.

:::{danger}
User plugins execute unsandboxed in the MemDiver process, with the server's
privileges. Run only code you wrote or reviewed.
:::

### Fixtures

A fixture pins a plugin, a view and row predicates, so you can re-test after
every edit.

```bash
memdiver vol3 fixture put finds_sshd --case demo --view kernel.mdview \
  --plugin linux.pslist --expect '{"row_where": {"COMM": "sshd"}, "count_at_least": 1}'
memdiver vol3 fixture run finds_sshd --case demo
memdiver vol3 fixture list --case demo
```

Predicates: `min_rows`, `max_rows`, `row_where` with `count_at_least`,
`column_all`, `column_any`. The verdict is `pass`, `fail` or
`indeterminate`, and it is filed as a `fixture_verdict` annotation.
**`indeterminate` proves nothing** (a truncated or timed-out run, an
unreadable view). Never read it as a pass.

### Using the plugin with stock `vol`

```bash
memdiver vol3 write-config --view kernel.mdview --out config.json \
  --source-name my_plugin --case demo
```

`write-config` writes a `config.json` that reproduces the view's layer stack,
including the 5-level paging fix. Pass it to the stock `vol` CLI with `-c`.
For a plugin emitted by MemDiver, the reference run reproduced the same key
offset from stock `vol` as the `.msl` had.

## Extracting a process

```bash
memdiver image open memory.lime --view process --pid 22176 --case demo
memdiver image extract <process.mdview> --out sshd.msl
```

Extraction takes seconds on a small process, longer on big ones. The `.msl`
records page states from the page tables: captured pages are data, pages not in
the image are marked failed, and pages never resident are marked as such.
Untranslated addresses are not invented. In the reference run on an
alma-9 sshd (pid 22176), 7,823,360 bytes were captured, 13,193,216 were failed
reads and 626,688 were not resident. The result is a normal capture for `heap_detect`, the
key finders and the consensus tools.

## Limits and traps

- **LA57.** Five-level paging makes stock Volatility 3 return zero rows with no
  error. MemDiver detects the depth and stacks a 5-level layer. A zero-row
  process list is an error.
- **Slow first run.** Profile extraction maps the whole image and runs as a
  background job in the web server, never inside the request.
- **kallsyms scans** on a multi-GB image can take over a minute.
- **Sandbox.** With `MEMDIVER_ALLOWED_ROOTS` set, path arguments must lie in
  those roots, and output paths in MemDiver home. A denial returns
  `code=path.outside_sandbox`.
- **Tools never overwrite.** An output path must be a new file.
- **Rows are not proof.** A plugin table is an interpretation. The image bytes
  and page states are the facts.
