---
myst:
  html_meta:
    "description lang=en": "Five-minute path from a full memory image to Volatility 3 rows and a process .msl, via web, CLI or MCP."
---

# Memory images in five minutes

MemDiver opens a **full physical memory image** (LiME, AVML, raw), resolves a
kernel profile for it, runs Volatility 3 plugins over it and lets you pull a
single process out as an `.msl` capture for the key-finding workflow. This page
is the short path. The details live in [Volatility 3 inside MemDiver](../user_guide/vol3.md)
and [The ISF workbench](../user_guide/isf_workbench.md).

## Install

Image support is an optional extra. It adds Volatility 3 and pakunoda, which
reconstructs a kernel profile (an ISF) straight from the image.

```bash
pip install "memdiver[image]"
```

If the extra is missing, the command stops with an error that names it. It
never returns an empty result.

## The path

Every step exists in the web UI, the CLI and MCP. The CLI form is shown here.
Every command prints a JSON payload, or writes it with `-o FILE`.

1. **Create a case.** A case directory holds everything you derive: views,
   extracted `.msl` files, annotations, ISF drafts, plugins and a table for
   every plugin run. A bare name files under `~/.memdiver/cases/<name>`.

   ```bash
   memdiver case init demo
   ```

2. **Look at the image.** `probe` reports size, layers, profile status and,
   with `--banners`, the Linux kernel banners. It never hashes the image, so
   the profile status reads `unknown` until a later step hashes it.

   ```bash
   memdiver image probe memory.lime --banners
   ```

3. **Resolve the profile.** The chain is explicit ISF, then cache, then
   pakunoda, then Volatility 3's own symbol directories. The first run on a
   large image is slow (about 15 s in the reference run, because pakunoda maps
   the whole image). The result is cached, and the second call returns at once.

   ```bash
   memdiver image profile memory.lime
   ```

4. **Open a kernel view.** This writes a `.mdview` descriptor under
   `<case>/views/`. Use `--view physical` for raw physical space and
   `--view process --pid N` for one process.

   ```bash
   memdiver image open memory.lime --view kernel --case demo
   memdiver image processes demo/views/<name>.mdview
   ```

   `image open` prints the exact path of the `.mdview` it wrote. Use that path.

5. **Run a plugin.** The rows land in a case table named
   `vol3__<os>_<plugin>`.

   ```bash
   memdiver vol3 run --view <kernel.mdview> --plugin linux.pslist --case demo
   ```

6. **Query the rows.** `case schema` lists tables and columns. `case query`
   runs one read-only `SELECT`. Bind values with `--param`, never by string
   formatting.

   ```bash
   memdiver case schema --case demo
   memdiver case query --case demo --sql "SELECT * FROM vol3__linux_pslist LIMIT 20"
   ```

7. **Extract a process.** Open its process view, then write an `.msl`.

   ```bash
   memdiver image open memory.lime --view process --pid 22176 --case demo
   memdiver image extract <process.mdview> --out sshd.msl
   ```

   The `.msl` is a normal capture. Pages the process never had in RAM are
   recorded as not captured. They are never invented as zeros. Continue with
   the heap and key-finder tools as for any other dump.

:::{note}
`vol3 run` blocks until the plugin finishes. Check `truncated` and
`stop_reason` in its result. The defaults are a 100,000-row cap and a
300 s timeout (`--limit`, `--timeout`). A truncated run is not the complete
result.
:::

## Three ways to drive it

**Web.** Start the server with `memdiver web`. In the **Memory image** panel
enter the image path, press **Probe**, then **Extract profile with pakunoda**
if no profile is found. **Open kernel view** loads the view into the workspace
and fills the **Processes** table. **Open process view** and
**Extract to .msl** act on a row. The **Volatility 3** panel runs plugins on
the active view.

**CLI.** The commands above: `memdiver image …`, `memdiver vol3 …`,
`memdiver case …`.

**MCP.** Fetch the prompt `vol3_inside_memdiver` (arguments `image_path` and
`case`). It renders a numbered playbook that names the exact tools:
`case_init`, `image_probe`, `image_profile`, `image_open_view`,
`image_processes`, `vol3_run`, `case_query`, `image_extract_process`. The
prompt `memdiver_start` lists all playbooks.

## Traps worth knowing up front

- **Zero rows is not "no processes".** On a 5-level-paging (LA57) kernel,
  stock Volatility 3 stacks a 4-level layer and returns an empty process list
  with no error. MemDiver detects the paging depth itself and treats zero tasks
  as an error. If a different tool shows an empty list, suspect the paging
  depth.
- **No profile found?** Do not guess one. Use the
  [ISF workbench](../user_guide/isf_workbench.md), or open a profile-less
  kernel view (`image open --no-profile`).
- **Sandbox.** If `MEMDIVER_ALLOWED_ROOTS` is set, every path must lie inside
  those roots. Outputs must lie inside MemDiver home.
