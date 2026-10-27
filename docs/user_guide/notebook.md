# The case explorer notebook

`memdiver notebook CASE` opens a [marimo](https://marimo.io) notebook on a case directory. It is an analyst companion for looking around a case, not one of the parity surfaces (library, CLI, web, MCP). It needs the `marimo` extra: `pip install "memdiver[marimo]"`.

```
memdiver notebook p6_gate_wf1            # run as an app
memdiver notebook p6_gate_wf1 --edit     # open the cells for editing
memdiver notebook CASE --port 2718 --headless
```

`CASE` is a case directory or a bare name under `~/.memdiver/cases/`. A path that is not a case exits with an error. If marimo is not installed the command prints an install hint and exits 1.

The notebook template is `ui/notebooks/case_explorer.py`. It reads the case from `--case DIR` or, if you open it yourself, from the `MEMDIVER_CASE` environment variable.

## What it shows

- **Manifest**: case name, directory, creation time.
- **Tables and runs**: every table with its runs and row counts.
- **SQL**: a read-only query box. It runs through `case.query`, the same hardened path as `memdiver case query`, so writes and file access are refused. A truncated result says so.
- **Process tree**: built from the newest run of `vol3__linux_pslist`. Without that table the notebook says so instead of failing.
- **Hex context**: pick a process to see the case rows that contain its task struct address and up to 256 bytes from the case's kernel `.mdview`. Bytes that were not captured print as `--`, never as zeros.
