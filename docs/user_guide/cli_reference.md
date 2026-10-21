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

```{eval-rst}
.. argparse::
   :module: cli
   :func: build_parser
   :prog: memdiver
```
