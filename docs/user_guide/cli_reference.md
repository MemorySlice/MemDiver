# CLI reference

MemDiver exposes a single `memdiver` console script with 20 subcommands. This page is auto-generated from the argparse parser — every flag listed here matches the installed version.

```{admonition} Common flags
:class: tip

Most subcommands accept:

- `-v`, `--verbose` — enable DEBUG logging.
- `-o PATH`, `--output PATH` — write JSON results to *PATH*.

The `experiment` subcommand additionally requires the optional `memdiver[experiment]` extra (pulls in `frida-tools` + `memslicer`). The LLDB backend is installed via your OS package manager.
```

```{eval-rst}
.. argparse::
   :module: cli
   :func: build_parser
   :prog: memdiver
```
