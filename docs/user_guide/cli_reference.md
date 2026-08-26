# CLI reference

MemDiver exposes a single `memdiver` console script with 22 subcommands. This page is auto-generated from the argparse parser — every flag listed here matches the installed version.

```{admonition} Common flags
:class: tip

Most subcommands accept:

- `-v`, `--verbose` — enable DEBUG logging.
- `-o PATH`, `--output PATH` — write JSON results to *PATH*.

The `experiment` subcommand's Python dependencies (`frida-tools` + `memslicer`) ship in the default `pip install memdiver`. What pip cannot provide is the runtime side: Frida needs an attachable target process, and the LLDB backend is installed via your OS package manager.
```

```{eval-rst}
.. argparse::
   :module: cli
   :func: build_parser
   :prog: memdiver
```
