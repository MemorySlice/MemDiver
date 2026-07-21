# Contributing

```bash
git clone https://github.com/MemorySlice/MemDiver.git
cd MemDiver
pip install -e ".[dev,docs]"
pytest tests/ -v

# Backend (serves built React bundle)
memdiver web

# Frontend dev server (hot-reload, proxies /api to :8080)
cd frontend && npm install && npm run dev

# Marimo sandbox
memdiver ui
```

## Extension points

MemDiver has six pluggable surfaces. They differ in how (and whether) an
out-of-tree package can register into them:

| Extension point | How to add (in-tree) | Out-of-tree (entry point)? | Guide |
| --- | --- | --- | --- |
| Detection algorithm | subclass `BaseAlgorithm` in `algorithms/{known_key,unknown_key,patterns}/` | YES (`memdiver.algorithms`) | [adding_algorithms](adding_algorithms.md) |
| KDF | `core/kdf_<name>.py` subclassing `BaseKDF` | YES (`memdiver.kdfs`) | [adding_kdf](adding_kdf.md) |
| Oracle | user `.py` loaded at runtime | n/a (user file) | [adding_oracles](adding_oracles.md) |
| Dump source | `register_dump_source(detector, factory)` | YES (`memdiver.dump_sources`) | [adding_dump_source](adding_dump_source.md) |
| Binary format | `register_format(FormatDescriptor(...))` | YES (`memdiver.formats`) | [adding_binary_format](adding_binary_format.md) |
| Pipeline stage | `register_stage(Stage(...))` (import-time) | YES (`memdiver.pipeline_stages`) | [adding_pipeline_stage](adding_pipeline_stage.md) |

Five of the six extension points support out-of-tree registration by an installed
package via an `entry_points` group (all except **Oracle**, which is loaded from
a user-supplied `.py` file at runtime rather than an installed package — see
[adding_oracles](adding_oracles.md)). For the two subclass-based points the entry
point resolves to a subclass (or a module exposing one); for the three
register-call-based points it resolves to a module (imported for its
`register_*` side effects) or a callable (invoked to self-register). Discovery is
additive and failure-isolated — a silent no-op when nothing is installed.

Entry-point discovery runs **once per process** (at first use of the relevant
registry), so a package installed into an already-running process is not picked
up until the process restarts.

## Code style

- Python: Google-style docstrings, strict type hints; stdlib-only in `core/`.
- React: TypeScript + Zustand slices; no shadcn/radix dependency.
- Comments explain **why**, not **what**. Self-documenting names preferred.
- Never delete existing code without explicit approval — preserve all functionality unless asked otherwise.

## Test taxonomy

- **Unit** (~90 files) — one per subsystem module.
- **Integration** — `test_integration.py`, `test_aes_e2e.py`, `test_pipeline.py`.
- **Real-dump E2E** — gated by the `requires_dataset` marker; skipped when no dataset is configured.
- **Playwright browser E2E** — `tests/e2e_*_test.py` (manually invoked, not collected by pytest default discovery).

## Docs build

```bash
pip install -e ".[docs]"
sphinx-build -W --keep-going -b html docs docs/_build/html
open docs/_build/html/index.html
```

Warnings-as-errors (`-W`) is mandatory; fix them, don't suppress.

```{toctree}
:hidden:

adding_algorithms
adding_oracles
adding_dump_source
adding_binary_format
adding_kdf
adding_pipeline_stage
```
