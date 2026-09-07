# Contributing

```bash
git clone https://github.com/MemorySlice/MemDiver.git
cd MemDiver
pip install -e ".[dev,docs]"
pytest tests/ -v

# Backend (serves built React bundle)
memdiver web

# Frontend dev server (hot-reload, proxies /api to :8080)
# NOTE: one hoisted npm install at the REPO ROOT -- frontend/ and tests/e2e/
# are npm workspaces. Do NOT `cd frontend` first; see "JS install" below.
npm ci && npm run dev

# Marimo sandbox
memdiver ui
```

## Extension points

MemDiver has seven pluggable surfaces. They differ in how (and whether) an
out-of-tree package can register into them:

| Extension point | How to add (in-tree) | Out-of-tree (entry point)? | Guide |
| --- | --- | --- | --- |
| Detection algorithm | subclass `BaseAlgorithm` in `algorithms/{known_key,unknown_key,patterns}/` | YES (`memdiver.algorithms`) | [adding_algorithms](adding_algorithms.md) |
| KDF | `core/kdf_<name>.py` subclassing `BaseKDF` | YES (`memdiver.kdfs`) | [adding_kdf](adding_kdf.md) |
| Oracle | user `.py` loaded at runtime | n/a (user file) | [adding_oracles](adding_oracles.md) |
| Dump source | `register_dump_source(detector, factory)` | YES (`memdiver.dump_sources`) | [adding_dump_source](adding_dump_source.md) |
| Binary format | `register_format(FormatDescriptor(...))` | YES (`memdiver.formats`) | [adding_binary_format](adding_binary_format.md) |
| Pipeline stage | `register_stage(Stage(...))` (import-time) | YES (`memdiver.pipeline_stages`) | [adding_pipeline_stage](adding_pipeline_stage.md) |
| Verification resource | `register_resource_type(name, factory)` in `engine/resources/builtin_oracle.py` | YES (`memdiver.oracles`) | [adding_oracles](adding_oracles.md) |

Six of the seven extension points support out-of-tree registration by an installed
package via an `entry_points` group (all except **Oracle**, which is loaded from
a user-supplied `.py` file at runtime rather than an installed package — see
[adding_oracles](adding_oracles.md)). For the two subclass-based points the entry
point resolves to a subclass (or a module exposing one); for the four
register-call-based points it resolves to a module (imported for its
`register_*` side effects) or a callable (invoked to self-register). Discovery is
additive and failure-isolated — a silent no-op when nothing is installed.

**Verification resources carry no trust.** The first-party pcap resource is
loaded with the untrusted-code sandbox disabled (our own module, and a pcap is
data rather than executable; sandboxing a large capture's parse would misread a
slow parse as a hang). That exemption is granted per resource type and only to
in-tree factories: `register_resource_type` records the provenance of every
registration, and a type that arrived through `memdiver.oracles` is always
loaded under the sandbox. Otherwise installing a package would be enough to run
its code unsandboxed.

Entry-point discovery runs **once per process** (at first use of the relevant
registry), so a package installed into an already-running process is not picked
up until the process restarts.

## Code style

- Python: Google-style docstrings, strict type hints; stdlib-only in `core/`.
- React: TypeScript + Zustand slices; no shadcn/radix dependency.
- Comments explain **why**, not **what**. Self-documenting names preferred.
- Never delete existing code without explicit approval — preserve all functionality unless asked otherwise.

## JS install (npm workspaces)

`frontend/` and `tests/e2e/` are **npm workspaces** of the root `package.json`.
There is exactly one `node_modules` (at the repo root) and exactly one
`package-lock.json` (at the repo root):

```bash
npm ci          # from the repo root, never from inside a workspace
```

| Root command | Underlying |
| --- | --- |
| `npm run dev` / `build` / `test:run` | `npm run <script> -w frontend` |
| `npm run e2e` | `npm run test -w tests/e2e` |
| `npm run lint` | `eslint .` against the root `eslint.config.mjs` |
| `npm run typecheck` | `tsc -b frontend` |

`npm install` inside a workspace directory creates a nested `node_modules` with
a duplicated React — see the warning in
[`CONTRIBUTING.md`](https://github.com/MemorySlice/MemDiver/blob/main/CONTRIBUTING.md).
CI asserts that exactly one copy of `react` exists.

## Test taxonomy

- **Unit** (~90 files) — one per subsystem module.
- **Integration** — `test_integration.py`, `test_aes_e2e.py`, `test_pipeline.py`.
- **Real-dump E2E** — gated by the `requires_dataset` marker; skipped when no dataset is configured.
- **Python browser E2E (pytest-playwright)** — `tests/e2e_*_test.py` (manually invoked, not collected by pytest default discovery).
- **Frontend unit (vitest)** — 32 files / 305 tests under `tests/frontend/`,
  mirroring the `frontend/src/` tree. Tests are **never** co-located with the
  module under test, and the directory anchor is load-bearing: it is what keeps
  vitest and the Playwright suite apart (Playwright's files are all `*.spec.ts`
  under `tests/e2e/specs/`, and vitest's include pattern accepts `spec` too).
  jsdom + `@testing-library/react`; `@/` → `frontend/src`, `@tests/` →
  `tests/frontend`. Run with `make fe-test`. Typechecked by
  `frontend/tsconfig.test.json` via `make fe-typecheck` — deliberately a
  *separate* TS project from `tsconfig.app.json`, which is what `vite build`
  compiles and must stay test-free.
- **TypeScript browser E2E / a11y (Playwright)** — `tests/e2e/specs/*.spec.ts`,
  34 files / 127 tests. Run with `scripts/test-e2e.sh` or `npm run e2e`; the
  `a11y-*` subset is asserted on every frontend-touching PR.

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
