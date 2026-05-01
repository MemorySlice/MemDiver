# Changelog

All notable changes to MemDiver are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Extras collapsed** to two groups: `[experiment]` (frida-tools + memslicer)
  and `[dev]` (pytest, pytest-asyncio, httpx). `marimo`, `nicegui`, `mcp`, and
  `kaitaistruct` are now part of the base install — the `[notebook]`,
  `[nicegui]`, `[ai]`, `[formats]`, and `[all]` extras were removed.
- `memdiver experiment` now surfaces an actionable install hint
  (`pip install memdiver[experiment]`) when the experiment extras are missing,
  instead of raising a bare ImportError.
- `LICENSE` file replaced with the canonical Apache License 2.0 text (was
  previously MIT). The `pyproject.toml` classifier was updated to
  `License :: OSI Approved :: Apache Software License` to match.
- Install-hint messages in `memdiver app` / `memdiver mcp` updated to the new
  single-profile install story.

### Added
- `pip install memdiver[experiment]` extra, pinning `frida-tools>=12.0` and
  `memslicer` for the dump-collection flow.
- GitHub Actions workflows:
  - `ci.yml` — pytest matrix (Python 3.11 / 3.12) on push / PR.
  - `publish.yml` — OIDC trusted publishing to PyPI on `v*` tag push, plus
    TestPyPI dry-runs via `workflow_dispatch`. Includes a `npm ci && npm run
    build` step so the React bundle is baked into every wheel.
- `MANIFEST.in` — ensures `LICENSE`, `README.md`, `CHANGELOG.md`, algorithm
  patterns, and the full `frontend/dist/` tree ship in the sdist.
- `frontend/dist/**/*` added to `[tool.setuptools.package-data]` so
  `pip install memdiver` ships a working web UI out of the box.
- Sphinx documentation site under `docs/` (Read the Docs theme, MyST-parser),
  published to <https://memoryslice.github.io/MemDiver/> via GitHub Pages.
  Covers quickstart, full user guide, ten-subsystem architecture walkthrough,
  eight algorithm reference pages, nine visualization pages, `.msl` v1.1.0
  file-format spec, Oracle interface + examples, and a 12-module Python API
  reference generated via `autodoc` + `napoleon`.
- `.github/workflows/docs.yml` — strict Sphinx build on every push and PR,
  Pages deploy gated to `main` (re-enabled after one-time repo Settings
  configuration).
- `.github/workflows/docs-screenshots.yml` — nightly Playwright refresh of
  the 11 baseline screenshots under `docs/_static/screenshots/`, opening a
  pull request on visual drift.
- Logo pipeline: `docs/_static/{logo,logo_simple}.svg` (both with `<title>`,
  `<desc>`, `role="img"` for accessibility), `docs/_static/favicon.ico`
  (multi-resolution 16/32/48), `docs/_static/logo_readme.png` (PyPI-safe
  512×512 raster), regenerator at `scripts/build_logo.py --check`.
- Playwright screenshot harness under `docs/screenshots/` — `capture.py`
  (deterministic Chromium driver with 10 flake-reduction techniques),
  `seed_data.py` (wraps the six `tests/fixtures/generate_*.py` generators),
  `captions.json` (per-slug alt text + viewport), and
  `generate_placeholders.py` for fresh clones.
- `docs` extra (`pip install memdiver[docs]`) pinning Sphinx 7.4,
  `sphinx-rtd-theme`, `myst-parser`, `sphinx-copybutton`, `sphinx-design`,
  `sphinxcontrib-mermaid`, `sphinx-argparse`, `cairosvg`, `pillow`.
- `cli.py` — public `build_parser()` alias exposed for `sphinx-argparse` and
  external tooling.
- Repo-root `__init__.py` — `__version__` now resolves dynamically via
  `importlib.metadata.version("memdiver")` instead of the drifted hard-coded
  `"0.1.0"`.
- `pyproject.toml` — canonical project URLs updated to
  `github.com/MemorySlice/MemDiver`; added a `Documentation` URL pointing at
  the GitHub Pages site.
- README overhaul — accurate capability counts (8 algorithms, 20 CLI
  subcommands, 12 FastAPI routers, 15 MCP tools), Apache-2.0 badge, MCP
  one-line wiring snippet, IMF research framing, thumbnail gallery linking
  into the docs site.

### Deferred follow-ups
- **React i18n retrofit** — NiceGUI was localized via `ui/locales.py` +
  `ui/locales/en.json` in this pass; the React SPA still hardcodes
  user-facing strings (e.g. `frontend/src/components/wizard/Wizard.tsx`,
  panel labels, button text). Recommend `react-i18next` with JSON namespaces
  sharing the `locales/` convention. Out of scope for the remediation pass.
- **`user_regex` confidence calibration** —
  `algorithms/unknown_key/user_regex.py:48` returns `min(total / 10.0, 1.0)`,
  an arbitrary heuristic that inflates confidence on dense matches.
  Track a calibration task: parameterize the divisor via context, or
  compute confidence per-pattern from match density × pattern complexity.
- **e2e dataset gate** — 24 of 25 Playwright specs in `tests/e2e/specs/`
  skip when no private dataset is mounted (`test.skip(!datasetAvailable, ...)`).
  CI cannot exercise the SPA without it. Track a task to either (a) build a
  minimal synthetic `.msl` fixture under `tests/e2e/fixtures/synthetic_msl/`
  or (b) tag specs `requires-dataset` and document the CI strategy.

## [0.5.1] — 2026-04-14

- TLS polymorphic structures + FTUE tour framework
  (841 tests).
- (packaging/ops) resolved — MemDiver is now PyPI-publishable.
