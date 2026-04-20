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
  - `ci.yml` — pytest matrix (Python 3.10 / 3.11 / 3.12) on push / PR.
  - `publish.yml` — OIDC trusted publishing to PyPI on `v*` tag push, plus
    TestPyPI dry-runs via `workflow_dispatch`. Includes a `npm ci && npm run
    build` step so the React bundle is baked into every wheel.
- `MANIFEST.in` — ensures `LICENSE`, `README.md`, `CHANGELOG.md`, algorithm
  patterns, and the full `frontend/dist/` tree ship in the sdist.
- `frontend/dist/**/*` added to `[tool.setuptools.package-data]` so
  `pip install memdiver` ships a working web UI out of the box.

## [0.5.1] — 2026-04-14

- TLS polymorphic structures + FTUE tour framework
  (841 tests).
- (packaging/ops) resolved — MemDiver is now PyPI-publishable.
