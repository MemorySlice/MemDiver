# Contributing to MemDiver

Thanks for considering a contribution! The full contributor guide lives at
[`docs/contributing/index.md`](docs/contributing/index.md) and is rendered on
the docs site at <https://memoryslice.github.io/MemDiver/contributing/>.

## Quick start

```bash
git clone https://github.com/MemorySlice/MemDiver.git
cd MemDiver
pip install -e ".[dev,docs]"
pytest tests/ -v
```

For frontend work:

```bash
cd frontend
npm ci
npm run dev      # Vite dev server, proxies to backend on :8080
```

## What to read before opening a PR

- [`docs/contributing/index.md`](docs/contributing/index.md) — full setup,
  test taxonomy, and code-style requirements.
- [`docs/contributing/adding_algorithms.md`](docs/contributing/adding_algorithms.md)
  — to add a detection algorithm.
- [`docs/contributing/adding_oracles.md`](docs/contributing/adding_oracles.md)
  — to add a decryption oracle for the brute-force pipeline.
- [`docs/file_formats/msl_v1_0_0.md`](docs/file_formats/msl_v1_0_0.md) — the
  Memory Slice Specification v1.0.0 reference, including the spec-conformance
  expectations new MSL changes must satisfy.
- [`CHANGELOG.md`](CHANGELOG.md) — what landed in `[Unreleased]` so far.

## Ground rules

- Don't delete existing code without explicit approval — preserve functionality.
- Use the localization system for any new UI strings.
- Add or update tests for code you change. The MSL spec-conformance suite at
  `tests/test_msl_conformance.py` is the canonical regression net for any
  reader / writer change.
- Match the existing code style; comments explain *why*, not *what*.

## Reporting issues

File an issue at <https://github.com/MemorySlice/MemDiver/issues>. Please
include MemDiver version (`memdiver --version`), Python version, and a
minimal repro. For analysis bugs, attach a small `.msl` file when possible.
