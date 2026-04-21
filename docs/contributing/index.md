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
```
