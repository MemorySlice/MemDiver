# ui/

Legacy Python-side UI layer. Two shells:

- **Marimo sandbox** — `run.py` is the single `marimo.App`. `memdiver ui` launches it via `python -m marimo run run.py`. This is where the 5 Marimo-only visualization views live (heatmap, variance map, phase lifecycle, cross-library comparison, differential diff).
- **NiceGUI shell** — `legacy_app.py` at repo root + `ui/nicegui/*`. `memdiver app` launches it. Pre-React entry point; retained for headless workflows where React/Vite is overkill.

`ui/mode.py` defines the `VERIFICATION_VIEWS` and `RESEARCH_VIEWS` lists consumed by both shells.

## When to prefer Marimo

- Prototyping new analysis math (reactive cells, inline plotly).
- Ad-hoc dump inspection where writing TypeScript + React would be overkill.
- Reproducing paper figures from raw dumps.

## When to prefer the React SPA

- Routine investigation workflows with the wizard + dockable workspace.
- Anything driving the Phase-25 pipeline (oracle upload, brute-force, n-sweep).
- Collaboration — session-sharing, bookmarks, screenshot-ready visuals.
