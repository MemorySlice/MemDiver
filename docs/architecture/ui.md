# ui/

Legacy Python-side UI layer.

- **Marimo sandbox** — `run.py` is the single `marimo.App`. `memdiver ui` launches it via `python -m marimo run run.py`. This is where the 5 Marimo-only visualization views live (heatmap, variance map, phase lifecycle, cross-library comparison, differential diff).

`ui/mode.py` defines `ModeManager`, whose `TESTING_VIEWS` and `RESEARCH_VIEWS` lists (returned by `available_views()`) gate which views the sandbox shows in each mode. The view implementations live in `ui/views/`.

## When to prefer Marimo

- Prototyping new analysis math (reactive cells, inline plotly).
- Ad-hoc dump inspection where writing TypeScript + React would be overkill.
- Reproducing standard analysis views from raw dumps.

## When to prefer the React SPA

- Routine investigation workflows with the wizard + dockable workspace.
- Anything driving the Phase-25 pipeline (oracle upload, brute-force, n-sweep).
- Collaboration — session-sharing, bookmarks, screenshot-ready visuals.
