# Cross-run variance map

:::{admonition} Availability
:class: warning
Component files exist (`ui/views/variance_map.py`, `frontend/src/components/charts/VarianceMap.tsx`) but neither is currently wired into the active SPA layout or the `run.py` Marimo notebook. The closest shipping visual in the SPA is the [consensus view](consensus.md).
:::

Per-offset byte variance across N runs plotted as a log-y bar chart. Variance thresholds `200` and `3000` separate `STRUCTURAL`, `POINTER`, and `KEY_CANDIDATE` classes.

To render it today, import the component directly into a custom Marimo cell or add it to `frontend/src/components/layout/Workspace.tsx`.
