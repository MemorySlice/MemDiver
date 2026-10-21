# Cross-run variance map

:::{admonition} Available in
:class: tip
**SPA** (bottom tab `variance`, exploration mode) · Marimo: component exists (`ui/views/variance_map.py`), not wired in `run.py`
:::

In the SPA the tab plots the variance slice of the current neighborhood overlay; until you select a hit or a neighborhood overlay in the hex viewer it shows "Select a hit or neighborhood overlay in the hex viewer to inspect its variance profile." For whole-dump classes, use the [consensus view](consensus.md) and its [hex overlay](consensus.md#hex-overlay).

Per-offset byte variance across N runs plotted as a log-y bar chart. Variance thresholds `200` and `3000` separate `STRUCTURAL`, `POINTER`, and `KEY_CANDIDATE` classes.

To render it in Marimo today, import the view directly into a custom cell.
