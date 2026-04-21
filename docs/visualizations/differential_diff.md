# Differential diff

:::{admonition} Availability
:class: warning
Component files exist (`ui/views/differential_diff.py`, `frontend/src/components/charts/DifferentialDiff.tsx`) but neither is currently wired into the active SPA layout or the `run.py` Marimo notebook. The SPA's `HexOverlay` covers the two-dump case from a different angle.
:::

Two-run XOR diff with color-coded changed bytes. Shows exactly which bytes differ between two snapshots of the same process — the raw material for the [`differential`](../algorithms/differential.md) algorithm.

To render it today, import the component into a custom Marimo cell or extend the SPA workspace.
