# Cross-library comparison

:::{admonition} Availability
:class: warning
Component files exist (`ui/views/cross_library.py`, `frontend/src/components/charts/CrossLibraryHex.tsx`) but neither is currently wired into the active SPA layout or the `run.py` Marimo notebook. The SPA does ship `HexComparison` / `HexOverlay` for dump-vs-dump comparison inside a single library.
:::

Side-by-side hex panels for the same secret type across two or more libraries. Reveals how different implementations serialize the same cryptographic primitive.

To render it today, import the component into a custom Marimo cell or extend the SPA workspace.
