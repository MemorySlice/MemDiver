# Phase lifecycle

:::{admonition} Availability
:class: warning
Component files exist (`ui/views/phase_lifecycle.py`, `frontend/src/components/charts/PhaseLifecycleGrid.tsx`) but neither is currently wired into the active SPA layout or the `run.py` Marimo notebook.
:::

For a single library, shows which secrets are recoverable at each lifecycle phase (`pre_handshake`, `post_handshake`, `pre_close`, `post_close`, `pre_abort`, …) after phase normalization.

To render it today, import the component into a custom Marimo cell or extend the SPA workspace.
