# Consensus view

:::{admonition} Available in
:class: tip
**SPA** (bottom tabs `consensus` + `live-consensus`) · **Marimo** sandbox
:::

Per-byte variance classification across N dumps. The SPA bundles three consensus visuals:

- **ConsensusChart** — stacked classification-count bars per offset bucket.
- **ConsensusBuilder** — incremental Welford session (begin → add → finalize).
- **NDumpOverlay** — overlay of N dumps with per-dump visibility toggles.

Backed by `POST /api/analysis/consensus`, `POST /api/consensus/begin`, `POST /api/consensus/{sid}/add-path|add-upload`, `POST /api/consensus/{sid}/finalize`.

```{figure} /_static/screenshots/07_consensus_tab.png
:alt: Consensus chart with stacked bars showing INVARIANT / STRUCTURAL / POINTER / KEY_CANDIDATE byte counts per offset bucket
:align: center
```
