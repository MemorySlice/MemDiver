# Web UI tour

A guided walk through the React SPA. Each screenshot below is regenerated deterministically by the Playwright harness documented in [](../contributing/index.md) — they stay in sync with the code, not a moving memory.

## Session landing

First screen when you open `http://127.0.0.1:8080`. Pick a saved session or start a new one.

```{figure} /_static/screenshots/01_landing.png
:alt: MemDiver session landing page, listing previously saved analysis sessions
:align: center

The session-landing view enumerates `.memdiver` SessionStore entries and offers a "New session" entry point into the wizard.
```

## Wizard — select data

Type a path or click **Browse** to open the file-browser modal.

```{figure} /_static/screenshots/02_wizard_select_data.png
:alt: Wizard step one, showing path input and a file-browser modal
:align: center

Accepted input types: a single `.dump` or `.msl` file, a run directory (auto-detected), or a full dataset root.
```

## Wizard — analysis algorithms

```{figure} /_static/screenshots/03_wizard_analysis.png
:alt: Wizard step three, showing the 8-algorithm checkbox grid with availability hints
:align: center

Algorithms unavailable for the selected mode (verification vs exploration) are dimmed. Defaults match the recommended set from [](../algorithms/index.md).
```

## Workspace — default layout

```{figure} /_static/screenshots/04_workspace_default.png
:alt: MemDiver workspace in dark theme, showing hex viewer, sidebar, and bottom analysis panel
:align: center

The IDA-Pro-style dockable workspace: main hex panel, sidebar with six tabs, detail overlay, and a mode-gated bottom-tabs row.
```

## Hex viewer with structure overlay

```{figure} /_static/screenshots/05_hex_with_overlay.png
:alt: Hex viewer with a TLS-13 structure overlay highlighting bytes by classification
:align: center

Structural fields are colored by class (`static`, `dynamic`, `key_material`); overlays drive the investigation panel on the right.
```

## Entropy profile

```{figure} /_static/screenshots/06_entropy_tab.png
:alt: Entropy profile chart with Shannon entropy plotted against byte offset and high-entropy regions shaded
:align: center

Sliding-window Shannon entropy. Shaded regions exceed the configurable threshold (default 7.5).
```

## Consensus view

```{figure} /_static/screenshots/07_consensus_tab.png
:alt: Consensus view — stacked bars showing per-byte classification counts across N dumps
:align: center

Consensus over multiple dumps from the same library and phase. Classification bands: `INVARIANT`, `STRUCTURAL`, `POINTER`, `KEY_CANDIDATE`.
```

## Pipeline — oracle stage

```{figure} /_static/screenshots/08_pipeline_oracle.png
:alt: Pipeline oracle-stage wizard showing uploaded decryption oracle with dry-run status
:align: center

Upload a bring-your-own decryption oracle (Python module matching the [oracle interface](../oracle/interface.md)), arm it, and preview dry-run results.
```

## Pipeline — run dashboard

```{figure} /_static/screenshots/09_pipeline_run.png
:alt: Live pipeline run dashboard with funnel chart, stage timings, and live oracle log
:align: center

Stages: `search-reduce` → `brute-force` → `n-sweep` → `emit-plugin`. Funnel shows candidates surviving each stage; live log streams oracle hits.
```

## Pipeline — results

```{figure} /_static/screenshots/10_pipeline_results.png
:alt: Pipeline results with survivor-curve chart and downloadable artifacts
:align: center

Downloadable artifacts include the finalized Welford state (`mean.npy`, `m2.npy`), the `hits.json` catalog, and the synthesized Volatility3 plugin.
```

## Theme triptych

```{figure} /_static/screenshots/11_theme_triptych.png
:alt: Three workspace panels side by side in light, dark, and dark-plus-high-contrast themes
:align: center

Light, dark, and dark+high-contrast modes. High-contrast mode passes WCAG AAA for text legibility.
```

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | New session |
| `Ctrl+S` | Autosave |
| `Ctrl+G` | Go to offset |
| `Ctrl+B` | Toggle sidebar |
| `Arrow`, `Shift+Arrow` | Hex navigation / selection |
| `PageUp`, `PageDown` | Page-wise scrolling |
| `Home`, `End` | (with `Ctrl`) jump to file start/end |
| `Tab` | Toggle hex ↔ ASCII column focus |
| `Esc` | Clear selection / back in wizard |
