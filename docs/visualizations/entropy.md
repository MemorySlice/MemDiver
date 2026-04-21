# Entropy profile

:::{admonition} Available in
:class: tip
**SPA** (bottom tab `entropy`) · **Marimo** sandbox
:::

Shannon entropy vs byte offset. Shaded bands mark windows exceeding the configurable threshold (default 7.5).

Backed by `GET /api/inspect/entropy?window=32&step=16&threshold=7.5`.

```{figure} /_static/screenshots/06_entropy_tab.png
:alt: Entropy profile — Shannon entropy per 32-byte window plotted against offset, with high-entropy regions shaded red
:align: center
```
