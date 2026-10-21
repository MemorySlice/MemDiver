# Consensus view

:::{admonition} Available in
:class: tip
**SPA** (bottom tabs `consensus` + `live-consensus`, and the hex panel's **Overlay** main view) · **Marimo** sandbox
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

## Hex overlay

The consensus vector can also be read directly in the hex panel. Select two or more dumps of the same process in the **Dumps** sidebar tab, run **Run Consensus** there (tick **ASLR Normalization** for `.msl` dumps so bytes are aligned by address), and switch the **Main view layout** to **Overlay**. If no consensus matches the selection yet, the pane says so and offers **Run consensus to classify**; a consensus built over a different set of dumps is flagged as stale instead of being painted on the wrong bytes.

- **Dump rail** — lists the aligned set. **Σ Overlay** shows the weighted plurality of every included dump; clicking a dump shows it alone (solo). Each dump can be left out of the consensus (at least one must stay) and given a weight that cycles `1.0×` → `1.5×` → `0.5×`. The status bar names what you are looking at (`Viewing: Overlay · weighted plurality of N` or `Viewing: <dump> · solo`) and the per-byte agreement.
- **Align** — **delta-fit** (default) puts bytes in correspondence by ASLR-invariant address; **raw offsets** compares byte `0x1000` with byte `0x1000` and is the control condition: expect almost every byte to differ.
- **Overlay render mode** — **Class** colours each byte by its consensus class, **Variants** by how many distinct values the dumps hold there, **Glyph** prints a colour-free mark (■ identical, 2–6 variants, ░ void). The legend follows the active mode; **What do these colours mean?** expands the band thresholds. **Differs** is drawn as a ring, not a fill, so it composes with the class colour. Hatched cells are bytes that are absent from a dump (not captured, not mapped, or no correspondence), never a difference.

The right-hand detail panel has two tabs:

- **Byte** — the byte inspector: what every selected dump really holds at the cursor (read from each dump, not the computed overlay byte).
- **Regions** — browse contiguous runs by class. The class chips (**Invariant**, **Structural**, **Pointer**, **Key Candidate**, **Differs**, **Changing**) show whole-build byte counts; **Changing** queries all three non-invariant bands at once and is usually the right chip, because real key material is class-mixed (a 48-byte TLS secret measured as 27 key-candidate + 18 pointer + 3 structural bytes). **Differs** is computed only from the window currently loaded. Clicking a row jumps the viewer to that region.

The region filter bar above the list narrows it to the sizes key material comes in:

- **Exact length** presets `16 B`, `24 B`, `32 B`, `48 B` set both bounds at once; **Any** restores the default floor of 8 bytes and removes the ceiling.
- **Min length** / **Max length** for a custom range (`0 = no limit` for the maximum).
- **Sort**: **Offset** (default), **Longest first**, **Shortest first**. Sorting and filtering happen server-side over the whole list, not just the loaded page, so **Longest first** really returns the longest candidates.

Lengths are the aligned length compared across dumps; a row marked *spans a page boundary* can list a different size. Backed by `POST /api/analysis/consensus/regions` and `POST /api/analysis/consensus/aligned-window`.
