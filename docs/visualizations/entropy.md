# Entropy profile

:::{admonition} Available in
:class: tip
**SPA** (bottom tab `entropy`) · **Marimo** sandbox
:::

Shannon entropy vs byte offset. For each of ~1500 buckets of window positions the chart draws the min–max band over **every** window in the bucket (step 1) and the maximum as a line, so a lone 32-byte key shows as a spike instead of falling between samples. Shaded bands mark high-entropy regions: runs of windows at or above the threshold covering at least 32 bytes.

**Threshold.** The default is window-aware: 4.5 bits/byte at the default 32-byte window (the same value `entropy_scan` uses), scaled with the expected entropy of random bytes for other windows (16 → 3.63, 64 → 5.31, 256 → 6.61, 1024 → 7.20). A window of *w* bytes can reach at most log2(min(*w*, 256)) bits/byte (5.0 for 32, drawn as a dashed line); the former fixed default 7.5 was unreachable below 182-byte windows and never reported anything. An explicit `threshold` is used as given; if it is unreachable the response says so (`threshold_reachable: false`, warning `threshold_unreachable`) and the chart shows a warning.

**Resolution.** `resolution=full` visits every window (exact region membership, envelope from the fixed-point estimate, error < 1e-9); `sampled` is the bounded-step profile; `auto` (default) is full up to 8 MiB and sampled above, with `full_resolution_available: true` — the SPA then shows the sampled chart immediately and replaces it with the full one when the follow-up request returns.

Backed by `GET /api/inspect/entropy?window=32&buckets=1500&resolution=auto` (optional `threshold`, `view=raw|vas|va`). Response fields added on top of the historical ones: `envelope` (`starts`/`stops`/`min`/`max`/`mean` columns), `resolution`, `full_resolution_available`, `threshold`, `threshold_source`, `max_entropy`, `threshold_reachable`, `warnings`, `region_count`, `regions_truncated` (list capped at 2000), `min_region_bytes`, and `byte_end` per region.

```{figure} /_static/screenshots/06_entropy_tab.png
:alt: Entropy profile — Shannon entropy per 32-byte window plotted against offset, with high-entropy regions shaded red
:align: center
```
