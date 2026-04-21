# Hex viewer

:::{admonition} Available in
:class: tip
**SPA** (main panel) · **Marimo** sandbox
:::

Color-coded hex / ASCII dump viewer. Virtualized rows via `@tanstack/react-virtual`; paged reads through the `/api/inspect/hex-raw` endpoint.

## Color classifications

| Class | Meaning |
|---|---|
| `INVARIANT` | identical across all runs (structural constants, `.rodata`) |
| `STRUCTURAL` | low variance; typically pointers that survive ASLR |
| `POINTER` | mid variance; ASLR-shifted pointers |
| `KEY_CANDIDATE` | high variance; possible cryptographic material |

## Overlays

- **Structure overlay** — colored fields from the structure library (TLS `SSL_SESSION`, SSH `session_id` layouts, …).
- **Neighborhood overlay** — variance slice around a selected byte offset.

```{figure} /_static/screenshots/05_hex_with_overlay.png
:alt: Hex viewer in dark theme with a TLS structure overlay coloring bytes by field role
:align: center

Hex viewer with structure overlay applied.
```
