# Pattern Architect

:::{admonition} Available in
:class: tip
**SPA** (bottom tab `architect`) · **Marimo** sandbox
:::

The SPA implementation (`frontend/src/components/research/ArchitectPlaceholder.tsx`, despite the filename) is a production 3-step wizard with Manual and Auto flows, clipboard copy, and file download — not a stub.

Converts a verified memory region into a reusable detection signature. Three export shapes:

- **YARA rule** — wildcarded hex pattern with `meta` attributes.
- **JSON signature** — `pattern_loader`-compatible schema matching what `algorithms/patterns/*.json` consumes.
- **Volatility3 plugin** — ready-to-load Python plugin for offline memory forensics.

Backed by `POST /api/architect/check-static`, `/generate-pattern`, `/export`.

## Workflow

1. Select a region in the hex viewer (or trust the Auto-Detect slider).
2. Run the static check — bytes that are identical across all dumps become the literal part of the pattern.
3. Generate — variable bytes become wildcards (`??`).
4. Export as YARA / JSON / Vol3.

See also: [](../architecture/architect.md).
