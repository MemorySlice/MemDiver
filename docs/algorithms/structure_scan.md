# structure_scan

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/structure_scan.py`

Structural overlay scanner. Walks the dump for high-entropy regions using module-level constants in `algorithms/unknown_key/structure_scan.py` (`_ENTROPY_THRESHOLD = 6.5`, `_SCAN_WINDOW = 32`, `_SCAN_STEP = 16`), then tries every structure in `core.structure_library` as an overlay and emits the best match per region.

## When to use

- Libraries with richly structured key material (TLS 1.3 traffic secrets inside `SSL_SESSION`, SSH `KEX` state).
- When you already have a Kaitai-Struct or structure-definition JSON for the target and want to annotate the hex viewer.

## Output

`Match.label = "struct:<structure_name>"`. Feeds the "Structure overlay" detail-panel view in the React SPA.

## Note

The README's original "7 algorithms" count omitted this one. It is a first-class, default-enabled algorithm.
