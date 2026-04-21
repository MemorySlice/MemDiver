# architect/

Pattern Architect — turns verified finds into reusable detection artifacts.

- `static_checker.StaticChecker.check(dumps)` — per-offset equality across N dumps → `(static_mask, reference_bytes)` + `static_ratio` helper.
- `pattern_generator.PatternGenerator` — static-mask → wildcard substitution; `find_anchors` (contiguous static runs ≥ `min_anchor_length=4`) + `infer_fields` (variance-based segmentation into `static` / `dynamic` / `key_material`).
- `yara_exporter.YaraExporter` — emits `rule NAME { meta: ... strings: $key = { WILDCARD_HEX } condition: $key }`.
- `json_exporter.JsonExporter` — emits `pattern_loader`-compatible signatures (`key_spec`, `applicable_to.libraries`, `applicable_to.protocol_versions`, structural `pattern.before` / `pattern.after`).
- `volatility3_exporter.Volatility3Exporter` — synthesizes a ready-to-load Volatility3 plugin.
