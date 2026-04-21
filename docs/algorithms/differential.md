# differential

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/differential.py`

Byte-level variance across ≥2 dumps, DPA-inspired. Regions whose byte values change between runs but whose length matches a target key size (32, 48) are candidate keys.

## Parameters (read from `context.extra`)

| Key | Default |
|---|---|
| `dump_paths: List[Path]` | required, ≥2 |

Class constants: `TARGET_KEY_LENGTHS = [32, 48]`, `LENGTH_TOLERANCE = 8`, `MAX_GAP_BYTES = 4`.

## Output

`Match.label = "diff_key_candidate_{N}B"`. Requires at least 2 dump paths or the algorithm returns confidence 0.
