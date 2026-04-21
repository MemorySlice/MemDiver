# entropy_scan

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/entropy_scan.py`

Shannon-entropy sliding window over the dump. Emits a `Match` for every window whose entropy exceeds `entropy_threshold`.

## Parameters (read from `context.extra`)

| Key | Default |
|---|---|
| `window_sizes` | `[32, 48]` |
| `entropy_threshold` | `4.5` |
| `step` | `1` |

## Output

`Match.label = "high_entropy_{N}B"` where `N` is the window size. High-entropy regions are the primary seed for downstream candidate reduction.
