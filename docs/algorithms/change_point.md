# change_point

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/change_point.py`

CUSUM (cumulative-sum) over the entropy profile. Detects stable high-entropy plateaus — the classic signature of packed key material surrounded by structure.

## Parameters (read from `context.extra`)

| Key | Default |
|---|---|
| `window` | `32` |
| `step` | `16` |
| `entropy_threshold` | `4.5` |
| `cusum_threshold` | `0.8` |
| `drift` | `0.05` |
| `plateau_widths` | `[32, 48]` |

## Output

`Match.label = "cusum_plateau_{N}B"`. Typically fed into `constraint_validator` downstream.
