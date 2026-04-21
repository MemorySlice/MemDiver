# exact_match

**Mode:** `known_key` &nbsp;·&nbsp; **File:** `algorithms/known_key/exact_match.py`

Literal byte-search for known secrets. Requires `context.secrets` (parsed from `keylog.csv`).

## Inputs

| Parameter | Source | Default |
|---|---|---|
| `context.secrets: List[CryptoSecret]` | ground-truth keylog | required |

## Output

For each secret in `context.secrets`, calls `dump_data.find(secret_bytes)` and emits a `Match` with `confidence = 1.0` on hit. Overall confidence = fraction of distinct `secret_type`s located.

## When to use

- Verifying a dataset contains the secrets the keylog claims.
- Benchmarking unknown-key algorithms against a ground-truth oracle.
