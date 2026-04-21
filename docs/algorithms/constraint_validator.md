# constraint_validator

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/constraint_validator.py`

Verifies TLS KDF relationships among candidate matches. Takes a list of candidates (typically from `entropy_scan`, `change_point`, or `differential`) and checks whether they derive one from another via the protocol's KDF chain.

## Parameters (read from `context.extra`)

| Key | Default |
|---|---|
| `candidates: List[Match]` | required |

Protocol routing is automatic based on `context.protocol_version` (TLS12, TLS13, SSH2). The underlying KDF plugins live in `core/kdf_*.py`.

## Output

`Match.label` is one of `kdf_validated_*` (constraint held) or `kdf_probe_*` (tested but inconclusive). Confidence is opportunistically upgraded to 1.0 when `context.secrets` confirms the derivation.
