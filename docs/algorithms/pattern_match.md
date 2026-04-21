# pattern_match

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/pattern_match.py`

Structural pattern matcher. Loads every JSON under `algorithms/patterns/` and applies the ones whose `applicable_to.libraries` + `applicable_to.protocol_versions` match the context. Internally re-invokes `EntropyScanAlgorithm` to seed candidate windows.

## JSON pattern schema

```json
{
  "name": "boringssl_tls13_exporter",
  "applicable_to": {
    "libraries": ["boringssl"],
    "protocol_versions": ["TLS13"]
  },
  "key_spec": { "length": 32, "entropy_min": 4.5 },
  "pattern": {
    "before": [ { "offset": -8, "bytes": "00010203...", "mask": "ffff..." } ],
    "after":  [ { "offset": 32, "bytes": "...",         "mask": "..." } ]
  }
}
```

Three ship out of the box: `boringssl_tls13.json`, `openssl_tls12.json`, `openssh_ssh2.json`.
