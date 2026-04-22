# Oracle interface

A memdiver *oracle* is a short Python script that answers a single yes/no
question per candidate: **is this byte string the real key?**

You write the oracle. Memdiver owns the rest of the pipeline:

1. `consensus-begin/add/finalize` builds the variance matrix.
2. `search-reduce` narrows the candidate set via alignment + entropy.
3. `brute-force` iterates every `(offset, key_size)` slice through your
   oracle. When one returns `True`, memdiver records the hit and the
   neighborhood variance slice from the stored Welford state.
4. `emit-plugin` turns that neighborhood into a Volatility3 plugin.

The oracle is invoked via `--oracle /abs/path/to/script.py`. Memdiver
prints the SHA-256 of the loaded file to stderr on startup and refuses
to load oracles from world-writable files or directories. Beyond that
it is equivalent to `find -exec` — the script runs with your privileges,
on your evidence, with full filesystem and network access. There is no
sandbox because sandboxes break legitimate network-replay and
filesystem-probe oracles. Treat unknown oracles like any other piece of
untrusted code.

## Two accepted shapes

Memdiver auto-detects which shape you used and wraps both into a flat
`verify(bytes) -> bool` callable internally.

### Shape 1 — stateless function

Use this when your verification is cheap and has no setup cost.

```python
# my_oracle.py
EXPECTED = bytes.fromhex("deadbeef" * 8)

def verify(candidate: bytes) -> bool:
    return candidate == EXPECTED
```

Run it with:

```bash
memdiver brute-force \
    --candidates candidates.json \
    --dump reference.msl \
    --oracle /abs/path/to/my_oracle.py \
    --key-sizes 32 \
    -o hits.json
```

### Shape 2 — stateful factory

Use this when verification needs to cache derivations (KDF, scrypt),
hold a network socket open, or mmap a large ciphertext once.

```python
# tls_oracle.py
from pathlib import Path

def build_oracle(config: dict):
    return TlsOracle(config)

class TlsOracle:
    def __init__(self, config: dict):
        self.record = Path(config["encrypted_record"]).read_bytes()
        self.nonce = bytes.fromhex(config["record_nonce_hex"])
        self.handshake_hash = bytes.fromhex(config["handshake_hash_hex"])

    def verify(self, candidate: bytes) -> bool:
        if len(candidate) not in (32, 48):
            return False
        try:
            # derive keys from candidate as traffic-secret, AEAD-decrypt
            ...
            return True
        except Exception:
            return False

    def close(self):  # optional, called on teardown
        pass
```

The `config` dict comes from an optional TOML file:

```bash
memdiver brute-force \
    --candidates candidates.json \
    --dump reference.msl \
    --oracle /abs/path/to/tls_oracle.py \
    --oracle-config /abs/path/to/tls_oracle.toml \
    --key-sizes 32,48 \
    -o hits.json
```

```toml
# tls_oracle.toml
encrypted_record = "/home/you/captures/record_0.bin"
record_nonce_hex = "001122..."
handshake_hash_hex = "aabbcc..."
```

## Contract notes

- Always return a plain `bool` — not `True`/`False`/`None`, not an int.
  Non-bool returns are coerced via `bool()` but explicit beats implicit.
- **Reject the wrong key length cheaply.** The hot loop may try 16, 24,
  and 32-byte candidates at every offset — a fast length-check keeps
  expensive derivations off the short-key path.
- **Catch exceptions internally.** A raised exception is treated as a
  `False` return and logged at debug level, but a deterministic `False`
  makes stacks and latency easier to read.
- **Do not hold global state across runs.** Each `memdiver brute-force`
  invocation loads the module fresh; if you use Shape 2 with
  `--jobs > 1`, each worker process re-imports and re-runs
  `build_oracle`, so any caching must live in instance state.
- **The oracle has no visibility into which offset is being tested.**
  This is by design — memdiver owns the offset bookkeeping so the hit
  metadata (offset, neighborhood variance, vol3 anchor) stays
  consistent across all users of the interface.

## Ready-made templates

- `docs/oracle/examples/generic_aes_gcm.py` — stateless AES-GCM boilerplate.
- `docs/oracle/examples/gocryptfs.py` — HKDF + AES-GCM verification of a
  gocryptfs file-content key derived from a candidate master key.
- `docs/oracle/examples/tls13_stub.py` — TLS 1.3 traffic-secret scaffolding
  (stateful; you fill in the HKDF-Expand-Label derivation).

Copy any of these into your experiment directory, adjust the `config`
keys for your target, and point `--oracle` at the result.
