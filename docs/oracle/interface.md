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
to load oracles from group- or world-writable files or directories.
Before importing the script in-process it replays the *load path* —
`import` plus `build_oracle(config)`, never `verify()` — in a throwaway
subprocess under a wall-clock timeout and best-effort CPU/memory limits
(`MEMDIVER_ORACLE_SANDBOX_TIMEOUT`, `MEMDIVER_ORACLE_SANDBOX_CPU`,
`MEMDIVER_ORACLE_SANDBOX_MEM`; see [](../user_guide/configuration.md)),
so an oracle that hangs or exhausts memory while loading is rejected
before it can take the process down. That probe is the only containment:
`verify()` itself runs unsandboxed, equivalent to `find -exec` — the
script runs with your privileges, on your evidence, with full filesystem
and network access, because sandboxes break legitimate network-replay and
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
  `build_oracle`, so any caching must live in instance state. Note that
  `--jobs` defaults to `0` = auto, which resolves to a small worker pool
  for a large exhaustive sweep — so a multi-worker run is now the default
  path, not an opt-in. Keep `build_oracle` cheap; it runs once per worker.
  Pass `--jobs 1` to force the single-process path.
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

## Running oracles from the web UI

The pipeline wizard's **Oracle** stage drives the same registry through
`/api/oracles` (`api/routers/oracles.py`).

**Enable an oracle directory first.** Oracles are stored in, and executed
from, a dedicated directory, and storing one is a consent decision, so it
is off until you opt in. The Oracle stage shows a consent panel that calls
`POST /api/oracles/enable` (optional body `{"path": "/abs/dir"}`; the
default is `<memdiver home>/oracles`). The directory is validated, created
with mode `0o700`, saved in the user-local `<memdiver home>/config.json`
and takes effect immediately. The precedence is `MEMDIVER_ORACLE_DIR`
(environment or `.env`) > the saved choice > disabled; an empty
`MEMDIVER_ORACLE_DIR` counts as unset. While the variable is set the UI
cannot change the directory — `POST /enable` answers **409** and
`GET /api/oracles/status` reports `env_pinned: true` and `source: "env"`.
Until a directory is enabled, upload and example-load answer **503**
(and there is nothing registered to arm or delete). Full details: [](../user_guide/configuration.md#directories-chosen-in-the-ui).

**Three gates.** An uploaded (or example-loaded) oracle is checked
leniently at upload — only a hang or crash during the load probe is
refused, because a Shape 2 oracle with no config yet is expected to raise
— and stored as `<uuid>.py` at mode `0o600`, unarmed. **Arming**
(`POST /api/oracles/{id}/arm`) is strict: the body echoes the sha256 the UI
displayed (409 on mismatch with the file on disk), may carry the oracle's
`config`, rejects config values that still contain an unexpanded `${VAR}`
placeholder, and replays the load with that config. The brute-force run
loads it strictly again. Registered oracles survive a server restart, but
always come back unarmed.

**Testing before arming.** Neither test needs the oracle to be armed:

- `POST /api/oracles/{id}/dry-run` grades up to 64 base64 samples *you*
  choose and returns pass/fail counts — it only means as much as the
  samples do.
- `POST /api/oracles/{id}/smoke-test` lets the server choose
  (`source_paths` required; `key_size` default 32, `negatives` default 15):
  one **positive control** — the run's master key from the `meta.json` that
  owns the first dump — plus N **negative controls**: real `key_size`-byte
  windows read at random offsets of that same first dump
  (`app/oracle_smoke_test.py`). Offsets are drawn in the dump's `vas`
  (captured-memory) view, or `raw` for a flat dump — never the zero-padded
  `va` view, so no negative is a byte the dump did not capture. A window equal
  to the key is redrawn, and windows with fewer than 8 distinct byte values
  are used only as a last-resort top-up, reported in
  `negatives.low_entropy_included` and in `caveats`. Pass `seed` for a
  reproducible draw. It returns a `verdict`:

  | `verdict` | Meaning |
  |---|---|
  | `accepts_noise` | At least one random dump window was accepted — the oracle says yes to arbitrary memory. Takes precedence over everything else. |
  | `no_positive_control` | No ground-truth key was available (e.g. the dump is not part of a corpus with `meta.json`); only the negatives were tested. |
  | `discriminates` | The real key was accepted **and** at least one negative was cleanly rejected. |
  | `inconclusive` | The real key was accepted, but no negative was cleanly rejected. |
  | `never_accepts` | The oracle rejected its own known-good key. |

  The response never echoes sample bytes, because the positive control is
  the run's master key.

The bundled examples and their config auto-fill are described in
[](examples.md#using-the-examples-from-the-web-ui).
