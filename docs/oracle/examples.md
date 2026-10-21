# Oracle Examples

Ready-to-copy templates demonstrating the two oracle shapes documented in [](interface.md). Save these under your project's `oracles/` directory, edit the marked constants, and point the MemDiver brute-force / n-sweep runners at them.

## `generic_aes_gcm.py` — stateless AES-GCM

```{literalinclude} examples/generic_aes_gcm.py
:language: python
:linenos:
```

## `gocryptfs.py` — stateful factory, HKDF-SHA256 + per-block AEAD

```{literalinclude} examples/gocryptfs.py
:language: python
:linenos:
```

## `tls13_stub.py` — TLS 1.3 traffic-secret verification scaffold

```{literalinclude} examples/tls13_stub.py
:language: python
:linenos:
```

## Using the examples from the web UI

The pipeline wizard's Oracle stage lists every `*.py` in `docs/oracle/examples/`
(files starting with `_` are skipped) through `GET /api/oracles/examples`. Each
entry carries the file's `sha256`, detected `shape`, a one-line `summary` and its
first lines, plus — when a sibling `<name>.toml` exists — a `config_template` the
UI prefills its config form from and `config_placeholders` naming the template
keys that are questions rather than answers.

Picking an example calls `POST /api/oracles/examples/{filename}/load`, which
copies the file into the enabled oracle directory and registers it through the
**same** path as an upload (mode `0o600`, `__pycache__` purge, sandboxed load
probe, shape detection) — shipping a file in the repo is not a trust decision.
It needs an enabled oracle directory, like an upload; see
[Running oracles from the web UI](interface.md#running-oracles-from-the-web-ui).

### Config auto-fill (`[memdiver]` table)

An example's `.toml` may contain a reserved `[memdiver]` table. It is MemDiver's
own automation metadata: it is stripped before the config reaches
`build_oracle()`, so an oracle never sees it. `gocryptfs.toml` uses it like this:

```toml
[memdiver]
requires_cipher = "aes"

[memdiver.autofill.sample_ciphertext]
strategy = "vault_content_file"
exclude = ["gocryptfs.conf", "gocryptfs.diriv"]
```

`POST /api/oracles/examples/{filename}/suggest-config` (body
`{"source_paths": [...]}`, the dumps already selected in the wizard) turns that
into a suggestion (`app/oracle_autoconfig.py`):

- Only the **first** selected dump matters — it is the reference the sweep
  verifies against. Its run's `meta.json` (`core/dataset_metadata.py`) is looked
  up; a selection spanning several runs adds a warning.
- `vault_content_file` (the only strategy implemented) fills the key with the
  encrypted file in the run's declared `vault_cipher_dir`, skipping the
  `exclude` names. It fills only when exactly one candidate file remains;
  otherwise the field stays empty and a warning names the directory.
- If the run's `cipher` does not match `requires_cipher` (for gocryptfs: an
  `xchacha` run against the AES-only oracle), nothing is prefilled and
  `blocked_reason` says why, because such a run could never produce a hit.
- A dump outside any corpus is a 200 with an empty `config` — fill the field by
  hand. Only an unknown example filename is an error (404).
