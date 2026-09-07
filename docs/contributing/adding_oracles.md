# Adding a decryption oracle

See [](../oracle/interface.md) for the complete interface contract, and [](../oracle/examples.md) for three ready-to-copy templates.

Summary:

- **Shape 1** — stateless function `verify(data: bytes) -> bool`.
- **Shape 2** — stateful factory `build_oracle(config: dict) -> Oracle` where `Oracle` implements `verify` + `close`.

Both shapes are loaded by `engine.oracle.load_oracle`, which refuses world-writable paths and prints a sha256 fingerprint of the loaded script to stderr. Oracles can be armed via:

- CLI: `memdiver brute-force --oracle path/to/oracle.py --oracle-config config.toml …`
- HTTP: `POST /api/oracles/upload` (requires `MEMDIVER_ORACLE_DIR`), then `POST /api/oracles/{id}/arm`.
- MCP: the `brute_force` / `n_sweep` tools accept an oracle path.

## Verification resources (`memdiver.oracles`)

A third shape sits beside those two: the **first-party builtin resource oracle**
(`engine/resources/builtin_oracle.py`), which is a Shape 2 oracle whose config
selects a *verification resource* by name instead of pointing at a user script:

```toml
resource_type = "tls-pcap"        # the only built-in type
pcap = "/path/to/session.pcap"
```

New resource kinds register a factory under a name:

```python
from memdiver.engine.resources.builtin_oracle import register_resource_type

register_resource_type("my-resource", lambda config: MyResource(config["path"]))
```

An installed package can add its own by advertising that registration under the
`memdiver.oracles` entry-point group — a module (imported for its
`register_resource_type` side effect) or a callable (invoked to self-register):

```toml
[project.entry-points."memdiver.oracles"]
my_resource = "my_pkg.memdiver_resource"      # module, or "...:register" callable
```

Discovery is lazy (first `build_resource` call), additive, failure-isolated, and
a silent no-op when nothing is installed.

**No trust is inherited.** `register_resource_type` records whether a type came
from in-tree code or from an entry point. Only in-tree types are loaded with the
untrusted-code sandbox disabled — an entry-point type always goes through
`validate_oracle_sandboxed`, so installing a package can never buy unsandboxed
execution. See `is_first_party_resource_type`.
