# Adding a decryption oracle

See [](../oracle/interface.md) for the complete interface contract, and [](../oracle/examples.md) for three ready-to-copy templates.

Summary:

- **Shape 1** — stateless function `verify(data: bytes) -> bool`.
- **Shape 2** — stateful factory `build_oracle(config: dict) -> Oracle` where `Oracle` implements `verify` + `close`.

Both shapes are loaded by `engine.oracle.load_oracle`, which refuses world-writable paths and prints a sha256 fingerprint of the loaded script to stderr. Oracles can be armed via:

- CLI: `memdiver brute-force --oracle path/to/oracle.py --oracle-config config.toml …`
- HTTP: `POST /api/oracles/upload` (requires `MEMDIVER_ORACLE_DIR`), then `POST /api/oracles/{id}/arm`.
- MCP: the `brute_force` / `n_sweep` tools accept an oracle path.
