# engine/

The analysis orchestrator. Not an algorithm itself — it composes the 8 algorithm plugins, the consensus vector, the oracle, and the exporter into coherent pipelines.

## Pipelines

- `pipeline.AnalysisPipeline` — classic `consensus → search → DiffStore → optional verify`.
- `pipeline_runner.run_pipeline` — Phase-25 worker-safe orchestrator with five stages (`build_consensus → run_reduce → run_brute_force → run_nsweep → run_emit_plugin`), emitting progress events onto an `mp.Queue`.
- `candidate_pipeline.reduce_search_space` — composable `variance-mask → aligned-mask → entropy-coverage-mask`, O(total_size) memory.

## Consensus

- `consensus.ConsensusVector` — per-byte variance across N dumps; incremental Welford API so dumps can stream.
- `consensus_msl` — ASLR-aware path that aligns regions via `core.region_align` before variance.

## Brute force &amp; sweep

- `brute_force.run_brute_force` — serial or spawn-safe `ProcessPoolExecutor` with per-worker oracle import.
- `nsweep.run_nsweep` — user-facing N-sweep harness emitting JSON / Markdown / Plotly HTML.

## Oracle &amp; verification

- `oracle.load_oracle` — dual-shape (`verify(bytes) -> bool` vs `build_oracle(config)` factory); refuses world-writable paths, logs sha256 on stderr.
- `verification.AesCbcVerifier` — default verifier; `VERIFIER_REGISTRY` is the extension point.

## Exports

- `vol3_emit.emit_plugin_for_hit` — synthesizes a Volatility3 plugin from neighborhood variance + reference bytes via `architect.PatternGenerator`.

## Persistence

- `project_db.ProjectDB` — DuckDB + Ibis append-only schema (`projects`, `dumps`, `analysis_runs`, `findings`).
- `session_store.SessionStore` — gzipped `.memdiver` session snapshots with schema versioning.

## Concurrency

Threads for I/O-bound; `spawn`-context `ProcessPoolExecutor` for CPU-bound oracle work. Cooperative cancellation via `cancellation.CancellationToken` (an `mp.Event` wrapper).
