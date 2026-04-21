# api/

FastAPI backend. Serves the built React bundle at `/` and the Marimo notebook at `/notebook` (when installed). All routers mounted under `/api/*`, plus a WebSocket at `/ws/tasks/{task_id}`.

## Routers

| Prefix | Responsibility |
|---|---|
| `/api/dataset` | Scan, list protocols, list phases. |
| `/api/analysis` | Run, consensus, verify-key, auto-export. |
| `/api/inspect` | Hex, entropy, strings, structure overlay, VAS, module / process / connection / handle tables. |
| `/api/sessions` | `.memdiver` session CRUD. |
| `/api/tasks` | Background-task status + cancellation. |
| `/api/dumps` | Multipart upload → MSL convert. |
| `/api/path` | File-browser — detects single-file / run-dir / dataset mode. |
| `/api/structures` | Structure library + Kaitai import/export. |
| `/api/architect` | Static check, pattern generate, export (YARA / JSON / Vol3). |
| `/api/consensus` | Incremental Welford consensus sessions. |
| `/api/oracles` | BYO-oracle registry (gated by `MEMDIVER_ORACLE_DIR`). |
| `/api/pipeline` | Phase-25 pipeline orchestration. |
| `/ws/tasks/{id}` | WebSocket progress stream (ring buffer + HTTP fallback). |
| `/api/tasks/{id}/events` | HTTP backfill endpoint registered by the same WS router; returns buffered events when the WebSocket ring has rolled past a client's last-seen sequence. |
| `/api/notebook/status` | Top-level status probe reporting whether the Marimo notebook mount at `/notebook` is available. |

## Progress bus

Background tasks run in a shared `ProcessPoolExecutor` with an `asyncio.Semaphore(1)` gating outer runs. Progress events (`stage_start`, `progress`, `stage_end`, `funnel`, `nsweep_point`, `oracle_tick`, `oracle_hit`, `artifact`, `done`, `error`) flow through a `ProgressBus` with per-task 512-event ring buffers.

## Persistence

Task records are atomically persisted to `<task_root>/<id>/record.json`; orphan `RUNNING` records are reset to `FAILED` on app restart.

## Middleware

- **CORS** — `CORSMiddleware` with `allow_origins=settings.cors_origins` (default `["http://localhost:5173"]`).
- **GZip** — `GZipMiddleware` with `minimum_size=1000`.
- No authentication; MemDiver is local-only.

## OpenAPI

`/docs` (Swagger), `/redoc` (ReDoc), `/openapi.json`.
