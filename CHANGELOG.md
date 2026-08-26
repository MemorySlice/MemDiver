# Changelog

All notable changes to MemDiver are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Brute-force `--stride` now defaults to `1` (was `8`).** The candidate grid
  is absolute, so the old default handed the oracle only 8-aligned offsets and
  a secret at, e.g., offset `585148` was never tested — the run ended
  *successfully* with zero hits, indistinguishable from "the key is not in this
  dump". The new default sweeps every offset (`coverage_fraction == 1.0`) on
  every product surface (CLI, MCP, web API, pipeline runner, engine, frontend);
  the Phase-A experiment (`engine/candidate_stats.py::run_phase_a` and
  `scripts/phase_a_experiment.py`) stays at `8` as frozen paper reproduction.
  Raising the stride is now an opt-in speed tradeoff. The web UI's
  *Replicate gocryptfs DFRWS* recipe still pins `stride 8` to reproduce the
  published result.
  - **Existing browser sessions are migrated.** The pipeline wizard's form is
    persisted to `localStorage`, so a browser that had already stored the old
    `stride: 8` would have gone on running at 15.7 % coverage no matter what
    the shipped default said — the new default only ever applied to a fresh
    profile. The pipeline store moves to schema `version 2` with a targeted
    migration that rewrites *only* a stale `bruteForce.stride === 8` to `1`.
    A hand-picked stride (2, 4, 16, …) is left alone, and every other saved
    field — selected dumps, armed oracle/pcap, reduce thresholds, wizard
    stage, in-flight task id — is carried across untouched. Nobody has to
    clear site data to get the fix.
  - **The candidate pre-count is now closed-form.** `count_candidate_slices`
    ran a full discard-iteration over the grid before every sweep purely to
    produce a progress denominator — ~700k wasted steps per run at the new
    default, and once per N in an n-sweep. It now delegates to the O(1)
    `count_region_grid` that already backed `count_possible_candidates`
    (~37 s → sub-millisecond on a 4·10⁸-window span). Counts are unchanged;
    the two functions are the same arithmetic and the equivalence is pinned.
- **The brute-force stage is cancellable mid-sweep on the web and MCP
  surfaces.** The producer passed only `progress_callback` to the engine and
  consulted `is_cancelled` exactly once, *before* the first candidate, which
  left `engine.progress.check_cancel` dead code on those paths — so a cancel
  was ignored for the whole run. Tolerable over 110k candidates; not over the
  ~700k the stride-1 default now enumerates. The cancel token is threaded into
  the sweep and the engine's `Cancelled` is re-expressed as the app layer's
  canonical `code="cancelled"` signal, so it is indistinguishable from one
  observed at a stage boundary.
- **MSL implementation declares conformance with the official Memory Slice
  Specification v1.0.0** (<https://github.com/MemorySlice/memslice-spec>):
  - Reader rejects unknown MSL major versions per spec §3.4 and rejects any
    Endianness byte other than `0x01` per spec §3.1 (strict consumer rules).
  - Writer now sets the Capability Bitmap accurately per spec §9 (MUST), with
    bits OR'd in for every emitted data category (MemoryRegions, ModuleList,
    CryptoHints, RelatedDumps, ProcessIdentity, SystemContext, Process /
    Network / Handle tables).
  - Writer validates `PageSizeLog2 ∈ [10, 40]` and `RegionSize % PageSize == 0`
    per spec §5.1; the decoder rejects out-of-range `PageSizeLog2` per
    spec §14.2 rule 10.
  - Writer adds full Investigation-mode support per spec §6: Process Identity
    (Block 0), Module List Index + Module Entry children (Block 1), System
    Context (Block 2), and Process/Connection/Handle table children. Block
    ordering is enforced at `write()` time.
  - Writer emits the spec's three-state page model (CAPTURED / FAILED /
    UNMAPPED) when `add_memory_region(..., page_states=...)` is supplied;
    legacy callers without `page_states` continue to get all-CAPTURED maps.
  - `msl/importer.py` zero-pads raw `.dump` inputs to a page boundary so
    imported regions satisfy spec §5.1; the original size is preserved in
    `IMPORT_PROVENANCE.orig_file_size`.
  - Documentation file `docs/file_formats/msl_v1_1_0.md` renamed to
    `msl_v1_0_0.md` to reflect the spec document version (the on-wire
    binary format byte at file header offset `0x0A` remains `0x0101`,
    which the spec calls "format 1.1").
- **Interface deps moved to extras (breaking):** `pip install memdiver` now
  installs only the library + CLI core. The FastAPI web UI + REST API
  (`fastapi`/`uvicorn`/`pydantic-settings`) live behind `[api]`, the MCP server
  behind `[mcp]`, and the legacy Marimo UI behind `[marimo]`. `[all]`
  (= `memdiver[api,mcp,marimo]`) reproduces the
  previous all-in-one install. `kaitaistruct` and the crypto stack remain base
  deps; `[experiment]` and `[dev]` are unchanged.
- `memdiver experiment` now surfaces an actionable install hint
  (`pip install memdiver[experiment]`) when the experiment extras are missing,
  instead of raising a bare ImportError.
- `LICENSE` file replaced with the canonical Apache License 2.0 text (was
  previously MIT). The `pyproject.toml` classifier was updated to
  `License :: OSI Approved :: Apache Software License` to match.
- Install-hint messages in `memdiver web` / `app` / `mcp` / `ui` now point at
  the specific extra (`memdiver[api]` / `[mcp]` / `[marimo]`) when
  the corresponding dependency is not installed.

### Security
- **`POST /api/analysis/export-keylog` contains `output_path` to the upload
  directory.** The handler passed the request string straight to
  `keylog_result`, which does `Path(output_path).write_text(...)` — an
  unauthenticated caller on a token-less localhost instance could write a
  file of largely chosen content to any path the server user owns (a shell rc,
  `~/.ssh/authorized_keys`, a `.pth` in site-packages). It now resolves through
  `ensure_within(settings.upload_dir, …)` and rejects an escape with 400,
  disclosing no server layout. This API's *read* path parameters remain an
  accepted, documented localhost risk; a write is a different class. The shared
  producer is deliberately unchanged, so the CLI and MCP surfaces still write
  wherever the operator's own shell can.

### Fixed
- **A typed server-side capture can be armed again.**
  `POST /api/pcaps/validate` contained `pcap_path` to the upload directory while
  `POST /api/pipeline/run` — the same parameter, the same capture — only checked
  existence. Since the UI's manual *Arm / re-validate* control routes through
  `/validate`, the "type a server-side path instead of uploading" flow
  documented in `docs/oracle/pcap_oracle.md` was broken: the capture could be
  run but never armed. Both endpoints now apply the same existence check.

### Added
- **PCAP verification oracle** — a first-party *trusted* oracle that proves a
  recovered secret by deriving record keys from it and AEAD-decrypting records
  of a real captured TLS session (TLS 1.3, TLS 1.2 GCM, TLS 1.2 CBC). Because
  it is MemDiver's own code and the capture is only ever parsed as data, never
  executed, it runs **outside** the untrusted-oracle sandbox that
  bring-your-own oracle scripts require. Capture parsing lives in
  `engine/resources/tls_pcap.py` (`TlsPcapResource` emits one
  `DecryptionChallenge` per encrypted application-data record); derivation and
  the AEAD/CBC checks stay in the oracle. Hits it confirms are stamped
  `verified: true` and `confirmed_by: "pcap"`. Parsing needs `dpkt`, behind the
  new `memdiver[pcap]` extra (`[all]` now expands to `api,mcp,marimo,pcap`);
  without it the arm/run steps surface an `INVALID_INPUT` capability error.
- `brute-force --pcap <capture>` on every surface, **mutually exclusive with
  `--oracle`** — a run confirms candidates either through a BYO script or
  against a capture, never both. `--tls-client-random <hex>` restricts matching
  to one session; `n-sweep` and `escalate` remain oracle-only.
- `inspect_pcap` — the "arm" producer that summarises a capture's TLS sessions
  (`client_random`, `server_random`, version, cipher suite, per-direction
  application-record counts, `has_app_records`), backed by
  `TlsPcapResource.describe_sessions()` and exposed on all four surfaces: CLI
  `memdiver inspect-pcap`, MCP `inspect_pcap`, web `POST /api/pcaps/validate`,
  library `memdiver.services.inspect_pcap`.
- `api/routers/pcaps.py` — `POST /api/pcaps/upload` streams a `.pcap` /
  `.pcapng` / `.cap` in 1 MiB chunks to `settings.upload_dir/pcaps/`, creating
  the file `0o600` via an `O_CREAT|O_EXCL` opener so a secret capture is never
  briefly group/world-readable, rejects a disallowed suffix with 400 and an
  over-cap upload with 413 (`PCAP_UPLOAD_MAX_BYTES` = 512 MiB, partial file
  removed), then LRU-prunes the persisted dir back under
  `settings.pcap_quota_bytes` (default 5 GiB) oldest-mtime-first, never
  evicting the just-uploaded capture. `POST /api/pcaps/validate` arms a
  persisted capture, `ensure_within`-confined to the upload dir.
- `POST /api/pipeline/run` accepts `pcap_path` + `tls_client_random` as a
  mutually exclusive alternative to `oracle_id` — exactly one oracle source is
  required (400 otherwise), and a pcap run carries `oracle_path: None` because
  there is no BYO oracle file to hash.
- Web pcap flow in the pipeline wizard's oracle stage: `PcapUpload`
  drag-and-drop uploader with a TLS-session picker (click a session to pin its
  `client_random`, or "match any session"; sessions without application-data
  records are marked unusable), driven by the shared `usePcapArm` hook
  (`frontend/src/components/pipeline/oracle/use-pcap-arm.ts`) reused by
  `StageOracle` for the manual-path re-validate control.
- Multi-secret NSS key-log composer in `KeyVerificationPanel` — add one row per
  secret (NSS label dropdown, `client_random`, secret hex), prefill the
  `client_random` from a selected pcap session, and export the whole set as one
  Wireshark-loadable key log.
- Provenance reaches the results UI: `frontend/src/components/results/provenance.ts`
  narrows the backend `confirmed_by` label to `pcap` / `oracle` / `verifier`
  (anything else falls back to a generic label rather than leaking a raw i18n
  key), and `VerificationBadge` renders it — a pcap-confirmed hit reads
  "Verified via pcap capture".
- `--persist-ground-truth` (CLI and MCP `brute_force`, opt-in) files
  pcap-confirmed hits into the project's DuckDB ground-truth ledger via
  `ProjectDB.record_ground_truth_run(..., confirmed_by="pcap")`, mapping each
  recovered key to its byte value for the survival/labelling analytics; a no-op
  when the DuckDB backend is unavailable.
- `docs/oracle/pcap_oracle.md` — walkthrough of the arm/run model, the
  four-surface table, and the two traps: `--key-sizes` (the candidate must
  match the *secret* — 32 for a TLS 1.3 traffic secret, 48 for a TLS 1.2 master
  secret) and `--stride` (the absolute grid, with measured coverage numbers
  from a real corpus dump).
- `pip install memdiver[experiment]` extra, pinning `frida-tools>=12.0` and
  `memslicer` for the dump-collection flow.
- GitHub Actions workflows:
  - `ci.yml` — pytest matrix (Python 3.11 / 3.12) on push / PR.
  - `publish.yml` — OIDC trusted publishing to PyPI on `v*` tag push, plus
    TestPyPI dry-runs via `workflow_dispatch`. Includes a `npm ci && npm run
    build` step so the React bundle is baked into every wheel.
- `MANIFEST.in` — ensures `LICENSE`, `README.md`, `CHANGELOG.md`, algorithm
  patterns, and the full `frontend/dist/` tree ship in the sdist.
- `frontend/dist/**/*` added to `[tool.setuptools.package-data]` so the built
  React bundle ships in the wheel; it is served once the web UI is installed via
  `pip install memdiver[api]`.
- Sphinx documentation site under `docs/` (Read the Docs theme, MyST-parser),
  published to <https://memoryslice.github.io/MemDiver/> via GitHub Pages.
  Covers quickstart, full user guide, ten-subsystem architecture walkthrough,
  eight algorithm reference pages, nine visualization pages, `.msl` v1.1.0
  file-format spec, Oracle interface + examples, and a 12-module Python API
  reference generated via `autodoc` + `napoleon`.
- `.github/workflows/docs.yml` — strict Sphinx build on every push and PR,
  Pages deploy gated to `main` (re-enabled after one-time repo Settings
  configuration).
- `.github/workflows/docs-screenshots.yml` — nightly Playwright refresh of
  the 11 baseline screenshots under `docs/_static/screenshots/`, opening a
  pull request on visual drift.
- Logo pipeline: `docs/_static/{logo,logo_simple}.svg` (both with `<title>`,
  `<desc>`, `role="img"` for accessibility), `docs/_static/favicon.ico`
  (multi-resolution 16/32/48), `docs/_static/logo_readme.png` (PyPI-safe
  512×512 raster), regenerator at `scripts/build_logo.py --check`.
- Playwright screenshot harness under `docs/screenshots/` — `capture.py`
  (deterministic Chromium driver with 10 flake-reduction techniques),
  `seed_data.py` (wraps the six `tests/fixtures/generate_*.py` generators),
  `captions.json` (per-slug alt text + viewport), and
  `generate_placeholders.py` for fresh clones.
- `docs` extra (`pip install memdiver[docs]`) pinning Sphinx 7.4,
  `sphinx-rtd-theme`, `myst-parser`, `sphinx-copybutton`, `sphinx-design`,
  `sphinxcontrib-mermaid`, `sphinx-argparse`, `cairosvg`, `pillow`.
- `cli.py` — public `build_parser()` alias exposed for `sphinx-argparse` and
  external tooling.
- Repo-root `__init__.py` — `__version__` now resolves dynamically via
  `importlib.metadata.version("memdiver")` instead of the drifted hard-coded
  `"0.1.0"`.
- `pyproject.toml` — canonical project URLs updated to
  `github.com/MemorySlice/MemDiver`; added a `Documentation` URL pointing at
  the GitHub Pages site.
- README overhaul — accurate capability counts (8 algorithms, 20 CLI
  subcommands, 12 FastAPI routers, 15 MCP tools), Apache-2.0 badge, MCP
  one-line wiring snippet, thumbnail gallery linking into the docs site.

### Deferred follow-ups
- **`user_regex` confidence calibration** —
  `algorithms/unknown_key/user_regex.py:48` returns `min(total / 10.0, 1.0)`,
  an arbitrary heuristic that inflates confidence on dense matches.
  Track a calibration task: parameterize the divisor via context, or
  compute confidence per-pattern from match density × pattern complexity.
- **e2e dataset gate** — 24 of 25 Playwright specs in `tests/e2e/specs/`
  skip when no private dataset is mounted (`test.skip(!datasetAvailable, ...)`).
  CI cannot exercise the SPA without it. Track a task to either (a) build a
  minimal synthetic `.msl` fixture under `tests/e2e/fixtures/synthetic_msl/`
  or (b) tag specs `requires-dataset` and document the CI strategy.

## [0.5.1] — 2026-04-14

- TLS polymorphic structures + FTUE tour framework
  (841 tests).
- (packaging/ops) resolved — MemDiver is now PyPI-publishable.
