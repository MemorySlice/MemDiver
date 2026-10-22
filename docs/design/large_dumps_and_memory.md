# Large dumps and memory use

Design note: how MemDiver keeps RAM bounded on multi-GiB dumps, what each
analysis path costs today, and what is still size-proportional. Every
statement below names the file that implements it.

## 1. Memory budget and guard

- **Budget** (`core/memory_budget.py`, `resolve_memory_budget`): available RAM
  (psutil if importable, else `/proc/meminfo`, macOS `vm_stat`, `sysconf`;
  cgroup v2 limits applied) × `DEFAULT_SAFETY_FRACTION` (0.7), lowered by the
  smallest configured cap: an explicit `cap_bytes`, `Settings.max_rss_mb`
  (`api/config.py`, default `0` = no cap, so the budget follows available
  RAM) and the `MEMDIVER_MEMORY_BUDGET_MB` environment variable.
- **Guard** (`check_budget`): a producer estimates its peak
  (`MemoryEstimate` with a per-component breakdown) before it reads data. Over
  budget it raises `CapabilityError` (PRECONDITION, code
  `memory_budget_exceeded`, `estimate_bytes` / `budget_bytes` in `details`);
  with `force` it logs the warning and proceeds.
- **Override on every surface**: CLI `--force-memory` (`cli/_shared.py`,
  refusal printed with a re-run hint, exit 2); MCP `force_memory=true`
  (`mcp_server/server.py`); REST `force_memory` (`api/models.py`
  `MemoryOverrideFields`), refused with **HTTP 507** and a flat body
  (`api/main.py`, `api/memory_budget_errors.py`); the web UI shows the estimate
  and a localized "Run anyway" button that re-sends with `force_memory: true`
  (`frontend/src/components/common/MemoryBudgetDialog.tsx`).
- **Spill instead of refuse**: when the in-RAM estimate does not fit, the
  float32 variance output is placed in an unlinked disk-backed `.npy` memmap
  (`core/slab_variance.py` `plan_slab_variance` / `allocate_variance_output`)
  and only the remainder is gated.

## 2. What is done

### Streaming import

- Importers describe each region as *runs* (file range, zero fill, literal)
  over a read-only mmap of the source (`msl/import_sources.py`, `MappedFile`).
  `MslWriter.write_streaming()` pulls at most `STREAM_CHUNK_SIZE` (16 MiB) at a
  time (`msl/writer.py`).
- **> 4 GiB fix**: `BlockLength` is u32, so regions are split at page
  boundaries into `MEMORY_REGION` blocks of at most `REGION_BLOCK_CAP`
  (1 GiB, `MslWriter(region_block_cap=...)`).
- **Page release**: `MappedFile.release` issues `MADV_DONTNEED` for consumed
  ranges (effective on Linux). Where that advice does not drop file-backed
  pages (macOS), `stream_view` / `find` map each chunk as its own short-lived
  window mmap, so pages leave the RSS when the window is unmapped.
- **Raw dumps with `.maps` sidecars**: `.bin` + `/proc/<pid>/maps` pairs are
  imported as streamed regions (`msl/importer.py`, regioned raw import) and
  read directly as VA-mapped sources (`core/dump_sources/_regioned_base.py`,
  `lldb_raw.py`, `gdb_raw.py`).

### Region selection and view filter

- Import-time selection (`msl/region_select.py`, `parse_selection`,
  `preview_import`): excluded categories are never written; the full layout
  still goes into `VAS_MAP` and the selection into provenance
  (`msl/importer.py`). Surfaces: CLI `import --list-regions`, MCP
  `preview_import` / `import_raw_dump(region_types=...)`.
- Analysis-time view filter (`core/region_view_filter.py`): a full `.msl` is
  analysed as if only the selected categories existed. Results carry
  `region_filter` because offsets are filtered-view offsets. CLI
  `--regions` / `--exclude-regions`, REST request field / session default, MCP
  per-tool `region_filter` or `set_region_filter`.

### Consensus: bit-identical slab streaming

`core/slab_variance.py` `stream_variance` replaces the old "load all N dumps,
then `compute_variance`" path. It reads one position slab from each source,
stacks a contiguous `(N, w)` float32 slab and reduces it with the same
two-pass `np.var(axis=0)`, so working set is `N × w` instead of `N × size`
(`engine/consensus.py` `ConsensusVector.build` / `_stream_flat_variance`).
Slab width is chosen by the budget, capped at `MAX_SLAB_POSITIONS` (1 Mi).

*numpy caveat*: a `(N, 1)` slab is reduced along a contiguous axis (pairwise
summation) and can differ in the last bit from the same column inside a wider
slab. `plan_slabs` therefore never emits a width-1 slab (a width-1 tail joins
its neighbour), except exactly where the historical 16 MiB grid of
`compute_variance` did (`size % legacy_chunk == 1`), which keeps results
bit-identical to the old builder.

### Lazy aligned MSL / VA paths

`core/region_align.py` no longer builds eager `{page: bytes}` maps:
`LazyCapturedPages` / `_MslRegionData` hold page *references* (zero-copy views
into the reader's mmap) and copy a page only when indexed; VA alignment uses
`build_va_page_index` / `read_va_slab`. `stream_aligned_variance` streams
slabs from those references under the same budget plan, keeping at most one
decompressed region per dump (`_ReaderHandle.decompressed_payload`).
**Bug fixed on the way**: compressed regions used to be read at their on-disk
offsets, i.e. the aligned consensus analysed *compressed* bytes; they are now
read from the decompressed payload.

### Entropy

`core/entropy_profile.py` `EntropyProfile` stores offsets/entropies as two
numpy arrays (16 B/position) instead of a list of Python tuples, and
`core/entropy.py` `compute_entropy_profile` is vectorised (`bincount`
histograms per slab, count-log lookup table); `find_high_entropy_regions` has a
vectorised run detector.

For windows ≤ 32 (`SORTED_PATH_MAX_WINDOW`) `window_entropies` takes a
sorted-run path: one stable radix argsort per slab touches only the nonzero
bins and accumulates them into numpy's pairwise-sum layout, so values are
**bit-identical** to the 256-bin histogram form (self-checked once per
process, falls back otherwise; pinned by `tests/test_entropy_fast_profile.py`
against a frozen copy). `byte_histogram` (behind `shannon_entropy`) counts
byte pairs in 512 KiB chunks and skips all-zero 1 KiB blocks: a whole-dump
`np.bincount` used to cast to a 2 GiB `intp` copy for 256 MiB.
The Entropy tab's `GET /api/inspect/entropy` (`length=0`) no longer calls
`read_all()`: `stream_entropy_profile` reads the flat view in 8 MiB slabs
(+ window − 1 look-ahead), feeding the histogram and the positions starting in
each slab; peak heap = one slab + 16 B × positions (≤ 2¹⁸). Same payload
bit for bit. `entropy_result`, warm page cache, old vs new back to back:
256 MiB raw 1.21 s → 0.43 s, 256 MiB `.msl` 1.26 s → 0.45 s, 208 MiB lldb
1.06 s → 0.18 s, 210 MiB real `.msl` 1.23 s → 0.19 s (under heavy machine load
the old path took 3.3–4.5 s). The frontend preloads the chart chunk during the
request and keeps the panel mounted (data → chart 0.34 s → 0.04 s; tab
re-entry 0.31 s → 3 ms).

**Full resolution + envelope** (`core/entropy_overview.py`,
`app/entropy_payload.py`). The sampled profile (`step = size / 2¹⁸`, then
200 plotted points) could miss a 32-byte key entirely. `resolution=full`
visits every window once (step 1) with the fixed-point
`sliding_entropy_estimate` (error < 1e-9) in 8 MiB read slabs split into
2¹⁷-position sub-slabs on `min(4, cpu − 1)` threads; all-zero 1 KiB blocks
are skipped (their windows are exactly 0.0). Region membership is exact
(windows within the tolerance of the threshold get the bit-exact
`window_entropies` float); the per-bucket min/max/mean envelope (default 1500,
max 4096 buckets) and stats come from the estimate. Byte-overlapping runs are
joined, so a long random buffer is one region. Peak heap: one slab + ~16 MiB
estimate scratch per worker + 32 B per run (tracemalloc 39–84 MiB measured).
`resolution=auto` (the tab's first request) is full up to 8 MiB and the old
sampled path above (with `full_resolution_available`); the SPA then requests
`resolution=full` and swaps it in. Measured (busy dev machine): first response
16 / 64 / 256 MiB synthetic 0.21 / 0.29 / 0.65 s, 212 MiB lldb / `.msl`
0.40 / 0.42 s; full pass 1.2 / 4.7 / 17.1 s and 7.8 / 8.3 s (~40 ns per
non-zero byte). The default threshold is window-aware
(`core.entropy.default_entropy_threshold`, 4.5 at window 32); the former 7.5
is unreachable below 182-byte windows.

### Convergence sweep

`engine/convergence.py` uses boolean masks (1 B/position) and sorted offset
arrays instead of Python `set`s of offsets, computes the step-1 entropy
profile in `ENTROPY_SLAB_POSITIONS` slabs, and builds each N with the
slab-streamed `ConsensusVector.build`. One upfront `_check_sweep_budget` for
the largest N (`force` / `budget` parameters) is wired to CLI
`consensus --convergence --force-memory`, REST `POST /api/analysis/convergence`
(`force_memory`, 507), and the experiment flow
(`app/experiment_orchestration.py`, CLI/MCP/REST `experiment`).

### Differential

`algorithms/unknown_key/differential.py` `_compute_variance` uses
`plan_slab_variance` + `stream_variance` (budget-checked, `force`);
`_variance_from_buffers` remains as the test seam.

### n-sweep (no guard needed)

`engine/nsweep.py` folds dumps one at a time into one `WelfordVariance`, so
RAM does not grow with N: float32 mean + M2 (8 B/position), reference dump
(1 B), checkpoint variance (4 B), one dump in flight. `_probe_min_size` reads
sizes from metadata (`sliceable_flat_size`) instead of `read_all()`. This is
the same O(size) footprint as the guarded incremental session, not the
O(N × size) build the guard exists to stop, so no budget check is added.

### Incremental consensus sessions

`api/routers/consensus.py` reads uploads in chunks into a buffer of exactly
`size` bytes (no whole-upload copy); `consensus/begin` is budget-checked with
`engine/consensus.py` `incremental_build_estimate` (accepts `force` or
`force_memory`).

`ConsensusSession.live_stats` (`api/services/consensus_session.py`) no longer
materialises the variance or an `argpartition` index (formerly ~12 B/position
on top of the 8 B Welford state). It walks `m2 / n` (or the finalized vector)
in slabs of at most `core/variance.py` `PAIRWISE_LEAF` (1 Mi) positions into
one reusable buffer: `pairwise_leaves_sum` follows numpy's pairwise-summation
tree so `mean_variance` is bit-identical to `variance.mean()`, `max_variance`
is exact, and `RunningTopK` merges each slab's local top-5 into a bounded
running set. Top-k ties are now broken deterministically (descending variance,
then ascending offset); the old `argpartition` tie order was unspecified.
tracemalloc peak at 64 Mi positions: 768 MiB -> 8 MiB.

### Encrypted materialize

`msl/materialize.py` rewrites a filtered copy streaming region bytes from the
source; an encrypted source is re-encrypted under the same key wrapping
(`MslEncryptionConfig.rewrap`) with a fresh nonce, using the incremental AEAD
in `msl/aead_stream.py` (AES-256-GCM and XChaCha20-Poly1305, byte-identical
to the one-shot path), so streamed encrypted *writes* do not buffer.

### Encrypted reading: verify once + seek

No format change. `MslReader.open()` on an encrypted container
(`msl/reader.py` `_verify_and_seek`, `msl/aead_seek.py`):

1. **Verifies** the single AEAD tag in one streamed pass over the mmap'd
   ciphertext in 1 MiB slices (AES-256-GCM: hazmat GCM decryptor
   `update_into` a reusable sink, plaintext discarded, tag checked by
   `finalize`; XChaCha20-Poly1305: Poly1305 over AAD‖pad‖ct‖pad‖lengths, no
   decryption, `hmac.compare_digest`). Failure → same `TagStatus.CORRUPTED`
   and no plaintext, exactly as before.
2. **Decrypts on demand** through the AEAD's stream cipher: GCM block *i* uses
   counter `nonce‖be32(2+i)` (inc32, split at the 2^32 wrap; GCM's 2^39-256
   bit message cap keeps valid files below it); XChaCha20 uses ChaCha20 with
   the HChaCha20 sub-key, counter `1 + off//64`.
3. Serves the reader a `DecryptedView` (`len`, `[i]`, `[a:b]` → `bytes`,
   `read`) with an LRU of 16 × 256 KiB decrypted pages for header walks;
   larger reads bypass the cache. `read_view` on an encrypted file returns a
   memoryview over a fresh decrypted copy (not zero-copy).
4. **TOCTOU guard**: `(dev, ino, size, mtime_ns, ctime_ns)` of the open fd is
   recorded before verification and re-checked (`os.fstat`, ~0.8 µs) after
   every ciphertext copy; a change raises `MslSourceChangedError`.
5. The content key lives in the re-wrap material's `bytearray` (shared, wiped
   on `close()`); the XChaCha sub-key is wiped with the view.

128 MiB encrypted file (32 × 4 MiB regions), open + read every region in
1 MiB windows, tracemalloc peak / wall time (warm imports, macOS):

| Cipher | One-shot (before) | Verify + seek (after) |
|---|---|---|
| AES-256-GCM | 128.0 MiB, open 0.03 s, read 0.07 s | 5.0 MiB, open 0.03 s, read 0.11 s |
| XChaCha20-Poly1305 | 256.0 MiB, open 2.78 s, read 0.07 s | 6.0 MiB, open 0.03 s, read 0.15 s |

Pinned by `tests/test_msl_encrypted_seek.py`.

### Bounded `.msl` / gcore byte search

A `vas` search on a 4.1 GiB `.msl` peaked at 6.7 GB RSS. About 4.1 GB of that
was clean mmap pages. The other ~2.2 GB was anonymous copies, and those are
gone now:

- **Region table without payloads.** `MslReader.collect_regions()` now decodes
  each MEMORY_REGION from `_region_head` (the 0x20 header plus the page map).
  It used to decode the merged full payload, which copied up to 1 GiB per
  block. The decoded region never held page data, so the result is unchanged.
  The list order replays `merge_continuations` on headers only
  (`_region_heads_in_merge_order`), so callers that zip the list against
  another walk stay aligned. `captured_run_index()` is built from this list,
  and so are `_va_span`/`metadata()`, the view filter and `region_align`.
  Compressed blocks are still decompressed one block at a time.
- **In-place `vas` search.** `MslDumpSource.find_all`/`find_first` for
  `view="vas"` no longer go through `iter_ranges()`, which does
  `bytes(read_view(...))` per run. Instead, `MslReader.iter_find` searches
  each captured run in place:
  - on the mmap or the one-shot plaintext `bytes`, with `buf.find(needle, start, end)`;
  - on an encrypted `DecryptedView`, in 8 MiB decrypted windows that overlap
    by `needle_len - 1` (`_iter_find_windowed`).

  The semantics are unchanged: each run is searched on its own, flat offsets
  accumulate `run.avail`, and the result honours the limit and the view
  filter. `iter_ranges()` itself is unchanged for its other callers.
- **gcore.** `_find_all_vas`/`_find_first_vas` use `mm.find(needle, lo, hi)`
  per PT_LOAD. They copy only a `needle_len - 1` boundary window plus the
  stitched tail, where they used to copy `mm[a:b] + tail`. `find_all(limit=)`
  now stops early and returns the same prefix as before.

- **Compressed region blocks.** The run index used to point zstd/lz4 runs at
  their on-disk bytes. As a result `iter_ranges`, `read_range`/`read_all`
  (`vas`), the `va` view, the in-place search and
  `core/msl_helpers.get_region_page_data` all served codec output instead of
  memory. This bug is fixed:
  - A compressed run now carries its block header (`CapturedRun.block`), and
    its `buf_offset` points into the block's decompressed payload.
  - Every run read goes through `MslReader.run_view`, `run_span` or
    `iter_find_run`.
  - `MslReader.decompressed_payload` keeps one decompressed block at a time
    in a one-entry cache. That block is at most the writer's 1 GiB region
    block cap, and the cache is dropped on `close()`.
  - Building the index decompresses each block once, transiently, inside
    `collect_regions`, and records its length.
  - Uncompressed runs keep the zero-copy mmap path.

  Pinned by `tests/test_msl_compressed_views.py`, with MemDiver- and
  memslicer-written zstd/lz4 files.

All three paths are pinned hit-for-hit against frozen copies of the old
implementations by `tests/test_bounded_vas_search.py`. The fixtures cover
needles at run starts and ends, across runs and regions, overlapping hits,
limits and misses, and both the seekable and one-shot encrypted paths. The
same file holds the tracemalloc bounds: under 4 MiB for 256 MiB `.msl`
search and metadata, and under 1 MiB for a 256 MiB gcore. Real-file
measurements are in §3.

### Single-dump analysis buffer

`app/pipeline/analysis_task_runner.py` `run_file` gets its flat `dump_data`
from `app/pipeline/analysis_buffer.py` `open_analysis_buffer` instead of an
unconditional `source.read_all()`:

| Case | Strategy | Heap cost of the buffer |
|---|---|---|
| dump copy + largest algorithm working set fits the budget | `read_all()` bytes (unchanged) | 1× raw, 2× `.msl` (chunk list + join) |
| raw file over budget | read-only `mmap` of the file | 0 (file-backed pages) |
| plaintext `.msl` over budget | flat `vas` view streamed in 8 MiB `read_range` chunks to a temp file under the artifact dir, mapped, deleted on exit | 0 |
| encrypted `.msl` over budget | never spilled (no plaintext on disk): `read_all()`, refused unless `force_memory` | 2× |

An mmap behaves like `bytes` for `find`, `re`, slicing and `np.frombuffer`,
but `needle in mm` silently returns `False`. The two such sites,
`algorithms/unknown_key/constraint_validator.py` and `core/kdf_ssh.py`
(SSH-2 `validate_pair`), now use `core/buffer_ops.py` `contains_bytes`
(pinned by `tests/test_analysis_buffer.py`).

**Algorithm working sets.** `algorithms/base.py`
`BaseAlgorithm.estimate_working_set(size, context, sample)` (default 0)
predicts the heap an algorithm allocates on top of `dump_data`; formulas live
in `algorithms/working_set.py`. The runner reads a content sample
(`read_estimate_sample`: 32 × 64 KiB blocks spread over the view), asks every
selected algorithm, and gates **dump copy (read_all path only) + the largest
working set** — algorithms run sequentially (`_run_algorithms`), so the max,
not the sum. `read_all` is chosen only while copy + working set fit; otherwise
mmap/spill leaves the budget to the algorithms. A refusal
(`memory_budget_exceeded`) carries the per-algorithm breakdown, names the
heaviest algorithm and suggests deselecting it or applying a region filter
(`details.heaviest_algorithm`, `details.algorithm_working_sets`).

| Algorithm | Estimate |
|---|---|
| `change_point` (window 32, step 16) | entropy profile 16 B × ⌈positions⌉ + one `CHUNK_POSITIONS` (8192-row) slab ≈ 35 MiB (`counts` int64 + `flut[counts]` float64 + composite key) + 1 MiB. Windows ≤ 32 take the sorted-run path instead: slab ≤ 8192 rows and ≤ 256 KiB of window bytes, estimated at 64 B per window byte + 128 B/row ≈ 17 MiB (`_profile_slab_bytes`) |
| `structure_scan` | size-independent: the step-1 entropy overview of one 1 MiB view at a time — per-worker estimate scratch (≤ 4 × 65536 positions × 128 B ≈ 32 MiB, × the sampled fraction of nonzero 1 KiB blocks), the view's pending per-position values (8 MiB), its regions (192 B each, sampled density, worst 1/32 B) — + at most 4096 matches × 2 KiB (`working_set.structure_scan_bytes`) |
| `entropy_scan` (step 1) | one 65536-row estimate-first slab (128 B + 64 B × window sizes per row ≈ 16 MiB for [32, 48]) + one exact-entropy batch (8 MiB); windows too large for the fixed-point estimate fall back to one 8192-row histogram slab ≈ 35 MiB (candidates are merged into regions slab by slab, the open region carried across slabs) + (576 B + max window) per output region × size × region density; the density is measured by a step-1 scan of 32 evenly spread 2 KiB pieces of the sample (×1.25 + 0.005 × 1/min window), worst case 1/min window (disjoint clusters) without a sample |
| `entropy_scan` (step ≠ 1) | incremental loop: 160 B per candidate window × positions × candidate fraction (every 64th window of the sample, ×1.25 + 0.005; 1.0 without a sample) |
| `pattern_match` | largest single-window `entropy_scan` over the applicable patterns |
| `differential` | its `plan_slab_variance` peak when given ≥ 2 `dump_paths`, else 0 |
| `exact_match`, `user_regex`, `constraint_validator` | 0 (not size-proportional) |

tracemalloc peak vs estimate on a raw dump through the mmap path
(`zeros` = all-zero, `mixed` = 10 % random 4 KiB blocks, `random` = uniform):

| Algorithm / data | 4 MiB measured → est | 16 MiB | 64 MiB |
|---|---|---|---|
| `change_point` zeros / mixed | 38.4 → 40.2 MiB | 50.4 → 52.2 MiB | 98.4 → 100.2 MiB |
| `structure_scan` zeros | 9.1 → 10.5 MiB | 9.9 → 14.4 MiB | 9.9 → 17.3 MiB |
| `structure_scan` mixed | 9.6 → 14.3 MiB | 8.5 → 20.0 MiB | 8.7 → 22.3 MiB |
| `structure_scan` random | 32.3 → 47.5 MiB | 32.3 → 49.2 MiB | 32.9 → 49.2 MiB |
| `entropy_scan` zeros | 8.8 → 25.4 MiB | 8.8 → 26.6 MiB | 8.8 → 31.2 MiB (absolute margin) |
| `entropy_scan` mixed | 10.1 → 25.6 MiB | 8.9 → 27.1 MiB | 9.2 → 34.3 MiB |
| `entropy_scan` random | 10.4 → 26.9 MiB | 10.4 → 32.7 MiB | 10.6 → 55.6 MiB |
| `exact_match`, `user_regex` | ~0 → 0 | ~0 → 0 | ~0 → 0 |

Validated (generous bounds) by `tests/test_algorithm_working_set.py`.

## 3. Measured peak RSS

| Workload | Before | After |
|---|---|---|
| Import 1 GiB raw, macOS | 1135 MiB | 127 MiB |
| Import 1 GiB raw, Linux | 1087 MiB | ~80 MiB |
| Consensus 4 × 32 MiB raw | 896 MiB | 240 MiB (128 MiB with memmap) |
| Differential 4 × 32 MiB | 896 MiB | 168 MiB (40 MiB with memmap) |
| Aligned MSL 4 × 32 MiB, working set beyond outputs | 168 MiB | 50 MiB (82 MiB total with memmap) |
| Entropy profile 8 MiB | 1293 MiB | 162 MiB |
| Entropy tab request (`GET /api/inspect/entropy`), 256 MiB raw / `.msl` | 2730 / 2978 MiB | 418 / 437 MiB (tracemalloc peak < 32 MiB for 48 MiB) |
| Entropy tab full-resolution follow-up (`resolution=full`), 256 MiB synthetic / 212 MiB lldb | — | tracemalloc peak 62 / 76 MiB (max RSS incl. page cache 549 / 505 MiB) |
| Convergence 2 MiB × 4 | 180 MiB / 115 s | 88 MiB / 0.9 s |
| Convergence 16 MiB × 4 | killed after 15 min | 177.8 MiB / 7.7 s |
| `open_dump(...).find_first(b"KEY!", view="vas")`, 4.1 GiB sparse raw imported to `.msl`, hit at 3 GiB, macOS: anonymous (`footprint`) / file-backed resident (`vmmap` mapped file) / max RSS | 2251 MiB / 4.1 GiB / 6.8 GB | 99 MiB / 3.0 GiB / 3.4 GB |
| Same file, `search_bytes_result(view="vas")` (byte-search endpoint, scans the whole view) | 2248 MiB / 4.1 GiB / 6.8 GB | 100 MiB / 4.1 GiB / 4.5 GB |
| Same two calls, tracemalloc peak | 2057 MiB | 9.1 MiB (the 1 M-entry page-state list) |

## 4. Remaining limits and follow-ups

- ~~**Encrypted reading decrypts the whole file into RAM**~~ — done, see
  "Encrypted reading: verify once + seek" in §2. The one-shot path remains
  behind `MEMDIVER_MSL_DECRYPT_ONESHOT=1` for debugging.
- **Outputs are inherently size-proportional**: the variance vector is float32
  (4 B/position), plus reference bytes and classifications. The guard moves
  the variance to a memmap when over budget; it cannot make outputs smaller.
- ~~**Single-dump algorithms get `dump_data: bytes`**~~ — done, see
  "Single-dump analysis buffer" in §2.
- ~~**Single-dump analysis of gcore / gdb / lldb regioned sources**~~ — done
  (`core/dump_sources/gcore.py`, `gdb_raw.py`, `lldb_raw.py`): each source
  now has a `read_all()` of its `vas` view (gcore: the PT_LOAD bodies with
  content, in program-header order; gdb_raw / lldb_raw: the captured-region
  prefix of the `.bin`), one heap copy at peak (1×, tracemalloc-measured).
  `run_file` hits are `vas` offsets, as for `.msl`. Over budget a gdb_raw /
  lldb_raw `.bin` is mapped read-only up to its `vas` size (trailing padding
  excluded; 0 heap) and a gcore core is spilled (already plaintext on disk).
  The planner reads that view explicitly: these sources' `size` is the RAW
  file size and `read_range` defaults to `"raw"`. Remaining gap: the web hex
  viewer offers its raw/vas switch only for `.msl`, so a gcore hit is shown
  at the right byte only in the `vas` view (gdb_raw / lldb_raw offsets
  coincide in both views).
- **Encrypted `.msl` single-dump analysis still materialises the plaintext**:
  it is never spilled to disk, so over budget it is refused unless
  `force_memory`.
- **`entropy_scan` working set depends on the region count**: one slab plus
  ~0.5 KiB per output region (before: ~112 B per window passing the
  threshold, ~12.4 GiB for 64 MiB of random bytes; then 35.8 MiB, one
  region; with the estimate-first scan 10.6 MiB, ~20x faster: ~0.08-0.19
  s/MiB instead of ~2.8 s/MiB for [32, 48] at threshold 4.5, bit-identical
  output). The densest input (one region per smallest window, e.g. 32 random
  + 32 zero bytes repeated) costs ~17 B per dump byte; the estimate scans
  small sample pieces for the density, so a dense area the sample misses can
  exceed it; without a sample it assumes the densest case. `step ≠ 1` still
  collects ~160 B per passing window.
- **A search still faults in the file pages it scans.** After the
  "Bounded `.msl` / gcore byte search" fixes, the remaining RSS of a `vas`
  search is clean, file-backed mmap pages: up to the whole scanned `vas` view
  (4.1 GiB for a full scan of a 4.1 GiB `.msl`). The kernel can reclaim
  those pages, and none of it is anonymous memory. A `madvise(MADV_DONTNEED)`
  per finished run would lower the reported RSS, but it has not been done.
- **The region table is proportional to page count.** `page_states` is a
  Python list with one entry per page, about 8 MiB per 4 GiB of 4 KiB
  pages. It is kept for backward compatibility; `page_intervals` alone would
  be O(runs).
- **Continuation regions keep their joined payload.** `iter_blocks()` (via
  `msl/block_iter.py merge_continuations`) still joins a `HAS_CHILDREN`
  region's payload with its continuations. `collect_regions()` no longer
  uses that path. `captured_run_index` maps a run to the parent's buffer
  offsets, so for a region split by CONTINUATION blocks (not produced by
  MemDiver's writer, which emits independent region blocks) the run bytes
  would cross the next block header. This is not new behaviour.
- **`constraint_validator` / `differential`** are not size-proportional in
  `run_file` (no candidates / fewer than two `dump_paths`): estimate 0;
  `differential` gates its own slab plan when given paths.

## 5. DuckDB: deferred deliberately

- **mmap is the right out-of-core primitive for bytes.** Every analysis reads
  by offset or VA; an mmap gives zero-copy random access with kernel-managed,
  file-backed paging. A BLOB column would store each dump twice, materialise
  reads as Python `bytes`, and turn `read(offset, length)` into a query.
  `.msl` already supplies integrity, compression, encryption and a block index.
- **No consumer for a `regions` table.** Region selection and the memory
  estimates already come from in-file metadata; nothing queries regions across
  dumps today.
- **Page-hash dedupe saves I/O, not RAM.** Slab streaming already bounds RAM;
  skipping identical pages only avoids reads. It would also need a stable dump
  identity, but `engine/project_db.py` `dumps.dump_id` is a random `uuid4`
  (`_new_id`) with no content hash.
- **What would justify it later**: large-N datasets with many identical pages
  across dumps, where read I/O dominates. Measure the identical-page fraction
  first. `engine/project_db.py` remains the place for metadata and results.
