// Reuse the shared VasEntry shape defined alongside the chart props. This is
// a type-only import (erased at compile time), so the charts/types <-> api/types
// pairing stays a pure compile-time cycle with no runtime dependency.
import type { VasEntry } from "@/components/charts/types";

// Key material carried on inspect/analysis requests for encrypted dumps.
export interface KeyMaterial {
  passphrase?: string;
  key_hex?: string;
  kem_key_hex?: string;
}

// Request types
export interface ScanRequest {
  root: string;
  keylog_filename?: string;
  protocols?: string[];
}

export interface AnalyzeRequest {
  library_dirs: string[];
  phase: string;
  protocol_version: string;
  keylog_filename?: string;
  template_name?: string;
  max_runs?: number;
  normalize?: boolean;
  expand_keys?: boolean;
  algorithms?: string[];
  /** Re-send past the server memory guard (see `@/api/memory-budget`). */
  force_memory?: boolean;
}

export interface AnalyzeFileRequest {
  dump_path: string;
  algorithms?: string[];
  user_regex?: string | null;
  custom_patterns?: Record<string, unknown>[];
}

// Response types
export interface ProtocolDescriptor {
  name: string;
  versions: string[];
  secret_types: Record<string, string[]>;
  dir_prefix: string;
}

export interface PhaseInfo {
  library_dir: string;
  library?: string;
  phases: string[];
  runs: number;
}

// Mirrors `engine.serializer.serialize_hit` exactly. APPEND-ONLY, and kept in
// lockstep by `tests/test_serializer.py`, which parses this very file and
// fails if the serializer emits a key this interface cannot see. Everything
// after `confidence` is optional here because a hit built by an older producer
// (or read back from an archived JSON result) may not carry it -- not because
// the serializer omits it: it always emits all fourteen.
export interface SecretHit {
  secret_type: string;
  offset: number;
  length: number;
  dump_path: string;
  library: string;
  phase: string;
  run_id: number;
  confidence?: number;
  // `null` is a real value, not "absent": the serializer distinguishes "the
  // producer recorded nothing" from a recorded false/empty result.
  verified?: boolean | null;
  metadata?: Record<string, unknown>;
  value_hex?: string | null;
  canonical_phase?: string;
  // Mirrors of the two verification labels, promoted out of `metadata` by the
  // serializer. `confirmed_by === "pcap"` is what backs the "Verified via pcap
  // capture" provenance badge (see `components/results/provenance.ts`).
  cipher?: string | null;
  confirmed_by?: string | null;
}

// Mirrors `engine.serializer.serialize_report`. APPEND-ONLY, same parity guard.
// The five trailing fields are the corpus axes both persistence paths read.
export interface LibraryReport {
  library: string;
  protocol_version: string;
  phase: string;
  num_runs: number;
  hits: SecretHit[];
  static_regions: StaticRegion[];
  /**
   * Free-form; `run_file` reports `offset_view` ("vas" / "raw") here: the
   * byte view every hit offset addresses (read via `hitOffsetView`).
   */
  metadata: Record<string, unknown>;
  canonical_phase?: string;
  library_version?: string;
  scenario?: string;
  protocol?: string;
  version_axis?: string;
}

// Mirrors `engine.serializer.serialize_static_region`, same parity guard.
export interface StaticRegion {
  start: number;
  end: number;
  // Derived server-side (`end - start`); optional so a hand-built region in a
  // test or an older archived result still type-checks.
  length?: number;
  mean_variance: number;
  classification: string;
}

export interface AnalysisResult {
  libraries: LibraryReport[];
  metadata: Record<string, unknown>;
}

/**
 * Response from ``POST /api/analysis/run`` and ``/run-file``. Both
 * endpoints now dispatch the GIL-bound algorithm work onto the
 * TaskManager's ProcessPool (like the pipeline + batch endpoints) and
 * return a ``task_id`` immediately. Progress streams over
 * ``/ws/tasks/{task_id}``; the full ``AnalysisResult`` is fetched from
 * the ``analysis_result`` artifact once the task succeeds.
 */
export interface AnalysisRunResponse {
  task_id: string;
  status: string;
}

export interface HexData {
  hex_lines: string[];
  offset: number;
  length: number;
  file_size: number;
  format: string;
}

export interface EntropyData {
  overall_entropy: number;
  /**
   * `start`/`end` are in window-start space (`end` exclusive); `byte_end` is
   * the exclusive end of the bytes the region's windows cover.
   */
  high_entropy_regions: { start: number; end: number; mean_entropy: number; byte_end?: number }[];
  profile_sample: { offset: number; entropy: number }[];
  stats: { min: number; max: number; mean: number };
  /**
   * The window/step the profile was ACTUALLY computed at. The server widens
   * `step` on large inputs to bound the work, so these are not necessarily what
   * was requested — they are what the numbers above describe.
   */
  step?: number;
  window?: number;
  /** The byte view every offset above is in (the dump's flat view). */
  view?: "raw" | "vas" | "va";
  /** "full" = every window position visited (step 1); "sampled" otherwise. */
  resolution?: "full" | "sampled";
  /** A `resolution: "full"` request would return a finer profile than this one. */
  full_resolution_available?: boolean;
  /**
   * Per-bucket summary of the profile, as column arrays: bucket `i` covers the
   * window starts `[starts[i], stops[i])` and min/max/mean are over every
   * window in it (over the sampled points when `resolution` is "sampled").
   * Buckets without points are omitted.
   */
  envelope?: {
    starts: number[];
    stops: number[];
    min: number[];
    max: number[];
    mean: number[];
  };
  /** The high-entropy threshold actually used, and where it came from. */
  threshold?: number;
  threshold_source?: "default" | "explicit";
  /** Achievable maximum for this window: log2(min(window, 256)). */
  max_entropy?: number;
  /** Whether `threshold` can be reached at all with this window (<= max_entropy). */
  threshold_reachable?: boolean;
  /** Machine-readable warning codes, e.g. "threshold_unreachable". */
  warnings?: string[];
  /** Total number of high-entropy regions (the list may be capped). */
  region_count?: number;
  /** `high_entropy_regions` was capped and holds fewer than `region_count`. */
  regions_truncated?: boolean;
  /** Shortest region (in bytes) the server reports. */
  min_region_bytes?: number;
}

export interface SessionInfo {
  path: string;
  name: string;
  display_name: string;
  created_at: string;
  mode: string;
  input_mode: string;
  input_path: string;
  /** How many dumps the saved workspace holds. `0` for a v1 file. */
  dump_count?: number;
}

export interface SessionSnapshot {
  schema_version: number;
  memdiver_version: string;
  created_at: string;
  session_name: string;

  // Input config
  input_mode: string;
  input_path: string;
  dataset_root: string;
  keylog_filename: string;
  template_name: string;

  // Selections
  protocol_name: string;
  protocol_version: string;
  scenario: string;
  selected_libraries: string[];
  selected_phase: string;
  algorithm: string;
  mode: string;
  max_runs: number;
  normalize_phases: boolean;
  selected_algorithms: string[];

  // File-specific
  single_file_format: string;
  ground_truth_mode: string;

  // Analysis results (serialized)
  analysis_result: Record<string, unknown> | null;

  // Investigation state
  bookmarks: Array<{ offset: number; length: number; label: string; view?: "raw" | "vas" | "va" }>;
  investigation_offset: number | null;

  // --- Multi-dump workspace (schema_version 2) -----------------------------
  // Every field below is OPTIONAL so a v1 response still typechecks: the
  // backend defaults them, and a session saved before this feature existed
  // simply has none of them.
  //
  // Persisted BY PATH, never by dump id: frontend dump ids are per-session
  // `crypto.randomUUID()` values and are meaningless in a saved file.
  //
  // SECURITY: `dumps` carries exactly `path/name/size/format`. It must never
  // grow `keyMaterial` (plaintext recovered secrets) or `tagStatus` (a stored
  // "valid" without its key would make the badge claim "unlocked").
  dumps?: SessionDumpEntry[];
  active_dump_path?: string | null;
  selected_dump_paths?: string[];
  /**
   * Paths whose pane is folded away. Named for what it is: the in-memory
   * field is `dump-store.visibleDumps`, which is actually a COLLAPSED set
   * (see `MultiHexViewer`), and the misnomer stops at the store boundary.
   */
  collapsed_dump_paths?: string[];
  origin_dump_path?: string | null;
  main_view?: string;
  aslr_normalize?: boolean;

  // Dump rail
  dump_weights?: Record<string, number>;
  excluded_dump_paths?: string[];
  /** "" means "no solo"; the wire contract has no null here. */
  solo_dump_path?: string;
  rail_collapsed?: boolean;

  /**
   * Analysis-time region view filter (`"regions=heap,stack"` as persisted,
   * `"heap,stack"` accepted), or `null` for every region. Honoured for
   * `.msl` dumps only; raw / ELF-core sources ignore it.
   */
  region_filter?: string | null;
}

/** The only dump fields that reach disk. See the security note above. */
export interface SessionDumpEntry {
  path: string;
  name: string;
  size: number;
  format: string;
}

// Task lifecycle types live in ./pipeline as the single source of truth. They
// mirror TaskRecord.to_dict() in api/services/task_manager.py exactly: the
// status enum is pending | running | succeeded | failed | cancelled (never
// "completed" or "not_implemented"), and the record carries stages/artifacts.
// Re-exported here so existing `./types` importers keep working without a
// second, drifting definition.
export type { TaskStatus, StageRecord, ArtifactSpec, TaskRecord } from "./pipeline";

export interface PathInfo {
  exists: boolean;
  is_file: boolean;
  is_directory: boolean;
  file_size: number;
  extension: string;
  has_keylog: boolean;
  dump_count: number;
  detected_mode: "single_file" | "run_directory" | "dataset" | "unknown";
}

export interface BrowseEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  extension: string;
}

export interface BrowseResult {
  current: string;
  parent: string | null;
  entries: BrowseEntry[];
  error?: string;
}

/** One dump file found by ``GET /api/path/discover-dumps``. */
export interface DiscoveredDump {
  path: string;
  /** ``RunDiscovery``'s own classification, e.g. ``msl`` / ``gcore`` / ``raw``. */
  kind: string;
  size: number;
  /** Name of the containing directory, which for a corpus is the run. */
  run: string;
}

/**
 * Result of a recursive dump sweep under one directory.
 *
 * ``counts_by_kind`` is deliberately counted over EVERYTHING discovered,
 * before the ``kinds`` filter is applied, so the kind checkboxes can show a
 * real count for the kinds that are currently switched off.
 *
 * ``error`` follows ``BrowseResult``: the server answers 200 with the four
 * keys always present and merely adds this one, so a caller renders the
 * result unconditionally instead of branching on a null response.
 */
export interface DiscoverDumpsResult {
  dumps: DiscoveredDump[];
  total: number;
  truncated: boolean;
  counts_by_kind: Record<string, number>;
  error?: string;
}

// Structure overlay types
export interface StructureField {
  name: string;
  offset: number;
  length: number;
  display: string;
  valid: boolean;
}

export interface StructureMatchResult {
  match: {
    name: string;
    description: string;
    protocol: string;
    total_size: number;
    confidence: number;
    fields: StructureField[];
  } | null;
  reason?: string;
}

export interface StructureApplyResult {
  structure: {
    name: string;
    protocol: string;
    total_size: number;
    offset: number;
    fields: StructureField[];
  };
}

export interface StringMatch {
  offset: number;
  value: string;
  encoding: string;
  length: number;
}

export interface PatternInfo {
  filename: string;
  name: string;
  description: string;
  applicable_to: Record<string, unknown>;
}

export interface StringsResponse {
  strings: StringMatch[];
  total_count: number | string;
  truncated: boolean;
  next_cursor?: number | null;
  window_end?: number | null;
}

// --- Convergence ---
export interface DetectionMetrics {
  tp: number;
  fp: number;
  precision: number;
  recall: number;
  candidates: number;
}

export interface ConvergencePoint {
  n: number;
  variance: DetectionMetrics;
  combined: DetectionMetrics | null;
  aligned: DetectionMetrics | null;
  decryption_verified: boolean | null;
}

export interface ConvergenceSweepResult {
  points: ConvergencePoint[];
  first_detection_n: number | null;
  first_decryption_n: number | null;
  first_fp_target_n: number | null;
  total_dumps: number;
  max_fp: number;
}

// --- Verification ---
export interface VerifyKeyResult {
  verified: boolean | null;
  offset: number;
  cipher: string;
  key_hex?: string;
}

// --- Format detection ---
export interface FormatSuggestion {
  format: string;
  reason: string;
  magic_ok: boolean;
}

// --- AEAD tag status (spec §10) ---
export type TagStatus = "not_encrypted" | "valid" | "corrupted" | "missing_key";

// --- MSL page model (CAPTURED/FAILED/UNMAPPED, plus 1.1 NOT_RESIDENT) ---
/** NOT_RESIDENT (MSL 1.1): mapped but never touched; content is known zero. */
export type PageState = "CAPTURED" | "FAILED" | "UNMAPPED" | "NOT_RESIDENT";

export interface PageStateInterval {
  va: number;
  length: number;
  state: PageState;
  page_count: number;
  /** Present only on CAPTURED intervals: offset into the flattened VAS stream. */
  vas_offset?: number;
}

export interface PageStateRegion {
  base_addr: number;
  region_size: number;
  page_size: number;
  intervals: PageStateInterval[];
}

export interface PageStatesResponse {
  regions: PageStateRegion[];
  total_pages: number;
  captured_pages: number;
  coverage: number;
  vas_size: number;
}

// --- MSL session metadata (GET /api/inspect/session-info) ---
// Structurally a superset of SessionView's inline SessionData so the response
// can be handed straight to <SessionView data={...} />.
export interface SessionInfoResponse {
  dump_uuid: string;
  pid: number;
  os_type: string;
  arch_type: string;
  timestamp_iso: string;
  exe_path?: string;
  modules: { path: string; base_addr: number; size: number }[];
  region_count: number;
  total_region_size: number;
  captured_page_count: number;
  key_hint_count: number;
  total_pages: number;
  coverage: number;
}

// --- MSL import provenance (GET /api/inspect/import-provenance) ---
/** One IMPORT_PROVENANCE block with its note parsed (api/models.py). */
export interface ImportProvenanceRecord {
  source_format: number;
  source_format_name: string;
  tool_name: string;
  import_time_ns: number;
  orig_file_size: number;
  source_hash: string;
  note: string;
  base_note: string;
  /** Kept region categories; null when the note records no selection. */
  selected_categories: string[] | null;
  selection_all: boolean;
  writable_only: boolean;
  module_globs: string[];
  excluded_regions: number | null;
  excluded_bytes: number | null;
  fallback_all: boolean;
  materialized: boolean;
  orig_eoc_hash: string | null;
  dropped_key_hints: number | null;
  /** Regions were classified by their mapping names (`region_names=1`). Missing on older servers. */
  region_names?: boolean;
}

export interface ImportProvenanceResponse {
  provenance: ImportProvenanceRecord[];
}

// --- MSL virtual address space regions (GET /api/inspect/vas) ---
export interface VasRegionsResponse {
  vas_entries: VasEntry[];
  region_count: number;
  total_region_size: number;
  vas_coverage: Record<string, number>;
}

// --- Dataset run discovery (GET /api/dataset/runs) ---
export interface DatasetRunDump {
  path: string;
  kind: string;
  size: number;
  phase: string | null;
}

/** Three-state verdict from RunDiscovery._find_capture. */
export type DatasetRunCaptureStatus = 'present' | 'absent' | 'unreadable';

export interface DatasetRunCapture {
  path: string | null;
  status: DatasetRunCaptureStatus;
}

export interface DatasetRun {
  path: string;
  meta: Record<string, unknown> | null;
  dumps: DatasetRunDump[];
  capture: DatasetRunCapture;
}

export interface DatasetRunsResponse {
  runs: DatasetRun[];
  total: number;
  offset: number;
  limit: number | null;
}

// --- Auto Export ---
export interface AutoExportResult {
  format: string;
  content: string;
  pattern: Record<string, unknown>;
  region: {
    offset: number;
    length: number;
    key_start: number;
    key_end: number;
  };
}

// --- Keylog Export ---
export interface KeylogSecret {
  secret_type: string;
  client_random: string; // hex
  secret: string; // hex
}

export interface ExportKeylogRequest {
  secrets: KeylogSecret[];
  output_path?: string;
}

export interface ExportKeylogResult {
  keylog: string;
  count: number;
  output_path: string | null;
}

// ---------------------------------------------------------------------------
// Dump import region selection (POST /api/dumps/preview, /upload, /import-path)
// ---------------------------------------------------------------------------

/** Selection category of a memory region (`msl/region_select.RegionCategory`). */
export type RegionCategory =
  | "heap"
  | "stack"
  | "image_code"
  | "image_data"
  | "mapped_file"
  | "shared"
  | "unclassified"
  | "runtime";

/**
 * Spec names accepted by `regions` / `exclude_regions`: every category plus
 * the aliases `image` (= image_code + image_data) and `all`. A comma-separated
 * list of these, e.g. `"heap,stack"`, is the wire form.
 */
export type RegionSelectionName = RegionCategory | "image" | "all";

/** One region an import would emit, as `ImportPreview.to_dict()` reports it. */
export interface RegionInfo {
  base_addr: number;
  size: number;
  protection: number;
  region_type: number;
  category: RegionCategory;
  module_path: string | null;
  captured_bytes: number;
  /** Writable mapping (protection has the W bit). */
  is_writable?: boolean;
  /**
   * Full mapping name (`[anon:scudo:primary]`, `/system/lib64/libc.so`);
   * `null` when unknown or untrusted. Missing on older servers.
   */
  name?: string | null;
}

/** What a selection would keep and drop (counts + captured bytes). */
export interface ImportSelectionCounts {
  included_count: number;
  included_bytes: number;
  excluded_count: number;
  excluded_bytes: number;
}

/**
 * Everything an `.mdview` descriptor says about its view (`app/image_preview.py::view_block`).
 * `profile` / `paging` are `null` (never omitted) when the descriptor has none.
 */
export interface ImageViewFacts {
  kind: "process" | "kernel" | "physical";
  /** The process view's pid; `null` for physical / kernel views. */
  pid: number | null;
  capture_id: string | null;
  view_path: string;
  /** A kernel/process view can list processes only with a profile. */
  has_profile: boolean;
  /** The ISF's origin / sha256 / FILE NAME (no directory). */
  profile: { origin: string; sha256: string | null; isf_name: string } | null;
  paging: { pgd_phys: number | null; arch: string | null; va_bits: number | null; page_size: number } | null;
  /** The image file, resolved against the descriptor's directory. */
  image_path: string;
  image_sha256: string;
}

/** Shape returned by `POST /api/dumps/preview`. */
export interface ImportPreview {
  format: string;
  is_msl: boolean;
  regions: RegionInfo[];
  totals: Partial<Record<RegionCategory, { count: number; bytes: number }>>;
  summary: ImportSelectionCounts;
  notes: string[];
  /** `.msl` only: the container is AEAD-encrypted. */
  encrypted?: boolean;
  /** `.msl` only: it was opened (tag verified) with the supplied key material. */
  decrypted?: boolean;
  /**
   * Where the region layout comes from: `"none"` = raw dump with no memory
   * layout (one unclassified region), `"maps"` = raw dump split by a `.maps`
   * sidecar, `"native"` = ELF core / minidump / `.msl`. Missing on older servers.
   */
  layout?: ImportLayout;
  /** `layout === "maps"`: the memory map used (auto-detected sidecar or the one asked for). */
  maps_path?: string | null;
  /** Detected platform of the dumped process (`"android"`, `"linux"`, `"windows"`, ...), or `null`. */
  platform?: string | null;
  /** What the platform was detected from (e.g. mapping names, file header), or `null`. */
  platform_source?: string | null;
  /** Regions in the `runtime` category (excluded by the default selection). */
  runtime_count?: number;
  /** Captured bytes of the `runtime` regions. */
  runtime_bytes?: number;
  /** `.mdview` image views only: which address space the view exposes. */
  view_kind?: "process" | "kernel" | "physical";
  /** `.mdview` only: the view's facts (`app/image_preview.py::view_block`). */
  view?: ImageViewFacts | null;
  /**
   * `.mdview` image views only: `false` for a physical / kernel view, which has
   * no process mappings to choose between (the UI explains instead of listing).
   */
  selection_applicable?: boolean;
}

/** Source of an import preview's region layout (see `ImportPreview.layout`). */
export type ImportLayout = "none" | "maps" | "native";

/** Region-selection options shared by the upload and server-path imports. */
export interface ImportSelectionOptions {
  /** Comma-separated categories to keep, e.g. `"heap,stack"`. */
  regions?: string;
  /** Comma-separated categories to drop, e.g. `"image"`. */
  excludeRegions?: string;
  /** For `.msl` input: write a filtered copy instead of the verbatim default. */
  materialize?: boolean;
  /**
   * Opens an encrypted `.msl` (needed to materialize it). Request-scoped
   * secret: component state only, always sent in a POST body.
   */
  keyMaterial?: KeyMaterial;
  /** Encrypted `.msl` + materialize: write the copy as PLAINTEXT (opt-in). */
  decryptOutput?: boolean;
}

/**
 * Selection outcome fields an import response carries ONLY when a selection
 * was applied or a warning was raised (`ImportResult.selection_summary()`).
 */
export interface ImportSelectionResult {
  selection?: string | null;
  excluded_region_count?: number;
  excluded_bytes?: number;
  secrets_only_in_excluded?: number;
  warnings?: string[];
  materialized?: boolean;
  dropped_key_hints?: number;
  /** Encrypted source: the filtered copy was re-encrypted with the same key. */
  reencrypted?: boolean;
  /** Encrypted source: the filtered copy was written as plaintext (opt-in). */
  decrypted_output?: boolean;
}

// ---------------------------------------------------------------------------
// Heap analysis (`/api/heap/*`). Shapes mirror the backend `heap/` package's
// `to_dict` payloads 1:1; the closed vocabularies (allocator kinds, chunk
// states, roles) live as const tuples in `./heap`, and their unions are
// re-derived here so a backend rename breaks `tsc -b` in one place.
// ---------------------------------------------------------------------------

/** Allocator families the backend can parse (`heap.model.AllocatorKind`). */
export type HeapAllocatorKind =
  | "ptmalloc2"
  | "dlmalloc"
  | "scudo"
  | "mallocng"
  | "jemalloc"
  | "generic"
  | "unknown";

/** What a caller may ASK for: a concrete allocator, or detection. */
export type HeapAllocatorChoice = HeapAllocatorKind | "auto";

/** `heap.model.ChunkState`. `cached` = sitting in tcache/fastbin. */
export type HeapChunkState = "in_use" | "free" | "cached" | "quarantined" | "unknown";

/** The byte roles the `/api/heap/roles` endpoint paints. */
export type HeapRoleName =
  | "chunk_header"
  | "user_data"
  | "free_link"
  | "free_data"
  | "allocator_meta"
  | "top"
  | "slack";

/** One piece of evidence behind a detection or a parse. */
export interface HeapEvidence {
  source: string;
  detail: string;
  weight: number;
}

export interface HeapDetectCandidate {
  kind: HeapAllocatorKind;
  score: number;
  evidence: HeapEvidence[];
}

export interface HeapPlatform {
  os: string;
  arch: string;
  pointer_size: number;
  endianness: string;
  source: string;
}

/** `GET /api/heap/detect`. */
export interface HeapDetectResponse {
  best: HeapAllocatorKind;
  confidence: number;
  hinted: boolean;
  platform: HeapPlatform | null;
  candidates: HeapDetectCandidate[];
  format: string;
}

export interface HeapRegion {
  va: number;
  size: number;
  name: string;
  kind: string;
}

export interface HeapSizeBucket {
  min_size: number;
  max_size: number;
  count: number;
}

/** `GET /api/heap/summary`. */
export interface HeapSummaryResponse {
  allocator: HeapAllocatorKind;
  confidence: number;
  version_hint: string | null;
  partial: boolean;
  heuristic: boolean;
  levels: string[];
  platform: HeapPlatform | null;
  regions: HeapRegion[];
  chunk_count: number;
  counts_by_state: Partial<Record<HeapChunkState, number>>;
  bytes_by_state: Partial<Record<HeapChunkState, number>>;
  size_histogram: HeapSizeBucket[];
  role_bytes: Partial<Record<HeapRoleName, number>>;
  metadata_bytes: number;
  free_list_count: number;
  evidence: HeapEvidence[];
  coverage: Record<string, unknown>;
  diagnostics: string[];
  format: string;
}

/** One parsed chunk (`heap.model.HeapChunk.to_dict`). */
export interface HeapChunk {
  va: number;
  size: number;
  state: HeapChunkState;
  header_len: number;
  user_va: number;
  user_len: number;
  flags: Record<string, unknown> | string[] | number | null;
  bin: string | number | null;
  extra: Record<string, unknown>;
  confidence: number;
  /** The chunk's start in the REQUESTED view's coordinate, or null if unmapped. */
  view_offset: number | null;
}

/** `GET /api/heap/chunks`. */
export interface HeapChunksResponse {
  allocator: HeapAllocatorKind;
  view: string;
  total: number;
  chunk_count: number;
  page: number;
  page_size: number;
  pages: number;
  chunks: HeapChunk[];
  diagnostics: string[];
  filters: Record<string, unknown>;
}

/** `GET /api/heap/chunk-at`. */
export interface HeapChunkAtResponse {
  allocator: HeapAllocatorKind;
  va: number;
  view: string;
  view_offset: number | null;
  found: boolean;
  chunk: HeapChunk | null;
  role: HeapRoleName | null;
  offset_in_chunk: number | null;
  offset_in_user: number | null;
  prev: HeapChunk | null;
  next: HeapChunk | null;
}

export interface HeapFreeList {
  kind: string;
  index: number;
  head_va: number;
  length: number;
  chunk_vas: number[];
  decoded: boolean;
  cycle: boolean;
  corrupt: boolean;
  unresolved_vas: number[];
}

/** `GET /api/heap/free-lists`. */
export interface HeapFreeListsResponse {
  allocator: HeapAllocatorKind;
  kinds: string[];
  list_count: number;
  cycle_count: number;
  corrupt_count: number;
  lists: HeapFreeList[];
}

/** One non-overlapping run of a role, in view coordinates. */
export interface HeapRoleRun {
  offset: number;
  length: number;
  role: HeapRoleName;
}

/** `GET /api/heap/roles`. */
export interface HeapRolesResponse {
  allocator: HeapAllocatorKind;
  view: string;
  offset: number;
  length: number;
  runs: HeapRoleRun[];
  chunk_starts: number[];
  partial: boolean;
  heuristic: boolean;
}

// ---------------------------------------------------------------------------
// Heap annotations on consensus / candidate / locate-key payloads (P7 → P8c)
// ---------------------------------------------------------------------------

/**
 * `heap_status` on an aligned-window answer: whether `heap_roles` can be read.
 * Absent on older servers and on a consensus built with `allocator="off"`.
 */
export type HeapWindowStatus = "ok" | "no_va_coordinate" | "empty_consensus" | "error";

/**
 * Role codes in an aligned window's `heap_roles` (`heap.model.HeapRole`):
 * `0` none, `1..7` the `HeapRoleName`s, `254` MIXED (the dumps disagree),
 * `255` UNCOVERED (outside every annotated run).
 */
export type HeapRoleCode = number;

/** The `heap_role_names` legend: role code (as a JSON key) → role name. */
export type HeapRoleNameLegend = Record<string, string>;

/** What the candidate reduction does with the consensus heap roles. */
export const HEAP_POLICIES = ["annotate", "mask", "off"] as const;
export type HeapPolicy = (typeof HEAP_POLICIES)[number];

/** The anchor chunk holding a candidate's first byte (slab coordinates). */
export interface CandidateHeapChunk {
  start: number;
  size: number;
  state: HeapChunkState;
  offset_in_chunk: number;
  /** Dumps whose chunk there agrees with the anchor's. */
  agree: number;
}

/** `CandidateRegion.heap` — present under `heap_policy` annotate / mask. */
export interface CandidateHeapAnnotation {
  /** Bytes per role name inside the region (`none`/`uncovered`/`mixed` included). */
  role_counts: Record<string, number>;
  chunk: CandidateHeapChunk | null;
  /** True when the region starts in a freed (free/cached/quarantined) chunk. */
  residual: boolean;
  /** Fewest agreeing dumps over the region's role runs; `null` when no runs. */
  agreement: number | null;
}

/** One locate-key hit's heap context, parallel to `DumpKeyLocation.offsets`. */
export interface KeyHitHeap {
  allocator: HeapAllocatorKind | string;
  chunk_va: number;
  chunk_size: number;
  state: HeapChunkState;
  offset_in_chunk: number;
  role: HeapRoleName | string | null;
}
