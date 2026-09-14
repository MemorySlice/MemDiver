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
  high_entropy_regions: { start: number; end: number; mean_entropy: number }[];
  profile_sample: { offset: number; entropy: number }[];
  stats: { min: number; max: number; mean: number };
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
  bookmarks: Array<{ offset: number; length: number; label: string }>;
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

// --- MSL three-state page model (CAPTURED/FAILED/UNMAPPED) ---
export type PageState = "CAPTURED" | "FAILED" | "UNMAPPED";

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
