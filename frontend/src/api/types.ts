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

export interface SecretHit {
  secret_type: string;
  offset: number;
  length: number;
  dump_path: string;
  library: string;
  phase: string;
  run_id: number;
  confidence?: number;
}

export interface LibraryReport {
  library: string;
  protocol_version: string;
  phase: string;
  num_runs: number;
  hits: SecretHit[];
  static_regions: StaticRegion[];
  metadata: Record<string, unknown>;
}

export interface StaticRegion {
  start: number;
  end: number;
  mean_variance: number;
  classification: string;
}

export interface AnalysisResult {
  libraries: LibraryReport[];
  metadata: Record<string, unknown>;
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
}

export interface TaskStatus {
  task_id: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled" | "not_implemented";
  progress?: number;
  message?: string;
}

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
