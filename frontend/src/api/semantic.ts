/**
 * Typed client for the semantic-workbench object-model routes:
 *
 *   POST /api/analysis/consensus/anchor  — consensus keyed by delta from each dump's own anchor
 *   POST /api/semantic/propose-layout    — field-boundary proposal around that anchor
 *
 * Both take EXACTLY ONE of `needles` ({dump_path: hex}) or `anchors`
 * ([{dump_path, va} | {dump_path, offset}]). A dump with no anchor is never dropped silently:
 * it comes back under `unanchored` and the response is PARTIAL.
 *
 * A `CapabilityError` reaches the client as an `ApiError`; `readableFailure` (api/client)
 * turns its JSON envelope into the message to show.
 */

import { request } from "./client";

export type AnchorSpec =
  | { dump_path: string; va: number }
  | { dump_path: string; offset: number };

/** A TLS key log (NSS format): exactly one of `path`, `text` (file content) or `per_dump`. */
export type KeylogSpec =
  | { path: string }
  | { text: string }
  | { per_dump: Record<string, string> };

/** Per dump: which key-log session it was anchored on, or why none could be chosen. */
export interface KeylogResolution {
  dump_path: string;
  anchored: boolean;
  client_random: string | null;
  candidates: number;
  reason: string;
  labels: Record<string, string>;
}

/** One key log's parse report: what was read, ignored, and dropped (1-based line numbers). */
export interface KeylogParseSummary {
  dump_path?: string;
  path?: string;
  text?: string;
  sessions: number;
  rows: number;
  ignored: Record<string, number>;
  malformed: number;
  conflicts: number;
  malformed_details: { line: number; reason: string }[];
  length_mismatches: string[];
}

/** A pre-filled field meaning derived from the key log (`label` empty = none). */
export interface SuggestedMeaning {
  field: string;
  meaning: string;
  label: string;
}

/** Present on results whose anchors came from a key log. */
export interface KeylogOutputs {
  keylog_resolution?: KeylogResolution[];
  keylog_anchor_label?: string;
  keylog_summary?: KeylogParseSummary[];
  suggested_meanings?: SuggestedMeaning[];
}

/** Inputs shared by both routes. */
export interface AnchorInputs {
  dump_paths?: string[];
  /** `{dump_path: hex}` — every occurrence is an alternative, `occurrence` picks the k-th. */
  needles?: Record<string, string>;
  anchors?: AnchorSpec[];
  /** Third anchor mode: replaces `needles`/`anchors`; needs `dump_paths`. */
  keylog?: KeylogSpec;
  anchor_label?: string;
  /** Omitted = every other label of the chosen session. */
  related_labels?: string[];
  occurrence?: number;
  delta_start?: number;
  length?: number;
  mixed_ok?: boolean;
}

export interface AnchorConsensusRequest extends AnchorInputs {
  min_instances?: number;
  include_bytes?: boolean;
}

export interface ProposeLayoutRequest extends AnchorInputs {
  anchor_length?: number;
  /** `{name: {dump_path: hex}}`: other verified values expected at one constant delta. */
  related?: Record<string, Record<string, string>>;
  pointer_quorum?: number;
  heap?: boolean;
  case_dir?: string;
  /** Server default is "summary"; the web client requests "full" (see `proposeLayout`). */
  detail?: PayloadDetail;
}

export type PayloadDetail = "summary" | "full";

export type ConsensusClassName =
  | "invariant" | "structural" | "pointer" | "key_candidate" | "undetermined";

export interface AnchorRegion {
  delta_start: number;
  /** Half-open. */
  delta_end: number;
  length: number;
  class: ConsensusClassName | string;
  min_captured: number;
  max_distinct: number;
}

export interface AnchorInstance {
  dump_path: string;
  va: number | null;
  offset: number;
  view: string;
  basis: string;
  captured_bytes: number;
}

export interface UnanchoredDump {
  dump_path: string;
  occurrences: number;
  reason: string;
}

export interface AnchorCommon {
  cohort: string | null;
  delta_start: number;
  length: number;
  occurrence: number;
  instances: AnchorInstance[];
  unanchored: UnanchoredDump[];
  /** Occurrence count per dump. */
  alternatives: Record<string, number>;
  class_counts: Record<string, number>;
  warnings: string[];
}

export interface AnchorConsensusResult extends AnchorCommon, KeylogOutputs {
  min_instances: number;
  regions: AnchorRegion[];
}

export interface ProposedField {
  delta: number;
  length: number;
  kind: string;
  name: string;
  /** Present with `detail: "full"`; a summary carries `alternatives_count` instead. */
  evidence?: string[];
  alternatives?: unknown[];
  alternatives_count?: number;
}

export interface ProposedLayoutResult extends AnchorCommon, KeylogOutputs {
  base_delta: number | null;
  total_size: number | null;
  bounds_evidence: string[];
  fields: ProposedField[];
  anchor_length: number;
  /** Present with `case_dir`. */
  record_entries?: string[];
}

const post = <T>(url: string, body: unknown) =>
  request<T>(url, { method: "POST", body: JSON.stringify(body) });

export const getAnchorConsensus = (body: AnchorConsensusRequest) =>
  post<AnchorConsensusResult>("/api/analysis/consensus/anchor", body);

export const proposeLayout = (body: ProposeLayoutRequest) =>
  post<ProposedLayoutResult>("/api/semantic/propose-layout", { detail: "full", ...body });

export interface FieldMeaningSpec {
  field: string;
  meaning: string;
  /** Output label; empty/omitted means none. */
  label?: string;
}

export interface RelationshipSpec {
  kind: "owned_by" | "same_object" | "pointer" | string;
  source: string;
  target: string;
}

export interface ApplicabilitySpec {
  library?: string;
  states?: string[];
}

export interface BuildModelRequest extends ProposeLayoutRequest {
  name: string;
  meanings?: FieldMeaningSpec[];
  relationships?: RelationshipSpec[];
  applicability?: ApplicabilitySpec;
  prefilter_length?: number;
  /** A NEW `.json` path; the server never overwrites. */
  out_path: string;
}

export interface BuildModelResult {
  /** Dropped by a summary build (see `omitted`); present with `detail: "full"`. */
  model?: Record<string, unknown>;
  path: string;
  sha256: string;
  problems: string[];
  proposal?: ProposedLayoutResult;
  record_entries?: string[];
  model_summary?: Record<string, unknown>;
  detail?: PayloadDetail;
  omitted?: string[];
  omitted_hint?: string;
}

export interface ExportModelRequest {
  model_path: string;
  out_path: string;
  plugin_name?: string;
}

export interface ExportModelResult {
  path: string;
  sha256: string;
  locator_kind: string;
  class_name: string;
  bytes: number;
}

/** One held-out capture: exactly one of `keylog_path` / `expected`. */
export interface HeldOutEntry {
  dump_path: string;
  /** Omit both when a shared `keylog` is sent on the request. */
  keylog_path?: string;
  expected?: { label: string; owner_hex: string; value_hex: string }[];
}

export interface ValidateModelRequest {
  model_path: string;
  held_out: HeldOutEntry[];
  labels?: string[];
  plugin_path?: string;
  out_path?: string;
  min_run?: number;
  /** One shared key log (`{path}` | `{text}`) for every capture naming no source of its own. */
  keylog?: Exclude<KeylogSpec, { per_dump: Record<string, string> }>;
}

export interface HeldOutCaptureResult {
  capture: string;
  expected: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  relationships_correct: number;
  relationships_checked: number;
  detail: string;
  /** Per-capture verdict; `indeterminate` = nothing was checked (0 sessions), never a pass. */
  verdict?: ValidationVerdict;
  scanned_runs?: number;
}

export type ValidationVerdict = "pass" | "fail" | "indeterminate" | string;

export interface ValidateModelResult {
  /** Parse report of the shared held-out key log (dropped/ignored lines), when one was given. */
  keylog_summary?: KeylogParseSummary[];
  verdict: ValidationVerdict;
  labels: string[];
  plugin_sha256: string;
  captures: HeldOutCaptureResult[];
  seconds: number;
  totals: {
    expected: number; tp: number; fp: number; fn: number;
    relationships_correct: number; relationships_checked: number;
  };
  model_path?: string;
}

export const buildArtifactModel = (body: BuildModelRequest) =>
  post<BuildModelResult>("/api/semantic/model-build", { detail: "full", ...body });

export const exportArtifactModel = (body: ExportModelRequest) =>
  post<ExportModelResult>("/api/semantic/model-export", body);

export const validateArtifactModel = (body: ValidateModelRequest) =>
  post<ValidateModelResult>("/api/semantic/model-validate", body);
