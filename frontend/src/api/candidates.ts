/**
 * Typed client for `POST /api/analysis/candidates` — the exploratory
 * differential path.
 *
 * Mirrors the Pydantic `AnalysisCandidatesRequest` (api/models.py) and the
 * payload of `app.tools_pipeline.analyze_candidates` 1:1, following the
 * `./pipeline` precedent: request/response shapes live here so a backend
 * change lands in one file rather than in every component that fetches.
 *
 * This is the ONE route that takes N dumps and returns a ranked candidate
 * list with no oracle and no pcap. `POST /api/pipeline/run` refuses to run
 * without one — correctly, because that flow exists to drive a brute force —
 * so an analyst who cannot yet confirm a key reaches a list only through here.
 */

import { request } from "./client";

// ---- byte classes (core/variance.py ByteClass) ----

export const BYTE_CLASSES = [
  "invariant",
  "structural",
  "pointer",
  "key_candidate",
] as const;

export type ByteClassName = (typeof BYTE_CLASSES)[number];

/**
 * The default class selection: every NON-invariant band.
 *
 * NOT `key_candidate` alone, and this is measured, not stylistic. Real key
 * material is class-MIXED: on eight real dumps of one OpenSSL run the actual
 * 48-byte TLS 1.2 secret classifies as 22 KEY_CANDIDATE + 18 POINTER + 8
 * STRUCTURAL, so its longest contiguous KEY_CANDIDATE run is 3 bytes. A
 * `key_candidate`-only query returns 7 regions and the key is not one of
 * them — it comes back as fragments from INSIDE the key, or not at all.
 * Querying all three non-invariant bands returns 25 regions with the key as
 * one clean 48-byte row at rank 10.
 *
 * `tests/frontend/api/candidates.test.ts` fails if this ever narrows to
 * key_candidate-only.
 */
export const NON_INVARIANT_CLASSES: readonly ByteClassName[] = [
  "structural",
  "pointer",
  "key_candidate",
];

export const DEFAULT_CANDIDATE_CLASSES: readonly ByteClassName[] =
  NON_INVARIANT_CLASSES;

// ---- alignment provenance (engine/consensus.py AlignmentReport) ----

export type AlignmentMethod =
  | "module_offset"
  | "virtual_address"
  | "file_offset";

/**
 * Are candidate offsets directly usable as hex-viewer offsets?
 *
 * Only under `file_offset`. The two ALIGNED methods index into a concatenated
 * slab of the regions the dumps have in common, so a candidate's offset is a
 * slab index, NOT a position in any one dump's byte stream -- and no slab->VA
 * mapping is exposed today (`/consensus/va-range` maps VA->slab, the wrong
 * way). Jumping the viewer to a slab index would scroll to real bytes at the
 * wrong address, which is the failure this repo already hit once when the
 * consensus overlay painted slab-coordinate classes at raw-container offsets.
 * Refusing the jump is the honest option until that endpoint exists.
 */
export function offsetsAreDumpOffsets(report: AlignmentReport): boolean {
  return report.method === "file_offset";
}

export interface AlignmentReport {
  method: AlignmentMethod;
  bytes_compared: number;
  bytes_discarded: number;
  sizes_differed: boolean;
  n_sources: number;
  /** Non-empty exactly when the comparison is questionable. */
  warnings: string[];
}

// ---- regions (engine/candidate_pipeline.py CandidateRegion) ----

/** The four normalized sub-scores behind `CandidateRegion.score`. */
export interface CandidateScoreComponents {
  byte_class: number;
  variance: number;
  entropy: number;
  length: number;
}

export interface CandidateRegion {
  offset: number;
  length: number;
  /** 1-based position in the score ranking, stamped whatever `order` ran. */
  rank: number;
  score: number;
  score_components: CandidateScoreComponents;
  /**
   * Per-ByteClass byte counts inside the region. EMPTY in the entropy-only
   * fallback (N below the variance floor), where the backend declined to
   * classify rather than classify against untrustworthy variance.
   */
  class_counts: Partial<Record<ByteClassName, number>>;
  mean_variance: number;
  /** Mean of fixed-width sliding entropy windows overlapping the region. */
  mean_entropy: number;
  /** Shannon entropy of the region's OWN bytes, bits/byte. */
  region_entropy: number;
}

/** Reduction funnel counts (engine/candidate_pipeline.py StageCounts). */
export interface CandidateStages {
  total_bytes: number;
  variance: number;
  byte_class: number;
  aligned: number;
  high_entropy: number;
}

/** Structured note qualifying a result (core.service_result.Diagnostic). */
export interface CandidateDiagnostic {
  code: string;
  message: string;
  severity: string;
  details?: Record<string, unknown>;
}

// ---- request / response ----

export type CandidateOrder = "rank" | "offset";

export interface AnalysisCandidatesRequest {
  dump_paths: string[];
  classes?: ByteClassName[] | null;
  /**
   * DELIBERATELY OMITTED by `buildCandidatesRequest`. The backend resolves it
   * against `classes` (3000 when no class is named, 0 when one is); sending
   * 3000 from here would silently re-impose the KEY_CANDIDATE floor that the
   * class filter just opened, and the mixed-class key would vanish again.
   */
  min_variance?: number | null;
  min_region?: number;
  max_region?: number;
  alignment?: number;
  block_size?: number;
  density_threshold?: number;
  entropy_window?: number;
  entropy_threshold?: number;
  order?: CandidateOrder;
  max_returned?: number;
  normalize?: boolean;
  project_id?: string;
}

export interface AnalysisCandidatesResponse {
  num_dumps: number;
  size: number;
  class_counts: Partial<Record<ByteClassName, number>>;
  alignment: AlignmentReport;
  /** The RESOLVED thresholds the reduction actually ran with. */
  thresholds: Record<string, unknown>;
  stages: CandidateStages;
  fallback_entropy_only: boolean;
  /** True total, regardless of how many rows came back inline. */
  num_regions: number;
  regions: CandidateRegion[];
  regions_returned: number;
  regions_truncated: boolean;
  max_returned: number;
  order: string;
  consensus_id: string | null;
  persisted: boolean;
  candidates_persisted?: number;
  /** Hoisted `alignment.warnings` — the banner reads this. */
  warnings: string[];
  diagnostics: CandidateDiagnostic[];
}

// ---- filter state -> request ----

/** The four filter controls the Consensus tab exposes, as plain state. */
export interface CandidateFilterState {
  classes: ByteClassName[];
  /** Shortest region to keep, in bytes. */
  minRegion: number;
  /** Longest region to keep; 0 means "no upper bound" (backend contract). */
  maxRegion: number;
  /** Bits/byte a sliding window must reach. */
  entropyThreshold: number;
  /** Byte-alignment a candidate's start must satisfy. */
  alignment: number;
}

/** Defaults mirroring `AnalysisCandidatesRequest`, with the class rule above. */
export const DEFAULT_CANDIDATE_FILTERS: CandidateFilterState = {
  classes: [...DEFAULT_CANDIDATE_CLASSES],
  minRegion: 16,
  maxRegion: 0,
  entropyThreshold: 4.5,
  alignment: 8,
};

/** Rows returned inline; matches DEFAULT_MAX_RETURNED_REGIONS server-side. */
export const DEFAULT_MAX_RETURNED_REGIONS = 200;

/**
 * Compose the filter state into a request body.
 *
 * `min_variance` is never set: see the field comment above. Everything else is
 * sent explicitly so the body reads as the query that actually ran.
 */
export function buildCandidatesRequest(
  dumpPaths: string[],
  filters: CandidateFilterState,
  opts: { normalize?: boolean; maxReturned?: number; order?: CandidateOrder } = {},
): AnalysisCandidatesRequest {
  return {
    dump_paths: [...dumpPaths],
    classes: filters.classes.length > 0 ? [...filters.classes] : null,
    min_region: filters.minRegion,
    max_region: filters.maxRegion,
    entropy_threshold: filters.entropyThreshold,
    alignment: filters.alignment,
    order: opts.order ?? "rank",
    max_returned: opts.maxReturned ?? DEFAULT_MAX_RETURNED_REGIONS,
    normalize: opts.normalize ?? false,
  };
}

/**
 * The class that owns most of a region's bytes.
 *
 * Ties break toward the HIGHER-variance class, because a region that is half
 * pointer and half key-candidate is the more interesting of the two readings
 * and under-calling it is the costlier mistake. Returns null for the
 * entropy-only fallback, where nothing was classified.
 */
export function dominantClass(
  counts: Partial<Record<ByteClassName, number>>,
): ByteClassName | null {
  let best: ByteClassName | null = null;
  let bestCount = 0;
  for (const name of BYTE_CLASSES) {
    const count = counts[name] ?? 0;
    if (count > 0 && count >= bestCount) {
      best = name;
      bestCount = count;
    }
  }
  return best;
}

export const analyzeCandidates = (body: AnalysisCandidatesRequest) =>
  request<AnalysisCandidatesResponse>("/api/analysis/candidates", {
    method: "POST",
    body: JSON.stringify(body),
  });
