/**
 * Typed client for the Phase 25 pipeline endpoints.
 *
 * Mirrors the Pydantic models in api/routers/pipeline.py and the
 * TaskRecord shape from api/services/task_manager.py. Consumers
 * should prefer these helpers over hand-rolled fetch calls so
 * request/response changes stay in one place.
 */

import { request, uploadFile } from "./client";

// ---- request models (must match api/routers/pipeline.py) ----

export interface ReduceParams {
  alignment?: number;
  block_size?: number;
  density_threshold?: number;
  min_variance?: number;
  entropy_window?: number;
  entropy_threshold?: number;
  min_region?: number;
}

export interface BruteForceParams {
  key_sizes?: number[];
  stride?: number;
  jobs?: number;
  exhaustive?: boolean;
  top_k?: number;
}

export interface NSweepParams {
  n_values: number[];
  reduce_kwargs?: ReduceParams | null;
  key_sizes?: number[];
  stride?: number;
  exhaustive?: boolean;
}

export interface EmitParams {
  name?: string;
  description?: string | null;
  hit_index?: number;
  min_static_ratio?: number;
  variance_threshold?: number | null;
}

export interface PipelineRunRequest {
  source_paths: string[];
  // Supply exactly one oracle source: an armed BYO oracle (oracle_id) or a
  // pcap/pcapng of the same TLS session (pcap_path), which routes the
  // brute-force stage through the first-party trusted pcap oracle.
  oracle_id?: string | null;
  pcap_path?: string | null;
  tls_client_random?: string | null;
  reduce?: ReduceParams;
  brute_force?: BruteForceParams;
  nsweep?: NSweepParams | null;
  emit?: EmitParams | null;
}

export interface PipelineRunResponse {
  task_id: string;
  status: string;
  // null for a pcap-oracle run (no BYO oracle file to hash).
  oracle_sha256?: string | null;
}

// ---- pcap oracle upload + validation (api/routers/pcaps.py) ----

/** Result of uploading a pcap/pcapng to the server-managed pcap dir. */
export interface PcapUploadResult {
  pcap_path: string;
  filename: string;
  size: number;
}

/**
 * One TLS session dpkt could parse out of the capture. ``version`` is the
 * negotiated TLS version ("12" = 1.2, "13" = 1.3); the app-record counts hint
 * whether there is ciphertext worth decrypting on each side.
 */
export interface PcapSession {
  client_random: string;
  server_random: string;
  version: "12" | "13";
  cipher_suite: number;
  cipher_name: string;
  client_app_records: number;
  server_app_records: number;
  // True when the session carries at least one application_data record the
  // oracle can decrypt. Always emitted by the backend, so ``sessionHasAppRecords``
  // reads it directly.
  has_app_records: boolean;
}

/** Server-side validation of an uploaded pcap: the sessions it contains. */
export interface PcapValidateResult {
  pcap_path: string;
  session_count: number;
  sessions: PcapSession[];
}

// ---- response models ----

/**
 * A single inferred structure field over a hit's neighborhood window.
 *
 * Produced server-side by ``PatternGenerator.infer_fields()`` (exposed via
 * ``POST /api/pipeline/infer-fields`` and the ``/refine`` response) so the
 * frontend consumes it instead of recomputing the segmentation client-side.
 * Shape matches the ``InferredField`` Pydantic contract byte-for-byte.
 */
export interface InferredField {
  offset: number;
  length: number;
  type: "static" | "key_material" | "dynamic";
  label: string;
  mean_variance: number;
}

export type TaskStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface StageRecord {
  name: string;
  status: TaskStatus;
  pct: number;
  msg: string;
  started_at: number | null;
  ended_at: number | null;
}

export interface ArtifactSpec {
  name: string;
  relpath: string;
  media_type: string;
  size: number;
  sha256: string | null;
  registered_at: number;
}

export interface TaskRecord {
  task_id: string;
  kind: string;
  status: TaskStatus;
  params: Record<string, unknown>;
  stages: StageRecord[];
  artifacts: ArtifactSpec[];
  created_at: number;
  started_at: number | null;
  ended_at: number | null;
  error: string | null;
  schema_version: number;
}

// ---- endpoints ----

export const runPipeline = (body: PipelineRunRequest) =>
  request<PipelineRunResponse>("/api/pipeline/run", {
    method: "POST",
    body: JSON.stringify(body),
  });

/**
 * Upload a pcap/pcapng. Multipart, so it delegates to the shared
 * ``uploadFile`` helper, which posts under the ``file`` form field and unwraps
 * FastAPI's ``{"detail": ...}`` error body into an ``ApiError`` so callers can
 * surface the capability-error message verbatim.
 */
export const uploadPcap = (file: File): Promise<PcapUploadResult> =>
  uploadFile<PcapUploadResult>("/api/pcaps/upload", file);

/**
 * Ask the server to parse the TLS sessions out of an uploaded pcap. On a
 * dpkt-missing / bad-capture condition the backend returns HTTP 400 via the
 * capability-error funnel, which ``request`` re-raises as an ``ApiError``.
 */
export const validatePcap = (pcapPath: string) =>
  request<PcapValidateResult>("/api/pcaps/validate", {
    method: "POST",
    body: JSON.stringify({ pcap_path: pcapPath }),
  });

export const getPipelineRun = (taskId: string) =>
  request<TaskRecord>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}`,
  );

export const cancelPipelineRun = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean; status?: string }>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}`,
    { method: "DELETE" },
  );

/**
 * Return an absolute URL for downloading a registered artifact. The
 * server enforces traversal + symlink guards via ArtifactStore so the
 * caller does not need to sanitize ``name``; it must still be one of
 * the ``name`` fields from a TaskRecord.artifacts entry.
 */
export const artifactDownloadUrl = (taskId: string, name: string): string =>
  `/api/pipeline/runs/${encodeURIComponent(taskId)}/artifacts/${encodeURIComponent(name)}`;

// --- Phase C: Refine workflow ---

export interface RefineResponse {
  num_dumps: number;
  static_count: number;
  dynamic_count: number;
  /** Variance threshold (PLUGIN_STATIC_THRESHOLD) used to classify bytes. */
  variance_threshold: number;
  hit_neighborhoods: Array<{
    offset: number;
    neighborhood_start: number;
    neighborhood_variance: number[];
    static_count: number;
    dynamic_count: number;
    /** Server-inferred field structure for this neighborhood window. */
    fields: InferredField[];
  }>;
}

/** Request body for ``POST /api/pipeline/infer-fields``. */
export interface InferFieldsRequest {
  neighborhood_variance: number[];
  neighborhood_start: number;
  offset: number;
  length: number;
  variance_threshold?: number | null;
}

/**
 * Segment a neighborhood variance array into contiguous static /
 * key_material / dynamic fields, server-side. Returns the inferred fields
 * plus the ``variance_threshold`` actually applied (so callers never hardcode
 * it). Replaces the former client-side ``inferNeighborhoodFields`` port.
 */
export async function inferFields(
  body: InferFieldsRequest,
): Promise<{ fields: InferredField[]; variance_threshold: number }> {
  return request<{ fields: InferredField[]; variance_threshold: number }>(
    "/api/pipeline/infer-fields",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
}

export async function refinePipeline(
  taskId: string,
  additionalPaths: string[],
): Promise<RefineResponse> {
  return request<RefineResponse>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}/refine`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ additional_paths: additionalPaths }),
    },
  );
}

export async function getNeighborhood(
  taskId: string,
  offset: number,
  length: number = 32,
): Promise<{ offset: number; neighborhood_start: number; num_dumps: number; variance: number[] }> {
  return request(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}/neighborhood?offset=${offset}&length=${length}`,
  );
}
