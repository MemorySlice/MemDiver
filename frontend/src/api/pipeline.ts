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
  // Pcap-oracle work caps, both validated server-side as >= 1 (api/routers/
  // pipeline.py). Omit or send null to keep the backend defaults: 16 records
  // per direction, no total challenge cap. Both are silent truncations of
  // verification coverage, so send them only deliberately -- and read the arm
  // step's `caps` / `records_truncated` to see what a capture actually loses.
  pcap_max_records?: number | null;
  pcap_max_challenges?: number | null;
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
  // Record accounting added by ``TlsPcapResource.describe_capture``: how many
  // application-data records the parser saw across both directions, and how
  // many of those the challenge stream actually COVERS -- after the per-
  // direction record cap, the TLS 1.2 ChangeCipherSpec gate, and whatever is
  // left of the total challenge budget. ``records_returned < app_records_seen``
  // means this session is only partially verified; ``records_returned: 0`` on a
  // session with records means it is not verified at all (look in
  // ``skipped_sessions`` for the reason). Optional so a caller holding a
  // ``describe_sessions`` dict (which carries neither) still type-checks.
  app_records_seen?: number;
  records_returned?: number;
  // Challenge accounting. A challenge is NOT a record: a TLS 1.3 record is
  // probed over a sequence-number window (up to 9 candidates), so one record
  // can contribute several challenges and this can far exceed
  // ``records_returned``. ``challenges_available`` is what the session would
  // contribute uncapped, ``challenges_returned`` what survives
  // ``caps.max_challenges`` -- which is spent ACROSS sessions in parse order,
  // so a later session can legitimately report 0 here.
  challenges_available?: number;
  challenges_returned?: number;
}

/**
 * Why the parser had to drop work, machine-readable. Mirrors the ``reason``
 * values ``TlsPcapResource._note_skipped`` emits; the list is closed on the
 * backend today, so a new reason is a deliberate contract change on both sides.
 *
 * Not every reason drops a whole session. ``no_change_cipher_spec`` KEEPS the
 * session and reports that one direction's application data is unreachable,
 * and ``client_random_mismatch`` reports a session that parsed fine but is not
 * the one the resource is pinned to -- so a row can appear in both ``sessions``
 * and ``skipped_sessions``, which is the point: it explains a
 * ``records_returned: 0`` that would otherwise read as an unexplained zero.
 * ``client_random_mismatch`` requires a pinned resource, which the arm producer
 * does not do, so expect it from a run rather than from this response.
 *
 * ``no_cipher_suite`` and ``short_random`` are defensive guards the bundled
 * dpkt cannot actually produce (it always yields a 32-byte random and an int
 * suite code, and a short random surfaces as ``no_server_hello``). They stay
 * in the union so a different dpkt build cannot break the narrowing, but a UI
 * must not present them as expected outcomes.
 */
export type PcapSkipReason =
  | "no_client_hello"
  | "no_server_hello"
  | "no_cipher_suite"
  | "short_random"
  | "unsupported_cipher_suite"
  | "no_change_cipher_spec"
  | "client_random_mismatch";

/**
 * One piece of work the parser saw but could not use. ``flow`` is the
 * human-readable directional flow label ("ip:port -> ip:port"); the remaining
 * fields are reason-specific context (``cipher_suite`` for an out-of-table
 * suite, the two random lengths for a truncated handshake, ``direction`` plus
 * that direction's ``app_records_seen`` for a missing ChangeCipherSpec, and
 * the hex ``client_random`` of a session this run is not pinned to).
 */
export interface PcapSkippedSession {
  reason: PcapSkipReason;
  flow: string;
  cipher_suite?: number;
  client_random_len?: number;
  server_random_len?: number;
  /** ``no_change_cipher_spec`` only: which half of the session is unreachable. */
  direction?: "client" | "server";
  /** ``no_change_cipher_spec`` only: application-data records lost on that
   * direction. Per-direction, so it does NOT match the session-level
   * ``PcapSession.app_records_seen``, which sums both directions. */
  app_records_seen?: number;
  /** ``client_random_mismatch`` only: hex ``client_random`` of the session the
   * stream skipped, so the UI can say WHICH session was passed over. */
  client_random?: string;
}

/**
 * The caps in force for a capture (``describe_capture().caps``).
 *
 * Both are silent losses of verification coverage, which is why both are
 * reported rather than only the record one. ``max_challenges`` is ``null`` when
 * uncapped -- the KEY is always present, so "uncapped" can never be mistaken
 * for "unreported".
 */
export interface PcapCaps {
  /** Application-data records each DIRECTION of each session contributes. */
  max_records_per_direction: number;
  /** Total challenges the oracle keeps, spent across sessions in parse order;
   * ``null`` = uncapped. A value below 1 is rejected server-side. */
  max_challenges?: number | null;
}

/**
 * Server-side validation of an uploaded pcap: the sessions it contains.
 *
 * The accounting fields below say what the parse *dropped*, and exist so a
 * zero-confirmation run is never mistaken for full coverage: a session with a
 * cipher suite outside the parser's table used to vanish with only a log line.
 * They are optional purely for backward compatibility with a cached or older
 * response.
 *
 * ``POST /api/pcaps/validate`` returns the ``app.tools_pipeline.inspect_pcap``
 * dict verbatim, and that producer emits every key below. They stay optional so
 * a cached or older response still type-checks -- read them defensively, do not
 * treat an absent one as an error.
 */
export interface PcapValidateResult {
  pcap_path: string;
  session_count: number;
  sessions: PcapSession[];
  /** Work the parser dropped, each entry with a machine-readable reason. Not
   * all of it is a whole session -- see ``PcapSkipReason``. */
  skipped_sessions?: PcapSkippedSession[];
  /** Directional TCP flows the capture yielded -- the denominator for
   * ``session_count``: "1 session out of 40 flows" is not "1 out of 2". */
  flow_count?: number;
  caps?: PcapCaps;
  /** True when any session returns fewer records than it saw, WHATEVER the
   * cause: ``caps.max_records_per_direction``, a missing TLS 1.2
   * ChangeCipherSpec (which makes a direction undecryptable outright), or an
   * exhausted ``caps.max_challenges`` budget. It is not a statement about the
   * record cap alone. */
  records_truncated?: boolean;
  /** Challenges the whole capture would contribute uncapped. Reported because
   * it is not derivable from the record counts: a TLS 1.3 record is probed over
   * a sequence-number window, so the corpus average is ~3.9 challenges per
   * record -- a ``max_challenges`` of 50 therefore covers only ~13 records. */
  challenges_available?: number;
  /** Challenges that survive ``caps.max_challenges``. */
  challenges_returned?: number;
  /** ``challenges_returned < challenges_available`` -- some record got only
   * part of its sequence window, so a no-hit run is a statement about the
   * challenges tried, not about the capture. */
  challenges_truncated?: boolean;
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
