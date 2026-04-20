/**
 * Typed client for the Phase 25 pipeline endpoints.
 *
 * Mirrors the Pydantic models in api/routers/pipeline.py and the
 * TaskRecord shape from api/services/task_manager.py. Consumers
 * should prefer these helpers over hand-rolled fetch calls so
 * request/response changes stay in one place.
 */

import { request } from "./client";

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
  oracle_id: string;
  reduce?: ReduceParams;
  brute_force?: BruteForceParams;
  nsweep?: NSweepParams | null;
  emit?: EmitParams | null;
}

export interface PipelineRunResponse {
  task_id: string;
  status: string;
  oracle_sha256: string;
}

// ---- response models ----

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
  hit_neighborhoods: Array<{
    offset: number;
    neighborhood_start: number;
    neighborhood_variance: number[];
    static_count: number;
    dynamic_count: number;
  }>;
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
