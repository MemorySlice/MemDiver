/**
 * Typed client for the key-finder routes (`api/routers/keyfinders.py`):
 *
 *   GET    /api/keyfinders       — the finders and the params each reads
 *   POST   /api/keyfinders/scan  — INLINE (small capture) or a JOB `{task_id, status}`
 *   GET    /api/tasks/{id}/result — a finished job's payload
 *   DELETE /api/tasks/{id}       — cancel a job
 */

import { getTaskPayload, postLossless, type WireInt } from "./lossless-json";
import { hasKey } from "./guards";
import { compact, request } from "./client";

export type HeapPolicy = "off" | "annotate" | "mask";

export interface KeyFinderParameter {
  name: string;
  default?: unknown;
  source?: string;
}

export interface KeyFinderInfo {
  name: string;
  description: string;
  mode: string;
  module: string;
  parameters: KeyFinderParameter[];
}

export interface KeyFinderList {
  finders: KeyFinderInfo[];
  count: number;
  default_finders: string[];
  heap_policies: HeapPolicy[];
}

export interface KeyHitHeap {
  chunk_va: WireInt;
  chunk_size: number;
  state: string;
  role: string;
  spans_chunks?: boolean;
}

export interface KeyHitRegion {
  start?: number;
  end?: number;
  perms?: string | null;
  path?: string | null;
  type?: string | null;
}

export interface KeyHitRow {
  finder: string;
  label: string;
  /** Address in the scanned `view`'s coordinate system. */
  addr: WireInt;
  space: string;
  length: number;
  confidence: number;
  metadata: Record<string, unknown>;
  va: WireInt | null;
  vas_offset: number;
  heap: KeyHitHeap | null;
  region: KeyHitRegion | null;
}

export interface KeyFindersResult {
  dump_path: string;
  view: string;
  space: string;
  finders: string[];
  heap_policy: HeapPolicy;
  heap: { policy: HeapPolicy; status: string; masked_out: number };
  rows: KeyHitRow[];
  row_count: number;
  limit: number;
  truncated: boolean;
  complete: boolean;
  coverage: Record<string, unknown>;
  candidates: unknown[];
}

export interface KeyFindersJobTicket {
  task_id: string;
  status: string;
}

export interface KeyFindersScanRequest {
  dump_path: string;
  finders: string[];
  view?: string;
  offset?: number;
  length?: number;
  heap_policy: HeapPolicy;
  params?: Record<string, unknown>;
  case_dir?: string;
  limit?: number;
  async?: boolean;
}

export const isKeyFindersTicket = (r: unknown): r is KeyFindersJobTicket => hasKey(r, "task_id");

export const listKeyFinders = () => request<KeyFinderList>("/api/keyfinders");

export const scanKeyFinders = (body: KeyFindersScanRequest) =>
  // Lossless: a kernel-VA `addr` exceeds 2^53 and arrives as a decimal string.
  postLossless<KeyFindersResult | KeyFindersJobTicket>("/api/keyfinders/scan", compact(body));

/** A finished job's `keyfinders_result` payload, or `null`. */
export const getKeyFindersJobPayload = (taskId: string) => getTaskPayload<KeyFindersResult>(taskId);

export const cancelKeyFindersJob = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean }>(
    `/api/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" });
