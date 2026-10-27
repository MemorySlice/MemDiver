/**
 * Typed client for the memory-image routes (`api/routers/image.py`):
 *
 *   GET  /api/image/probe            — cheap facts, never hashes / runs pakunoda
 *   POST /api/image/profile          — JOB: resolve the kernel profile
 *   POST /api/image/open-view        — JOB: write a `.mdview` descriptor
 *   GET  /api/image/processes        — pslist rows of a kernel / process view
 *   POST /api/image/extract-process  — JOB: process view -> `.msl`
 *
 * A job returns `{task_id, status}` at once; progress streams over the task
 * WebSocket (`useTaskProgress`) and the producer payload arrives as the
 * terminal `done` event's `extra`.
 */

import { compact, postJson, request } from "./client";

export type ImageViewKind = "physical" | "kernel" | "process";

export interface ProfileStatus {
  /** `found` | `missing` | `unknown` (image not hashed yet). */
  status: "found" | "missing" | "unknown";
  isf?: string;
  origin?: string;
  banner?: string;
  reason?: string;
  attempts?: string[][];
}

export interface ImageProbe {
  image: string;
  size: number;
  physical_layer_chain: string[];
  image_sha256: string | null;
  profile: ProfileStatus;
  versions: Record<string, string | null>;
  banners?: string[];
}

export interface ImageJobTicket {
  task_id: string;
  status: string;
}

export interface ProfileResult extends ProfileStatus {
  image: string;
  image_sha256: string;
  sha256?: string;
}

export interface OpenViewResult {
  view_path: string;
  capture_id: string;
  descriptor: Record<string, unknown>;
}

export interface Location {
  space: string;
  value: number;
  capture_id: string;
}

export interface ProcessRow {
  pid: number;
  ppid: number;
  comm: string;
  uid: number | null;
  has_mm: boolean;
  task_offset: number;
  location: Location;
}

export interface ProcessList {
  view_path: string;
  capture_id: string;
  row_source: string;
  count: number;
  processes: ProcessRow[];
}

export interface ExtractResult {
  view_path: string;
  output_path: string;
  pid: number;
  regions_written: number;
  captured_bytes: number;
}

export interface OpenViewArgs {
  image_path: string;
  view: ImageViewKind;
  pid?: number;
  isf?: string;
  case_dir?: string;
  no_profile?: boolean;
  paging?: PagingOverride;
  draft?: string;
  draft_version?: string;
}

/** Manual paging for a profile-less kernel view; omitted fields are auto-detected. */
export interface PagingOverride {
  pgd_phys?: number | string;
  arch?: string;
  va_bits?: number;
  page_size?: number;
}

export const probeImage = (imagePath: string, banners = false, isf?: string) => {
  const qs = new URLSearchParams({ image_path: imagePath });
  if (banners) qs.set("banners", "true");
  if (isf) qs.set("isf", isf);
  return request<ImageProbe>(`/api/image/probe?${qs}`);
};

export const startProfileJob = (imagePath: string, isf?: string, allowPakunoda = true) =>
  postJson<ImageJobTicket>("/api/image/profile", compact({
    image_path: imagePath, isf, allow_pakunoda: allowPakunoda,
  }));

/** Cooperative cancel of a job (`DELETE /api/tasks/{id}`; 409 once it is terminal). */
export const cancelImageJob = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean }>(
    `/api/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" });

export const startOpenViewJob = (args: OpenViewArgs) =>
  postJson<ImageJobTicket>("/api/image/open-view", compact(args));

export const listImageProcesses = (viewPath: string, limit?: number) => {
  const qs = new URLSearchParams({ view_path: viewPath });
  if (limit !== undefined) qs.set("limit", String(limit));
  return request<ProcessList>(`/api/image/processes?${qs}`);
};

export const startExtractProcessJob = (viewPath: string, outPath: string) =>
  postJson<ImageJobTicket>("/api/image/extract-process", { view_path: viewPath, out_path: outPath });
