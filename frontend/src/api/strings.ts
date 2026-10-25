/**
 * Typed client for the strings-table route (`api/routers/strings.py`):
 *
 *   POST /api/strings/table — one row per string of the CAPTURED bytes, with
 *                             `addr` + `space`, region and IOC badges (`iocs`).
 *
 * Small dumps are answered inline; a large one (over 64 MiB of captured bytes,
 * decided server-side, with no way to refuse) returns `{task_id, status}` (a job),
 * surfaced as `StringsJobTicket`; the caller follows it over the task WebSocket
 * and reads `getStringsJobPayload`.
 */

import { request } from "./client";
import { parseJsonLossless, postLossless, type WireInt } from "./lossless-json";

export type StringsView = "va" | "vas" | "raw";
export type StringsEncoding = "ascii" | "utf-8" | "utf16le";

export interface StringsTableRow {
  addr: WireInt;
  /** AddressSpace value `addr` is expressed in (`msl_va`, `msl_vas`, `file_offset`). */
  space: string;
  encoding: StringsEncoding;
  /** Characters in the string. */
  length: number;
  byte_length: number;
  value: string;
  value_truncated: boolean;
  /** IOC kinds that match (`urls`, `ipv4`, `unix_paths`, ...). */
  iocs: string[];
  va: WireInt | null;
  vas_offset: number;
  region: { start: number; end: number; perms: string | null; path: string | null } | null;
}

export interface StringsTable {
  view: StringsView;
  space: string;
  rows: StringsTableRow[];
  row_count: number;
  limit: number;
  truncated: boolean;
  complete: boolean;
  coverage: { captured_bytes: number; bytes_scanned: number; gaps_skipped: number };
}

export interface StringsJobTicket {
  task_id: string;
  status: string;
}

export interface StringsTableRequest {
  dump_path: string;
  view?: StringsView;
  min_len?: number;
  encodings?: StringsEncoding[];
  limit?: number;
}

export const isJobTicket = (r: StringsTable | StringsJobTicket): r is StringsJobTicket =>
  "task_id" in r;

export const getStringsTable = (
  body: StringsTableRequest,
  signal?: AbortSignal,
): Promise<StringsTable | StringsJobTicket> =>
  // Lossless: a kernel-VA `addr` exceeds 2^53 and arrives as a decimal string.
  postLossless<StringsTable | StringsJobTicket>("/api/strings/table", body, signal);

export const STRINGS_SYNC_MAX_BYTES = 64 * 1024 * 1024;

/** A finished job's `strings_result` payload, or `null`. */
export async function getStringsJobPayload(taskId: string): Promise<StringsTable | null> {
  const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/result`);
  if (!res.ok) throw new Error(await res.text());
  const body = parseJsonLossless(await res.text()) as { payload?: StringsTable | null } | null;
  return body?.payload ?? null;
}

export const cancelStringsJob = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean }>(
    `/api/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" });
