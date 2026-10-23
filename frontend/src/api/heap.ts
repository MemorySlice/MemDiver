/**
 * Typed client for the heap-analysis routes (`/api/heap/*`).
 *
 * Request and response shapes live in `./types` (the `Heap*` interfaces); the
 * CLOSED vocabularies — allocator kinds, chunk states, byte roles — are const
 * tuples here so a backend rename breaks `npx tsc -b` instead of producing a
 * value no branch matches. Same precedent as `./locate-key`.
 *
 * Every call is a GET, so key material for an encrypted `.msl` rides the query
 * string exactly like the other inspect reads (`appendKey`, `./client`).
 */

import { appendKey, request } from "./client";
import type {
  HeapAllocatorChoice,
  HeapAllocatorKind,
  HeapChunkAtResponse,
  HeapChunkState,
  HeapChunksResponse,
  HeapDetectResponse,
  HeapFreeListsResponse,
  HeapRoleName,
  HeapRolesResponse,
  HeapSummaryResponse,
  KeyMaterial,
} from "./types";
import type { DumpViewMode } from "./client";

export const HEAP_ALLOCATORS = [
  "ptmalloc2",
  "dlmalloc",
  "scudo",
  "mallocng",
  "jemalloc",
  "generic",
  "unknown",
] as const satisfies readonly HeapAllocatorKind[];

export const HEAP_CHUNK_STATES = [
  "in_use",
  "free",
  "cached",
  "quarantined",
  "unknown",
] as const satisfies readonly HeapChunkState[];

export const HEAP_ROLES = [
  "chunk_header",
  "user_data",
  "free_link",
  "free_data",
  "allocator_meta",
  "top",
  "slack",
] as const satisfies readonly HeapRoleName[];

/** The allocator a request asks for when the caller has not chosen one. */
export const DEFAULT_HEAP_ALLOCATOR: HeapAllocatorChoice = "auto";

/** Filters `GET /api/heap/chunks` understands. Unset = no constraint. */
export interface HeapChunkFilters {
  state?: HeapChunkState | null;
  minSize?: number | null;
  maxSize?: number | null;
  vaStart?: number | null;
  vaEnd?: number | null;
  /** Restrict to chunks overlapping `[offset, offset + length)` in `view`. */
  offset?: number | null;
  length?: number | null;
}

/** Common inputs of every heap request. */
export interface HeapRequestBase {
  dumpPath: string;
  allocator?: HeapAllocatorChoice;
  key?: KeyMaterial;
}

function baseQuery({ dumpPath, allocator, key }: HeapRequestBase): URLSearchParams {
  const qs = new URLSearchParams({ dump_path: dumpPath });
  if (allocator && allocator !== DEFAULT_HEAP_ALLOCATOR) qs.set("allocator", allocator);
  appendKey(qs, key);
  return qs;
}

/** Set `name` only when `value` is a real number/string (null/undefined skip). */
function setIfPresent(qs: URLSearchParams, name: string, value: unknown): void {
  if (value === null || value === undefined || value === "") return;
  qs.set(name, String(value));
}

export const fetchHeapDetect = (base: HeapRequestBase) =>
  request<HeapDetectResponse>(`/api/heap/detect?${baseQuery(base).toString()}`);

export const fetchHeapSummary = (base: HeapRequestBase) =>
  request<HeapSummaryResponse>(`/api/heap/summary?${baseQuery(base).toString()}`);

export interface HeapChunksQuery extends HeapRequestBase {
  filters?: HeapChunkFilters;
  view?: DumpViewMode;
  page?: number;
  pageSize?: number;
}

export function fetchHeapChunks(query: HeapChunksQuery): Promise<HeapChunksResponse> {
  const qs = baseQuery(query);
  const f = query.filters ?? {};
  setIfPresent(qs, "state", f.state);
  setIfPresent(qs, "min_size", f.minSize);
  setIfPresent(qs, "max_size", f.maxSize);
  setIfPresent(qs, "va_start", f.vaStart);
  setIfPresent(qs, "va_end", f.vaEnd);
  setIfPresent(qs, "offset", f.offset);
  setIfPresent(qs, "length", f.length);
  setIfPresent(qs, "view", query.view);
  setIfPresent(qs, "page", query.page);
  setIfPresent(qs, "page_size", query.pageSize);
  return request<HeapChunksResponse>(`/api/heap/chunks?${qs.toString()}`);
}

/** Exactly one of `va` / `offset` addresses the byte; `offset` is in `view`. */
export interface HeapChunkAtQuery extends HeapRequestBase {
  va?: number;
  offset?: number;
  view?: DumpViewMode;
}

export function fetchHeapChunkAt(query: HeapChunkAtQuery): Promise<HeapChunkAtResponse> {
  const qs = baseQuery(query);
  setIfPresent(qs, "va", query.va);
  setIfPresent(qs, "offset", query.offset);
  setIfPresent(qs, "view", query.view);
  return request<HeapChunkAtResponse>(`/api/heap/chunk-at?${qs.toString()}`);
}

export interface HeapFreeListsQuery extends HeapRequestBase {
  kind?: string;
}

export function fetchHeapFreeLists(query: HeapFreeListsQuery): Promise<HeapFreeListsResponse> {
  const qs = baseQuery(query);
  setIfPresent(qs, "kind", query.kind);
  return request<HeapFreeListsResponse>(`/api/heap/free-lists?${qs.toString()}`);
}

export interface HeapRolesQuery extends HeapRequestBase {
  view: DumpViewMode;
  offset: number;
  length: number;
}

export function fetchHeapRoles(query: HeapRolesQuery): Promise<HeapRolesResponse> {
  const qs = baseQuery(query);
  qs.set("view", query.view);
  qs.set("offset", String(query.offset));
  qs.set("length", String(query.length));
  return request<HeapRolesResponse>(`/api/heap/roles?${qs.toString()}`);
}
