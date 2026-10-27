/**
 * Typed client for the Volatility 3 routes (`api/routers/vol3.py`):
 *
 *   GET  /api/vol3/plugins   — bundled plugins of an OS family
 *   POST /api/vol3/describe  — a plugin's user requirements (argument schema)
 *   POST /api/vol3/run       — INLINE (timeout_s <= 30 and limit <= 10000) or a JOB
 *   POST /api/vol3/scaffold  — source text of a new plugin
 *   POST /api/vol3/check     — load source (and test it against a view)
 *   GET/PUT /api/vol3/sources[/{name}] — plugin sources stored in a case
 *   GET/PUT /api/vol3/fixtures[/{name}], POST .../run — plugin fixtures (D13)
 *   POST /api/vol3/annotate  — file `plugin_row` entries for a registered run
 *   DELETE /api/tasks/{id}   — cancel a job
 *
 * A job returns `{task_id, status}`; progress streams over the task WebSocket
 * and the producer payload arrives as the terminal `done` event's `extra`.
 */

import { ApiError, compact, postJson as post, request } from "./client";
import type { PageStatesResponse } from "./types";
import { getTaskPayload, parseJsonLossless, postLossless } from "./lossless-json";
import { hasKey } from "./guards";

export interface Vol3Plugin {
  name: string;
  description: string;
  version: string;
}

export interface Vol3PluginList {
  os_family: string;
  plugins: Vol3Plugin[];
  count: number;
}

export type Vol3ArgType = "integer" | "string" | "boolean" | "array";

export interface Vol3Requirement {
  name: string;
  type: Vol3ArgType;
  requirement: string;
  description: string;
  optional: boolean;
  default: unknown;
  /** `array` only. */
  items?: { type: "integer" | "boolean" | "string" };
  min_elements?: number;
  max_elements?: number | null;
  /** Present for a `ChoiceRequirement`. */
  choices?: string[];
}

export interface Vol3PluginDescription extends Vol3Plugin {
  requirements: Vol3Requirement[];
  satisfied_by_context: string[];
}

export interface Vol3Column {
  name: string;
  /** int | hex | str | bytes | datetime | bool | float | multi */
  type: string;
  /** AddressSpace value for an address column, else null. */
  space: string | null;
  /** The kernel type the address column points at (e.g. `task_struct`); absent when unknown. */
  object_type?: string;
  /** Byte size of that type; the highlight length. Absent when unknown. */
  object_size?: number;
}

export interface Vol3Row {
  depth: number;
  /** One cell per column; `null` where the cell is absent. */
  values: unknown[];
  /** column name -> the absent-value class (why the cell has no value). */
  absent: Record<string, string>;
}

export interface Vol3RunResult {
  plugin: string;
  capture_id: string | null;
  columns: Vol3Column[];
  rows: Vol3Row[];
  row_count: number;
  rows_returned: number;
  truncated: boolean;
  /** `row_limit` | `timeout` | null. */
  stop_reason: string | null;
  elapsed_s: number;
  diagnostics: string[];
  files: string[];
  defaults_applied: Record<string, unknown>;
  args: Record<string, unknown>;
  /** Set only when the run was registered into a case. */
  table: Record<string, unknown> | null;
  run_id: string | null;
  /** The active `.mdview` the run read (absent on an older server). */
  view?: Vol3ViewBlock | null;
}

/** `app/image_preview.py::view_block`: the view's kind, pid and capture. */
export interface Vol3ViewBlock {
  kind: "physical" | "kernel" | "process";
  /** The process view's pid; `null` for physical / kernel views. */
  pid: number | null;
  capture_id: string | null;
  view_path: string;
}

export interface Vol3JobTicket {
  task_id: string;
  status: string;
}

export interface Vol3RunRequest {
  view_path: string;
  /** A bundled plugin's name; omit when running `source` / `source_name`. */
  plugin?: string;
  /** Raw (unsaved) plugin source: runs UNSANDBOXED in the server process. */
  source?: string;
  /** A source stored in `case_dir` (see `putVol3Source`). */
  source_name?: string;
  args?: Record<string, unknown>;
  case_dir?: string;
  limit?: number;
  timeout_s?: number;
  max_rows?: number;
  column_map?: Record<string, string | null>;
  async?: boolean;
}

export interface Vol3AnnotateRequest {
  case_dir: string;
  table: string;
  run_id: string;
  column: string;
  label_column?: string;
  rows?: number[];
}

/** A run answers inline with its result, or as a job ticket. */
export const isJobTicket = (r: unknown): r is Vol3JobTicket => hasKey(r, "task_id");

export const listVol3Plugins = (osFamily = "linux") =>
  request<Vol3PluginList>(`/api/vol3/plugins?os_family=${encodeURIComponent(osFamily)}`);

export const describeVol3Plugin = (plugin: string) =>
  post<Vol3PluginDescription>("/api/vol3/describe", { plugin });

export const runVol3Plugin = (req: Vol3RunRequest) =>
  // Lossless: kernel addresses exceed 2^53 and must not be rounded by JSON.parse.
  postLossless<Vol3RunResult | Vol3JobTicket>("/api/vol3/run", compact(req));

export const annotateVol3Run = (req: Vol3AnnotateRequest) =>
  post<Record<string, unknown>>("/api/vol3/annotate", compact(req));

/**
 * The exact run document of a finished JOB (`GET /api/tasks/{id}/result` ->
 * `.payload`), parsed losslessly; `null` when the server stored none. The task
 * WebSocket's copy went through `JSON.parse` and has rounded kernel addresses.
 */
export const getVol3JobPayload = (taskId: string) => getTaskPayload<Vol3RunResult>(taskId);

/**
 * The VA -> packed-offset map of a view (`page-states?view=vas`), parsed
 * losslessly: a kernel view's VAs exceed 2^53, so each interval `va` may arrive
 * as a decimal STRING — read it with `BigInt`. The default `va` request is
 * refused by a kernel view (it offers no `va`), but `vas` navigation needs only
 * this map. The legacy inspect contract answers a refusal as 200 + `{error}`.
 */
export async function getVasNavigationMap(viewPath: string): Promise<PageStatesResponse> {
  const qs = new URLSearchParams({ msl_path: viewPath, view: "vas" });
  const res = await fetch(`/api/inspect/page-states?${qs.toString()}`);
  const text = await res.text();
  if (!res.ok) throw new ApiError(res.status, text);
  const body = parseJsonLossless(text) as PageStatesResponse & { error?: string };
  if (body.error !== undefined || !Array.isArray(body.regions)) {
    throw new ApiError(res.status, text);
  }
  return body;
}

export const cancelVol3Job = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean }>(
    `/api/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" });

// -- plugin editor (T2.5) ----------------------------------------------------

export interface Vol3ScaffoldResult {
  class_name: string;
  os_family: string;
  per_process: boolean;
  source: string;
  line_count: number;
}

export interface Vol3CheckError {
  type: string;
  message: string;
  /** 1-based line inside the plugin source, when the failure has one. */
  line: number | null;
  offset: number | null;
  text: string | null;
  code: string | null;
}

export interface Vol3UnsatisfiedRequirement {
  name: string;
  requirement: string;
  optional?: boolean;
  description?: string;
  path?: string;
  reason?: string;
  code?: string;
}

/** A broken plugin is a finding (`ok: false`), never an HTTP error. */
export type Vol3CheckOutcome =
  | {
      ok: true;
      plugin: Vol3PluginDescription;
      view_path?: string;
      unsatisfied?: Vol3UnsatisfiedRequirement[];
      satisfied?: boolean;
    }
  | { ok: false; error: Vol3CheckError };

export interface Vol3SourceMeta {
  name: string;
  sha256: string;
  size: number;
  created: string | null;
  updated: string | null;
  version: number | null;
  path: string;
  modified_externally?: boolean;
}

export interface Vol3SourceDocument extends Vol3SourceMeta {
  source: string;
}

export interface Vol3SourcePutResult {
  stored: Vol3SourceMeta;
  check: Vol3CheckOutcome;
}

export const scaffoldVol3Plugin = (name: string, perProcess: boolean) =>
  post<Vol3ScaffoldResult>("/api/vol3/scaffold", { name, per_process: perProcess });

export const checkVol3Source = (body: {
  source?: string; source_name?: string; case_dir?: string; view_path?: string;
}) => post<Vol3CheckOutcome>("/api/vol3/check", compact(body));

export const listVol3Sources = (caseDir: string) =>
  request<{ sources: Vol3SourceMeta[]; count: number }>(
    `/api/vol3/sources?case_dir=${encodeURIComponent(caseDir)}`);

export const getVol3Source = (caseDir: string, name: string) =>
  request<Vol3SourceDocument>(
    `/api/vol3/sources/${encodeURIComponent(name)}?case_dir=${encodeURIComponent(caseDir)}`);

export const putVol3Source = (
  caseDir: string, name: string, source: string, viewPath?: string,
) => request<Vol3SourcePutResult>(`/api/vol3/sources/${encodeURIComponent(name)}`, {
  method: "PUT",
  body: JSON.stringify(compact({ case_dir: caseDir, source, view_path: viewPath })),
});

// -- plugin fixtures (T2.8, D13) ---------------------------------------------

/** One declarative row predicate (see `analysis/fixture_predicates.py`). */
export type Vol3Predicate = Record<string, unknown>;

export interface Vol3Fixture {
  name: string;
  plugin: string;
  source_name: string | null;
  view_path: string;
  args: Record<string, unknown>;
  expect: Vol3Predicate[];
  version?: number;
  updated?: string;
}

export type Vol3Verdict = "pass" | "fail" | "indeterminate";

export interface Vol3PredicateResult {
  ok: boolean;
  detail?: string;
  [key: string]: unknown;
}

export interface Vol3FixtureRun {
  fixture: string;
  verdict: Vol3Verdict;
  reason: string | null;
  predicates: Vol3PredicateResult[];
  row_count: number | null;
  truncated: boolean | null;
  recorded: boolean;
}

export const listVol3Fixtures = (caseDir: string) =>
  request<{ fixtures: Vol3Fixture[]; count: number }>(
    `/api/vol3/fixtures?case_dir=${encodeURIComponent(caseDir)}`);

export const putVol3Fixture = (caseDir: string, name: string, body: {
  view_path: string; expect: Vol3Predicate[]; plugin?: string; source_name?: string;
  args?: Record<string, unknown>;
}) => request<Vol3Fixture>(`/api/vol3/fixtures/${encodeURIComponent(name)}`, {
  method: "PUT",
  body: JSON.stringify(compact({ case_dir: caseDir, ...body })),
});

export const runVol3Fixture = (caseDir: string, name: string, viewPath?: string) =>
  post<Vol3FixtureRun>(`/api/vol3/fixtures/${encodeURIComponent(name)}/run`,
    compact({ case_dir: caseDir, view_path: viewPath }));

// -- case queries (T2.7) -----------------------------------------------------

export interface Vol3SavedQuery {
  name: string;
  description: string;
  [extra: string]: unknown;
}

/** `POST /api/vol3/query` with sql/saved: columns are names, rows are arrays. */
export interface Vol3QueryResult {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
  row_count: number;
  limit: number;
  elapsed_s: number;
  saved?: string;
  description?: string;
  /** Backend caveats (e.g. raw SQL over a truncated table run). */
  warnings?: unknown[];
}

/** Neither `sql` nor `saved` lists the saved queries. */
export const listVol3SavedQueries = (caseDir: string) =>
  post<{ saved_queries: Vol3SavedQuery[]; count: number }>("/api/vol3/query", { case_dir: caseDir });

/** Lossless: `addr` columns of a case table are uint64. */
export const runVol3Query = (caseDir: string, body: { sql?: string; saved?: string; limit?: number }) =>
  postLossless<Vol3QueryResult>("/api/vol3/query", compact({ case_dir: caseDir, ...body }));
