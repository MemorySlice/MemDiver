/**
 * Typed client for the YARA editor routes (`api/routers/yara.py`):
 *
 *   POST /api/yara/check — compile a rule; a rule that does not compile is a 200 with
 *                          `valid: false` and `errors: [{line, message}]`
 *   POST /api/yara/scan  — scan the CAPTURED bytes of ONE dump (optionally a window):
 *                          INLINE (small capture) or a JOB `{task_id, status}`
 *   GET|PUT|DELETE /api/yara/rules[/{name}] — the stored rules (library / case scope)
 *   GET    /api/tasks/{id}/result · DELETE /api/tasks/{id} — a job's payload / cancel
 *
 * Not `./scan` (the N-dump census): this one has a window, capture-gap coverage and
 * virtual addresses. Scan answers decode losslessly — a kernel VA exceeds 2^53 and
 * arrives as a decimal string ({@link WireInt}).
 */

import { request } from "./client";
import { getTaskPayload, postLossless, type WireInt } from "./lossless-json";
import { hasKey } from "./guards";

export interface YaraError {
  /** 1-based line libyara names, or `null`. */
  line: number | null;
  message: string;
  /** 1-based column span of the offending token, when it could be located. */
  column?: number | null;
  end_column?: number | null;
  /** The line libyara itself named (it may sit where the rule ENDS). */
  reported_line?: number | null;
  relocated?: boolean;
  rule?: string | null;
  hint?: string | null;
}

export interface YaraWarning {
  code: string;
  severity: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface YaraCheckResult {
  valid: boolean;
  rule_names: string[];
  errors: YaraError[];
  warnings: YaraWarning[];
  scan_limit?: number | null;
}

export interface YaraRegion {
  start?: WireInt;
  end?: WireInt;
  perms?: string | null;
  path?: string | null;
  type?: string | number | null;
}

export interface YaraHitRow {
  rule: string;
  tags: string[];
  string_id: string;
  /** Address in the scanned `view`'s coordinate system. */
  addr: WireInt;
  space: string;
  length: number;
  /** First bytes of the match only; `length` is the true width. */
  matched_hex: string;
  va: WireInt | null;
  vas_offset: number;
  region: YaraRegion | null;
}

export interface YaraCoverage {
  view: string;
  captured_bytes: number;
  bytes_scanned: number;
  runs_scanned: number;
  gaps_skipped: number;
  gap_bytes: WireInt;
  short_reads: number;
  requested_offset: number;
  requested_length: number | null;
}

export interface YaraScanResult {
  dump_path: string;
  view: string;
  space: string;
  rule_names: string[];
  matched_rules: string[];
  rows: YaraHitRow[];
  row_count: number;
  limit: number;
  truncated: boolean;
  timed_out: boolean;
  complete: boolean;
  incomplete_reason: string | null;
  errors: string[];
  warnings: YaraWarning[];
  coverage: YaraCoverage;
  /** Present when the scan used a stored rule. */
  rule_name?: string;
  scope?: RuleScope;
}

export interface YaraScanRequest {
  dump_path: string;
  /** Exactly one of `rule_source` / `rule_name` (a stored rule, resolved by the backend). */
  rule_source?: string;
  rule_name?: string;
  case_dir?: string;
  view?: string;
  offset?: number;
  length?: number;
  limit?: number;
  async?: boolean;
}

/** What `POST /api/yara/scan` returns for a large capture or `async: true`. */
export interface YaraJobTicket {
  task_id: string;
  status: string;
}

export type RuleScope = "library" | "case";

export interface YaraRuleMeta {
  name: string;
  scope: RuleScope;
  version: number | null;
  sha256: string;
  size: number;
  /** `null` when unknown (the file was edited outside MemDiver since it was checked). */
  compiles: boolean | null;
  errors: YaraError[];
  rule_names: string[];
  modified_externally: boolean;
  updated: string | null;
  /** A case rule that hides a library rule of the same name... */
  shadows: boolean;
  /** ...and the library rule that is hidden by it. */
  shadowed: boolean;
}

export interface YaraRule extends Omit<YaraRuleMeta, "shadows" | "shadowed"> {
  source: string;
}

export interface YaraRuleList {
  case_dir: string | null;
  /** Set when the case directory could not be read: the library rows still come back. */
  case_error?: string | null;
  rules: YaraRuleMeta[];
  count: number;
}

export interface YaraRulePutResult {
  stored: Omit<YaraRuleMeta, "shadows" | "shadowed">;
  check: YaraCheckResult;
}

export const checkYaraRule = (rule_source: string) =>
  request<YaraCheckResult>("/api/yara/check", {
    method: "POST",
    body: JSON.stringify({ rule_source }),
  });

export const isYaraTicket = (r: unknown): r is YaraJobTicket => hasKey(r, "task_id");

export const scanYara = (body: YaraScanRequest) =>
  postLossless<YaraScanResult | YaraJobTicket>("/api/yara/scan", body);

/** A finished job's `yara_result` payload (exact addresses), or `null`. */
export const getYaraJobPayload = (taskId: string) => getTaskPayload<YaraScanResult>(taskId);

export const cancelYaraJob = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean }>(
    `/api/tasks/${encodeURIComponent(taskId)}`, { method: "DELETE" });

const withCase = (caseDir?: string) =>
  caseDir && caseDir.trim() ? `case_dir=${encodeURIComponent(caseDir.trim())}` : "";

const query = (...parts: string[]) => {
  const joined = parts.filter(Boolean).join("&");
  return joined ? `?${joined}` : "";
};

export const listYaraRules = (caseDir?: string) =>
  request<YaraRuleList>(`/api/yara/rules${query(withCase(caseDir))}`);

/** One stored rule; a case rule wins over a library rule of the same name. */
export const getYaraRule = (name: string, caseDir?: string) =>
  request<YaraRule>(`/api/yara/rules/${encodeURIComponent(name)}${query(withCase(caseDir))}`);

export const putYaraRule = (name: string, rule_source: string, scope: RuleScope, caseDir?: string) =>
  request<YaraRulePutResult>(`/api/yara/rules/${encodeURIComponent(name)}`, {
    method: "PUT",
    body: JSON.stringify({ rule_source, scope, ...(scope === "case" ? { case_dir: caseDir } : {}) }),
  });

export const deleteYaraRule = (name: string, scope: RuleScope, caseDir?: string) =>
  request<{ name: string; deleted: boolean; scope: RuleScope }>(
    `/api/yara/rules/${encodeURIComponent(name)}${query(
      `scope=${scope}`, scope === "case" ? withCase(caseDir) : "")}`,
    { method: "DELETE" });
