/**
 * Typed client for the ISF workbench routes (`api/routers/isf.py`):
 *
 *   GET  /api/isf/drafts                       — a capture's drafts
 *   POST /api/isf/drafts                       — create a draft
 *   GET  /api/isf/drafts/{name}[/versions]     — materialized draft / operation history
 *   POST /api/isf/drafts/{name}/{set,retract,diff,validate,export}
 *   POST /api/isf/probe | /api/isf/try         — INLINE, or with `async: true` an image JOB
 *                                                `{task_id, status}` (progress over the task
 *                                                WebSocket, payload as the `done` event's `extra`)
 *
 * Symbol addresses arrive as hex strings (a kernel VA exceeds 2^53) and are SENT as hex
 * strings for the same reason.
 */

import type { ImageJobTicket } from "./image";
import { getTaskPayload, postLossless as post, requestLossless as request, type WireInt } from "./lossless-json";

export type IsfSection = "symbols" | "user_types" | "base_types" | "enums";
export const ISF_SECTIONS: readonly IsfSection[] = ["symbols", "user_types", "base_types", "enums"];

export const ISF_TIERS = [
  "exact", "ordinal", "population", "code", "crc_certified", "upstream_constant", "bound",
  "imported", "probe", "manual",
] as const;
export type IsfTier = (typeof ISF_TIERS)[number];

export interface IsfProvenance {
  source: string;
  tier: string;
  evidence: string[];
  author: string;
  witnesses?: number;
}

export interface IsfOrigin {
  entry_id: string;
  op: string;
  created?: string;
  provenance: IsfProvenance;
  /** Field rows only: the offset is an untyped placeholder, not exported. */
  untyped?: boolean;
}

/** An ISF type descriptor (`base` / `pointer` / `array` / `struct` ...). */
export interface TypeDescriptor {
  kind: string;
  name?: string;
  count?: number;
  subtype?: TypeDescriptor;
}

export interface IsfField { offset: number; type: TypeDescriptor }
export interface IsfStruct {
  kind?: string;
  size: number;
  fields?: Record<string, IsfField>;
  /** Count of untyped placeholder offsets (not exported). */
  untyped_fields?: number;
}
export interface IsfSymbol { address: string; type?: TypeDescriptor }
export interface IsfBaseType { size: number; signed: boolean; kind: string; endian: string }
export interface IsfEnum { size: number; base: string; constants: Record<string, number> }
export type IsfItem = IsfSymbol | IsfStruct | IsfBaseType | IsfEnum;

export interface DraftSummaryRow {
  name: string;
  arch: string;
  created: string;
  version: string | null;
  applied: number;
  counts: Record<IsfSection, number>;
}
export interface DraftList { capture_id: string; drafts: DraftSummaryRow[]; count: number }

export interface DraftSection {
  items: Record<string, IsfItem>;
  /** Matches before paging. */
  total: number;
  offset: number;
  limit: number;
  /** More matches beyond this page. */
  truncated: boolean;
  missing: string[];
  origins?: Record<string, IsfOrigin | null>;
  /** user_types only: `"struct.field"` -> provenance row. */
  field_origins?: Record<string, IsfOrigin | null>;
}
export interface DraftMaterialized {
  name: string;
  capture_id: string;
  version: string | null;
  applied: number;
  metadata: Record<string, unknown>;
  counts: Record<IsfSection, number>;
  size_bounds: Record<string, unknown>;
  sections?: Partial<Record<IsfSection, DraftSection>>;
  truncated?: boolean;
}

export interface DraftVersion {
  entry_id: string;
  created: string;
  op: string;
  key: string[] | null;
  provenance: IsfProvenance;
  retracted: boolean;
}
export interface DraftVersions { draft: string; versions: DraftVersion[]; total: number; truncated: boolean }

export interface DiffItem { key: string[]; change: "added" | "removed" | "changed"; before: unknown; after: unknown }
export interface DraftDiff {
  draft: string;
  against: string;
  equal: boolean;
  counts: Record<"added" | "removed" | "changed", number>;
  total: number;
  truncated: boolean;
  items: DiffItem[];
}

export interface PluginReadiness {
  plugin: string;
  verdict: string;
  required_missing: unknown[];
  optional_missing: number;
  indeterminate: number;
  upstream_defects: number;
  reason: string | null;
}
export interface ValidateResult {
  draft: string;
  version: string | null;
  is_valid: boolean;
  error_count: number;
  warning_count: number;
  errors: unknown[];
  warnings: unknown[];
  truncated: boolean;
  plugins: PluginReadiness[];
  verdicts: Record<string, number>;
}

export type TryVerdict = "pass" | "partial" | "fail" | "unverified" | "error";
export interface TryMismatch { [column: string]: unknown }
export interface TryComparison {
  expected: number;
  returned: number;
  matched: number;
  recall: number;
  precision: number;
  missing: number[];
  extra: number[];
  duplicates: number[];
  mismatches: TryMismatch[];
  mismatch_count: number;
  truncated: boolean;
}
export interface TryImplicated { item: string; reason?: string }
export interface TryResult {
  plugin: string;
  verdict: TryVerdict;
  stage: string;
  draft?: string | null;
  version?: string | null;
  comparison?: TryComparison;
  implicated: TryImplicated[];
  error?: string;
  sample?: Record<string, unknown>[];
  elapsed_s?: Record<string, number>;
  record_entry?: string;
}

/** A coordinate read losslessly: `value` is a decimal STRING once it exceeds 2^53. */
export interface WireLocation { space: string; value: WireInt; capture_id: string }
export interface ProbeRow { location?: WireLocation; [key: string]: unknown }
export interface ProbeResult {
  probe: string;
  arch: string;
  capture_id: string;
  rows: ProbeRow[];
  counts: Record<string, number>;
  truncated: boolean;
  limit: number;
  timings: Record<string, number>;
  warnings: string[];
  imported?: Record<string, unknown>;
}

export const PROBES = [
  "viability", "banner", "vmcoreinfo", "kallsyms", "btf", "init_task", "page_table_root",
  "utsname", "ksymtab", "layout_legs",
] as const;
/** The probes whose finding a draft can import. */
export const FEEDABLE_PROBES: readonly string[] = ["kallsyms", "vmcoreinfo", "btf", "layout_legs"];

export interface DraftRef { caseDir: string; captureId: string }

const refBody = (ref: DraftRef) => ({ case_dir: ref.caseDir, capture_id: ref.captureId });
const draftUrl = (name: string, tail = "") => `/api/isf/drafts/${encodeURIComponent(name)}${tail}`;
const query = (ref: DraftRef, extra: Record<string, string | number | boolean | undefined> = {}) => {
  const qs = new URLSearchParams({ case_dir: ref.caseDir, capture_id: ref.captureId });
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) qs.set(k, String(v));
  return qs.toString();
};

export const listIsfDrafts = (ref: DraftRef) =>
  request<DraftList>(`/api/isf/drafts?${query(ref)}`);

export const createIsfDraft = (ref: DraftRef, name: string, arch: string, author = "human") =>
  post<{ draft: string; capture_id: string }>("/api/isf/drafts", { ...refBody(ref), name, arch, author });

export interface GetDraftOptions {
  /** `{section: [names]}`; an empty list selects the whole section (cut at `limit`). */
  only?: Partial<Record<IsfSection, string[]>>;
  version?: string;
  includeOrigins?: boolean;
  limit?: number;
  /** Case-insensitive substring over item names (server-side). */
  search?: string;
  offset?: number;
}
export const getIsfDraft = (ref: DraftRef, name: string, opts: GetDraftOptions = {}) =>
  request<DraftMaterialized>(draftUrl(name, `?${query(ref, {
    version: opts.version,
    only: opts.only ? JSON.stringify(opts.only) : undefined,
    include_origins: opts.includeOrigins,
    limit: opts.limit,
    search: opts.search || undefined,
    offset: opts.offset,
  })}`));

export const getIsfDraftVersions = (ref: DraftRef, name: string, limit?: number) =>
  request<DraftVersions>(draftUrl(name, `/versions?${query(ref, { limit })}`));

export interface SetOpRequest {
  op: "symbol" | "struct" | "field" | "base_type" | "enum" | "remove";
  args: Record<string, unknown>;
  provenance: { source: string; tier: string; evidence: string[]; author: string };
}
export const setIsfDraft = (ref: DraftRef, name: string, req: SetOpRequest) =>
  post<{ draft: string; op: string; entry: { entry_id: string } }>(draftUrl(name, "/set"), {
    ...refBody(ref), op: req.op, args: req.args, ...req.provenance,
  });

export const retractIsfEntry = (ref: DraftRef, name: string, entryId: string, reason = "") =>
  post<{ draft: string }>(draftUrl(name, "/retract"), {
    ...refBody(ref), entry_id: entryId, author: "human", reason,
  });

export const diffIsfDraft = (
  ref: DraftRef, name: string, against: { version: string } | { isf: string }, limit?: number,
) => post<DraftDiff>(draftUrl(name, "/diff"), {
  ...refBody(ref),
  ...("version" in against ? { against_version: against.version } : { against_isf: against.isf }),
  ...(limit !== undefined ? { limit } : {}),
});

export const validateIsfDraft = (ref: DraftRef, name: string, checkSchema = false) =>
  post<ValidateResult>(draftUrl(name, "/validate"), { ...refBody(ref), check_schema: checkSchema });

export interface TryArgs {
  imagePath: string;
  caseDir: string;
  draft: string;
  version?: string;
  plugin: string;
  groundTruth?: string;
}
const tryBody = (a: TryArgs, async_: boolean) => ({
  image_path: a.imagePath, case_dir: a.caseDir, draft: a.draft, plugin: a.plugin,
  ...(a.version ? { version: a.version } : {}),
  ...(a.groundTruth ? { ground_truth: a.groundTruth } : {}),
  async: async_,
});
/** Submit a try as an image JOB; the verdict arrives as the `done` event's payload. */
export const startIsfTryJob = (a: TryArgs) => post<ImageJobTicket>("/api/isf/try", tryBody(a, true));

export interface ProbeArgs {
  imagePath: string;
  probe: string;
  arch: string;
  caseDir?: string;
  draft?: string;
}
/** Submit a probe as an image JOB (kallsyms on a multi-GB image can take over a minute). */
export const startIsfProbeJob = (a: ProbeArgs) =>
  post<ImageJobTicket>("/api/isf/probe", {
    image_path: a.imagePath, probe: a.probe, arch: a.arch, async: true,
    ...(a.caseDir && a.draft ? { case_dir: a.caseDir, draft: a.draft } : {}),
  });

/**
 * The stored payload of a finished isf job, decoded losslessly (a kernel VA past 2^53 stays an
 * exact decimal string). `null` when the task has no payload.
 */
export const getIsfJobPayload = <T>(taskId: string) => getTaskPayload<T>(taskId);
