import type {
  ScanRequest,
  AnalyzeRequest,
  AnalyzeFileRequest,
  ProtocolDescriptor,
  PhaseInfo,
  AnalysisRunResponse,
  HexData,
  EntropyData,
  SessionInfo,
  SessionSnapshot,
  TaskRecord,
  PathInfo,
  BrowseResult,
  StructureMatchResult,
  StructureApplyResult,
  StringsResponse,
  ConvergenceSweepResult,
  VerifyKeyResult,
  AutoExportResult,
  ExportKeylogRequest,
  ExportKeylogResult,
  FormatSuggestion,
  TagStatus,
  PageStatesResponse,
  SessionInfoResponse,
  VasRegionsResponse,
  DatasetRunsResponse,
  KeyMaterial,
} from "./types";

const BASE = ""; // relative -- Vite proxy handles /api/* during dev

/** Append the non-empty key-material fields to a query string, if present. */
function appendKey(qs: URLSearchParams, key?: KeyMaterial) {
  if (key?.passphrase) qs.set("passphrase", key.passphrase);
  if (key?.key_hex) qs.set("key_hex", key.key_hex);
  if (key?.kem_key_hex) qs.set("kem_key_hex", key.kem_key_hex);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * A sentence a human can read, out of whatever a `request` call rejected with.
 *
 * `request` throws `ApiError` carrying the RAW response body, so an error
 * surfaced verbatim reads
 * `{"error":"anchor offset does not name an addressable byte","category":...}`.
 * Unwrapping the envelope's own message is the difference between a note the
 * analyst can act on and a JSON blob in the middle of the UI.
 *
 * Lives beside `ApiError` because that is the shape it decodes; every store
 * that surfaces a failed request should import THIS one rather than keep a
 * private copy that silently reverts to the raw body.
 */
export function readableFailure(err: unknown): string {
  const raw = (err instanceof Error ? err.message : String(err)).trim();
  if (!raw.startsWith("{")) return raw;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      const envelope = parsed as { error?: unknown; detail?: unknown; message?: unknown };
      for (const field of [envelope.error, envelope.detail, envelope.message]) {
        if (typeof field === "string" && field.trim() !== "") return field.trim();
      }
    }
  } catch {
    // Not JSON after all -- the raw text is the best we have.
  }
  return raw;
}

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const { headers: callerHeaders, ...restInit } = init ?? {};
  const res = await fetch(`${BASE}${url}`, {
    ...restInit,
    headers: { "Content-Type": "application/json", ...callerHeaders },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body);
  }
  // Read as text first so an empty (e.g. 204 No Content) or malformed body
  // surfaces as an ApiError instead of a bare SyntaxError from res.json(),
  // keeping `instanceof ApiError` handling consistent for all callers.
  const text = await res.text();
  if (text === "") {
    return undefined as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(res.status, `Malformed JSON response: ${text.slice(0, 200)}`);
  }
}

// Dataset
export const scanDataset = (body: ScanRequest) =>
  request<Record<string, unknown>>("/api/dataset/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const listProtocols = () =>
  request<{ protocols: ProtocolDescriptor[] }>("/api/dataset/protocols");

/** Enumerate run directories (with their dumps) under a dataset/library dir. */
export const listDatasetRuns = (
  root: string,
  limit?: number,
  offset?: number,
) => {
  let query = `/api/dataset/runs?root=${encodeURIComponent(root)}`;
  if (limit !== undefined) query += `&limit=${limit}`;
  if (offset !== undefined) query += `&offset=${offset}`;
  return request<DatasetRunsResponse>(query);
};

export const listPhases = (libraryDir: string) =>
  request<PhaseInfo>(
    `/api/dataset/phases?library_dir=${encodeURIComponent(libraryDir)}`,
  );

// Analysis
//
// Both endpoints now dispatch the GIL-bound algorithm work onto the
// TaskManager's ProcessPool and return a ``task_id`` immediately (the
// same async pattern as the pipeline + batch endpoints). Callers
// subscribe to ``/ws/tasks/{task_id}`` for progress and fetch the full
// ``AnalysisResult`` from the ``analysis_result`` artifact on
// completion — see ``@/api/analysis`` for the higher-level helpers.
export const runAnalysis = (body: AnalyzeRequest) =>
  request<AnalysisRunResponse>("/api/analysis/run", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const runFileAnalysis = (body: AnalyzeFileRequest & KeyMaterial) =>
  request<AnalysisRunResponse>("/api/analysis/run-file", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Inspect
export const readHex = (
  dumpPath: string,
  offset = 0,
  length = 256,
  key?: KeyMaterial,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
  });
  appendKey(qs, key);
  return request<HexData>(`/api/inspect/hex?${qs.toString()}`);
};

/**
 * How many sliding-window positions the entropy profile may be computed at.
 *
 * `length = 0` means "the whole file", and on the 220 MB corpus dump that is
 * ~13.75 million window positions computed in order to plot 200 of them — which
 * the entropy tab used to ask for on mount, with no user action, stalling the
 * single-process backend for the duration. The server enforces its own ceiling;
 * sending one anyway keeps the cost of this call stated where the call is made,
 * so it cannot quietly become unbounded again if that default ever moves.
 */
export const ENTROPY_MAX_PROFILE_POSITIONS = 1 << 18;

export const getEntropy = (
  dumpPath: string,
  offset = 0,
  length = 0,
  key?: KeyMaterial,
  maxPositions = ENTROPY_MAX_PROFILE_POSITIONS,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
    max_positions: String(maxPositions),
  });
  appendKey(qs, key);
  return request<EntropyData>(`/api/inspect/entropy?${qs.toString()}`);
};

export interface StringsOpts {
  minLength?: number;
  encoding?: string;
  maxResults?: number;
  cursor?: number;
  chunkSize?: number;
  key?: KeyMaterial;
}

export const extractStrings = (
  dumpPath: string,
  opts: StringsOpts = {},
): Promise<StringsResponse> => {
  const qs = new URLSearchParams({ dump_path: dumpPath });
  const { minLength, encoding, maxResults, cursor, chunkSize, key } = opts;
  if (minLength !== undefined) qs.set("min_length", String(minLength));
  if (encoding !== undefined) qs.set("encoding", encoding);
  if (maxResults !== undefined) qs.set("max_results", String(maxResults));
  if (cursor !== undefined) qs.set("cursor", String(cursor));
  if (chunkSize !== undefined) qs.set("chunk_size", String(chunkSize));
  appendKey(qs, key);
  return request<StringsResponse>(`/api/inspect/strings?${qs.toString()}`);
};

// Sessions
export const listSessions = () =>
  request<{ sessions: SessionInfo[] }>("/api/sessions/");

export const saveSession = (payload: Partial<SessionSnapshot>) =>
  request<{ path: string; name: string; status: string }>("/api/sessions/", {
    method: "POST",
    body: JSON.stringify(payload),
  });

export const loadSession = (name: string) =>
  request<SessionSnapshot>(`/api/sessions/${encodeURIComponent(name)}`);

export const deleteSession = (name: string) =>
  request<{ deleted: string; status: string }>(
    `/api/sessions/${encodeURIComponent(name)}`,
    { method: "DELETE" },
  );

// Tasks
// NOTE: currently unused (zero callers). GET /api/tasks/{id} returns the full
// TaskRecord (record.to_dict() from api/services/task_manager.py), not a bare
// status enum. Kept for parity with the tasks endpoint.
export const getTask = (taskId: string) =>
  request<TaskRecord>(`/api/tasks/${taskId}`);

// Path info
export const getPathInfo = (path: string) =>
  request<PathInfo>(
    `/api/path/info?path=${encodeURIComponent(path)}`,
  );

// File browser
export const browsePath = (path?: string) =>
  request<BrowseResult>(
    path ? `/api/path/browse?path=${encodeURIComponent(path)}` : "/api/path/browse",
  );

// MSL inspection
export const listBlocks = (mslPath: string) =>
  request<Array<{ category: string; blocks: Array<{ label: string; block_type: number; offset: number; size: number; detail: string }> }>>(
    `/api/inspect/blocks?msl_path=${encodeURIComponent(mslPath)}`,
  );

export const listModules = (mslPath: string) =>
  request<Array<{ path: string; base_addr: number; size: number; version: string }>>(
    `/api/inspect/modules?msl_path=${encodeURIComponent(mslPath)}`,
  );

// The keyed /api/inspect/* endpoints differ only by path segment + response
// type, so they share one helper (msl_path + optional key material as query).
const getKeyedInspect = <T>(endpoint: string, mslPath: string, key?: KeyMaterial) => {
  const qs = new URLSearchParams({ msl_path: mslPath });
  appendKey(qs, key);
  return request<T>(`/api/inspect/${endpoint}?${qs.toString()}`);
};

export const getPageStates = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<PageStatesResponse>("page-states", mslPath, key);

export const getSessionInfo = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<SessionInfoResponse>("session-info", mslPath, key);

export const getVasRegions = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<VasRegionsResponse>("vas", mslPath, key);

export const getTagStatus = (mslPath: string) =>
  request<{ tag_status: TagStatus }>(
    `/api/inspect/tag-status?msl_path=${encodeURIComponent(mslPath)}`,
  );

export const probeTagStatusWithKey = (
  mslPath: string,
  secret: { passphrase?: string; key_hex?: string; kem_key_hex?: string },
) =>
  request<{ tag_status: TagStatus }>("/api/inspect/tag-status", {
    method: "POST",
    body: JSON.stringify({ msl_path: mslPath, ...secret }),
  });

// Structure inspection
export const autoDetectStructure = (dumpPath: string, offset: number, protocol?: string) =>
  request<StructureMatchResult>(
    `/api/inspect/structure?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}${protocol ? `&protocol=${encodeURIComponent(protocol)}` : ""}`,
  );

// Analysis patterns
export const listPatterns = () =>
  request<{ patterns: import("./types").PatternInfo[] }>("/api/analysis/patterns");

export const applyStructure = (
  dumpPath: string,
  offset: number,
  structureName: string,
  key?: KeyMaterial,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    structure_name: structureName,
  });
  appendKey(qs, key);
  return request<StructureApplyResult>(`/api/inspect/structure-apply?${qs.toString()}`);
};

// Format detection
export interface FormatResult {
  format: string | null;
  detected_format?: string | null;
  forced?: boolean;
  suggested_formats?: FormatSuggestion[];
  available_formats?: string[];
  nav_tree: Record<string, unknown> | null;
  overlays: { structure_name: string; base_offset: number; fields: Array<{ field_name: string; offset: number; length: number; display: string; description: string; path: string; valid: boolean }> } | null;
}

export const detectFormat = (
  dumpPath: string,
  offset = 0,
  forceFormat?: string,
  key?: KeyMaterial,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
  });
  if (forceFormat) qs.set("force_format", forceFormat);
  appendKey(qs, key);
  return request<FormatResult>(`/api/inspect/format?${qs.toString()}`);
};

// Architect
export interface CheckStaticResult { static_mask: boolean[]; reference_hex: string; static_ratio: number; anchors: Array<{ start: number; length: number }> }
export interface PatternGenResult { name: string; length: number; hex_pattern: string; wildcard_pattern: string; static_ratio: number; static_count: number; volatile_count: number }
export interface ExportResult { format: string; content: string }

export const checkStatic = (body: { dump_paths: string[]; offset: number; length: number } & KeyMaterial) =>
  request<CheckStaticResult>("/api/architect/check-static", { method: "POST", body: JSON.stringify(body) });

export const generatePattern = (body: { reference_hex: string; static_mask: boolean[]; name?: string }) =>
  request<PatternGenResult>("/api/architect/generate-pattern", { method: "POST", body: JSON.stringify(body) });

export const exportPattern = (body: { pattern: Record<string, unknown>; format: string }) =>
  request<ExportResult>("/api/architect/export", { method: "POST", body: JSON.stringify(body) });

// File uploads (multipart — bypass JSON Content-Type)
export async function uploadFile<T>(url: string, file: File): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}${url}`, { method: "POST", body: form });
  if (!res.ok) {
    // FastAPI serializes errors as {"detail": "..."}; surface that human
    // message rather than the raw JSON envelope. A non-JSON body (e.g. a proxy
    // error page) is kept verbatim.
    const body = await res.text();
    let msg = body;
    try {
      msg = (JSON.parse(body) as { detail?: string }).detail ?? body;
    } catch {
      // Non-JSON body — keep it verbatim.
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

export const importKsy = (file: File) =>
  uploadFile<{ name: string; filename: string; message: string }>("/api/structures/import-ksy", file);

// Notebook
export const getNotebookStatus = () =>
  request<{ available: boolean; error: string | null }>("/api/notebook/status");

// Convergence
export const runConvergence = (body: {
  dump_paths: string[];
  n_values?: number[];
  normalize?: boolean;
  max_fp?: number;
} & KeyMaterial) =>
  request<ConvergenceSweepResult>("/api/analysis/convergence", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Key verification
export const verifyKey = (body: {
  dump_path: string;
  offset: number;
  length?: number;
  ciphertext_hex: string;
  iv_hex?: string;
  nonce_hex?: string;
  aad_hex?: string;
  tag_hex?: string;
  cipher?: string;
} & KeyMaterial) =>
  request<VerifyKeyResult>("/api/analysis/verify-key", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Auto export
export const autoExport = (body: {
  dump_paths: string[];
  format?: string;
  name?: string;
  align?: boolean;
  context?: number;
} & KeyMaterial) =>
  request<AutoExportResult>("/api/analysis/auto-export", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Keylog export -- render recovered TLS secrets as a Wireshark NSS key log
export const exportKeylog = (body: ExportKeylogRequest) =>
  request<ExportKeylogResult>("/api/analysis/export-keylog", {
    method: "POST",
    body: JSON.stringify(body),
  });
