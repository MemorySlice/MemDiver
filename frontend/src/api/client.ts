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
  FormatSuggestion,
  TagStatus,
  PageStatesResponse,
  SessionInfoResponse,
  VasRegionsResponse,
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
  return res.json() as Promise<T>;
}

// Dataset
export const scanDataset = (body: ScanRequest) =>
  request<Record<string, unknown>>("/api/dataset/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const listProtocols = () =>
  request<{ protocols: ProtocolDescriptor[] }>("/api/dataset/protocols");

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

export const getEntropy = (
  dumpPath: string,
  offset = 0,
  length = 0,
  key?: KeyMaterial,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
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

export const getPageStates = (mslPath: string, key?: KeyMaterial) => {
  const qs = new URLSearchParams({ msl_path: mslPath });
  appendKey(qs, key);
  return request<PageStatesResponse>(`/api/inspect/page-states?${qs.toString()}`);
};

export const getSessionInfo = (mslPath: string, key?: KeyMaterial) => {
  const qs = new URLSearchParams({ msl_path: mslPath });
  appendKey(qs, key);
  return request<SessionInfoResponse>(`/api/inspect/session-info?${qs.toString()}`);
};

export const getVasRegions = (mslPath: string, key?: KeyMaterial) => {
  const qs = new URLSearchParams({ msl_path: mslPath });
  appendKey(qs, key);
  return request<VasRegionsResponse>(`/api/inspect/vas?${qs.toString()}`);
};

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

export const checkStatic = (body: { dump_paths: string[]; offset: number; length: number }) =>
  request<CheckStaticResult>("/api/architect/check-static", { method: "POST", body: JSON.stringify(body) });

export const generatePattern = (body: { reference_hex: string; static_mask: boolean[]; name?: string }) =>
  request<PatternGenResult>("/api/architect/generate-pattern", { method: "POST", body: JSON.stringify(body) });

export const exportPattern = (body: { pattern: Record<string, unknown>; format: string }) =>
  request<ExportResult>("/api/architect/export", { method: "POST", body: JSON.stringify(body) });

// File uploads (multipart — bypass JSON Content-Type)
async function uploadFile<T>(url: string, file: File): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}${url}`, { method: "POST", body: form });
  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body);
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
