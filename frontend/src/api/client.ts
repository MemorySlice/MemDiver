import type {
  ScanRequest,
  AnalyzeRequest,
  AnalyzeFileRequest,
  ProtocolDescriptor,
  PhaseInfo,
  AnalysisResult,
  HexData,
  EntropyData,
  SessionInfo,
  SessionSnapshot,
  TaskStatus,
  PathInfo,
  BrowseResult,
  StructureMatchResult,
  StructureApplyResult,
  StringsResponse,
  ConvergenceSweepResult,
  VerifyKeyResult,
  AutoExportResult,
} from "./types";

const BASE = ""; // relative -- Vite proxy handles /api/* during dev

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
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
export const runAnalysis = (body: AnalyzeRequest) =>
  request<AnalysisResult>("/api/analysis/run", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const runFileAnalysis = (body: AnalyzeFileRequest) =>
  request<AnalysisResult>("/api/analysis/run-file", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Inspect
export const readHex = (dumpPath: string, offset = 0, length = 256) =>
  request<HexData>(
    `/api/inspect/hex?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}&length=${length}`,
  );

export const getEntropy = (dumpPath: string, offset = 0, length = 0) =>
  request<EntropyData>(
    `/api/inspect/entropy?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}&length=${length}`,
  );

export const extractStrings = (
  dumpPath: string,
  minLength = 4,
  encoding = "ascii",
  maxResults = 500,
) =>
  request<StringsResponse>(
    `/api/inspect/strings?dump_path=${encodeURIComponent(dumpPath)}&min_length=${minLength}&encoding=${encoding}&max_results=${maxResults}`,
  );

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
export const getTask = (taskId: string) =>
  request<TaskStatus>(`/api/tasks/${taskId}`);

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

// Structure inspection
export const autoDetectStructure = (dumpPath: string, offset: number, protocol?: string) =>
  request<StructureMatchResult>(
    `/api/inspect/structure?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}${protocol ? `&protocol=${encodeURIComponent(protocol)}` : ""}`,
  );

// Analysis patterns
export const listPatterns = () =>
  request<{ patterns: import("./types").PatternInfo[] }>("/api/analysis/patterns");

export const applyStructure = (dumpPath: string, offset: number, structureName: string) =>
  request<StructureApplyResult>(
    `/api/inspect/structure-apply?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}&structure_name=${encodeURIComponent(structureName)}`,
  );

// Format detection
export interface FormatResult {
  format: string | null;
  nav_tree: Record<string, unknown> | null;
  overlays: { structure_name: string; base_offset: number; fields: Array<{ field_name: string; offset: number; length: number; display: string; description: string; path: string; valid: boolean }> } | null;
}

export const detectFormat = (dumpPath: string, offset = 0) =>
  request<FormatResult>(
    `/api/inspect/format?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}`,
  );

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
}) =>
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
}) =>
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
}) =>
  request<AutoExportResult>("/api/analysis/auto-export", {
    method: "POST",
    body: JSON.stringify(body),
  });
