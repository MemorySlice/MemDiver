/**
 * Typed client for the analysis-record routes (`api/routers/annotations.py`):
 * list / add / retract entries of a capture. Only what the table-rule editor
 * needs; `case_dir` is required and WRITES must live under the upload dir or
 * `~/.memdiver`.
 */
import { request } from "./client";

export interface RecordEntry {
  id: string;
  kind: string;
  capture_id?: string | null;
  label?: string;
  locations: unknown[];
  payload?: Record<string, unknown> | null;
  [extra: string]: unknown;
}

export const listAnnotations = (caseDir: string, captureId: string, kind?: string) => {
  const q = new URLSearchParams({ case_dir: caseDir, capture_id: captureId });
  if (kind) q.set("kind", kind);
  return request<{ entries: RecordEntry[]; count: number }>(`/api/annotations?${q}`);
};

export const addAnnotation = (body: {
  case_dir: string; capture_id: string; kind: string; label?: string;
  payload?: Record<string, unknown>; locations?: unknown[];
}) => request<Record<string, unknown>>("/api/annotations/add", {
  method: "POST", body: JSON.stringify(body),
});

export const retractAnnotation = (body: {
  case_dir: string; capture_id: string; entry_id: string; reason?: string;
}) => request<Record<string, unknown>>("/api/annotations/retract", {
  method: "POST", body: JSON.stringify(body),
});

/** One `isf_try` entry of the analysis record (payload written by the try producer). */
export interface IsfTryEntry extends RecordEntry {
  created?: string;
  payload: {
    draft?: string | null;
    version?: string | null;
    state_id?: string | null;
    plugin?: string;
    verdict?: string;
    implicated?: { item: string; reason?: string }[];
    comparison?: Record<string, unknown> | null;
    error?: string | null;
  } | null;
}

/** Past tries of a capture, from `GET /api/annotations?kind=isf_try`. */
export const listIsfTries = (caseDir: string, captureId: string) =>
  listAnnotations(caseDir, captureId, "isf_try") as Promise<{ entries: IsfTryEntry[]; count: number }>;
