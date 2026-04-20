/**
 * Typed client for the BYO oracle registry endpoints.
 *
 * Mirrors the Pydantic + dataclass models in api/routers/oracles.py
 * and api/services/oracle_registry.py. Upload uses multipart/form-data
 * so it bypasses the shared JSON request() helper.
 */

import { ApiError, request } from "./client";

/** Bundled example oracle from docs/oracle_examples/ served read-only. */
export interface OracleExample {
  filename: string;
  path: string;
  sha256: string;
  size: number;
  shape: 1 | 2;
  summary: string;
  head_lines: string[];
}

/** Uploaded oracle tracked in the in-memory OracleRegistry. */
export interface OracleEntry {
  id: string;
  filename: string;
  sha256: string;
  size: number;
  shape: 1 | 2;
  head_lines: string[];
  uploaded_at: number;
  armed: boolean;
  description: string | null;
}

export interface DryRunResult {
  oracle_id: string;
  samples: number;
  passes: number;
  fails: number;
  errors: number;
  per_call_us_avg: number;
  results: Array<{
    index: number;
    ok: boolean;
    duration_us?: number;
    error?: string;
  }>;
}

// ---- endpoints ----

export const listOracleExamples = () =>
  request<{ examples: OracleExample[] }>("/api/oracles/examples");

export const listOracles = () =>
  request<{ oracles: OracleEntry[] }>("/api/oracles");

export async function uploadOracle(
  file: File,
  description?: string,
): Promise<OracleEntry> {
  const form = new FormData();
  form.append("file", file);
  if (description !== undefined) {
    form.append("description", description);
  }
  const res = await fetch("/api/oracles/upload", {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    throw new ApiError(res.status, await res.text());
  }
  return (await res.json()) as OracleEntry;
}

export const armOracle = (oracleId: string, sha256: string) =>
  request<OracleEntry>(
    `/api/oracles/${encodeURIComponent(oracleId)}/arm`,
    { method: "POST", body: JSON.stringify({ sha256 }) },
  );

/**
 * Dry-run the oracle against a list of sample bytes (base64-encoded).
 * The registry does NOT require the oracle to be armed first so the
 * user can smoke-test before committing.
 */
export const dryRunOracle = (oracleId: string, samplesB64: string[]) =>
  request<DryRunResult>(
    `/api/oracles/${encodeURIComponent(oracleId)}/dry-run`,
    { method: "POST", body: JSON.stringify({ samples_b64: samplesB64 }) },
  );

export const deleteOracle = (oracleId: string) =>
  request<{ oracle_id: string; deleted: boolean }>(
    `/api/oracles/${encodeURIComponent(oracleId)}`,
    { method: "DELETE" },
  );
