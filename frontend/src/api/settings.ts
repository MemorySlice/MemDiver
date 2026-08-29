/**
 * Typed client for the server-side settings endpoints (``/api/settings``).
 *
 * Mirrors the Pydantic models in ``api/routers/settings.py``.
 *
 * Why a dedicated module rather than another block in ``client.ts``: the upload
 * directory is *server* state (it lives in the user config file, or is pinned
 * by ``MEMDIVER_UPLOAD_DIR``), which makes it the opposite of everything in
 * ``stores/settings-store.ts`` -- that store is 100% localStorage. Keeping the
 * two apart is what stops the browser and the backend from silently diverging
 * on where uploads actually land.
 */

import { ApiError, request } from "./client";

/**
 * The legacy (pre-configuration) upload directory, when one still holds files
 * worth moving. The backend omits the whole key unless a migration is
 * offerable, so every consumer must treat it as optional.
 */
export interface UploadDirLegacy {
  path: string;
  file_count: number;
  total_bytes: number;
  owned_by_us: boolean;
}

/** Where uploads go, and who decided that. */
export interface UploadDirStatus {
  configured: boolean;
  /** Absolute path, or ``null`` while unconfigured. */
  path: string | null;
  source: "env" | "user_config" | null;
  /**
   * True when ``MEMDIVER_UPLOAD_DIR`` is set. The directory is then read-only
   * from the UI's point of view -- a POST would be rejected with 409.
   */
  env_pinned: boolean;
  quota_bytes: number;
  legacy?: UploadDirLegacy;
}

/** The result of configuring the directory, including the migration tally. */
export interface SetUploadDirResult {
  configured: boolean;
  path: string;
  source: "env" | "user_config" | null;
  migrated: number;
  skipped: number;
}

/**
 * ``request`` rethrows the raw response body, which for FastAPI is the
 * ``{"detail": "..."}`` envelope. The 400 reason and the 409 pin message are
 * both meant to be shown to the user verbatim, so unwrap them here -- the same
 * unwrap ``client.uploadFile`` does for multipart failures. Non-JSON bodies
 * (a proxy error page, say) are kept as-is.
 */
function unwrapDetail(error: unknown): unknown {
  if (!(error instanceof ApiError)) return error;
  try {
    const detail = (JSON.parse(error.message) as { detail?: unknown }).detail;
    if (typeof detail === "string") return new ApiError(error.status, detail);
  } catch {
    // Non-JSON body -- keep it verbatim.
  }
  return error;
}

async function withUnwrappedDetail<T>(call: Promise<T>): Promise<T> {
  try {
    return await call;
  } catch (e) {
    throw unwrapDetail(e);
  }
}

/** Read the current upload-directory status. Always 200 on a live backend. */
export const getUploadDir = (): Promise<UploadDirStatus> =>
  withUnwrappedDetail(request<UploadDirStatus>("/api/settings/upload-dir"));

/**
 * Configure the upload directory.
 *
 * Rejects with an ``ApiError`` carrying the human reason: 400 for a path the
 * backend will not accept, 409 when ``MEMDIVER_UPLOAD_DIR`` pins it.
 */
export const setUploadDir = (
  path: string,
  migrateLegacy = false,
): Promise<SetUploadDirResult> =>
  withUnwrappedDetail(
    request<SetUploadDirResult>("/api/settings/upload-dir", {
      method: "POST",
      body: JSON.stringify({ path, migrate_legacy: migrateLegacy }),
    }),
  );
