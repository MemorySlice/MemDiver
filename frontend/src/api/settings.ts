/**
 * Typed client for the server-side settings endpoints (``/api/settings``).
 *
 * Mirrors the Pydantic models in ``api/routers/settings.py``.
 *
 * Why a dedicated module rather than another block in ``client.ts``: everything
 * here is *server* state -- it lives in the user config file
 * (``memdiver_home()/config.json``) rather than in the browser, which makes it
 * the opposite of everything in ``stores/settings-store.ts``, a store that is
 * 100% localStorage. Keeping the two apart is what stops the browser and the
 * backend from silently diverging.
 *
 * That distinction is exactly why the file browser's FAVOURITES live here too.
 * They were localStorage once, and localStorage is keyed by origin: running
 * ``memdiver web`` on a different ``--port``, clearing site data, or opening
 * the UI in a second browser each produced a silently empty list.
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

/**
 * A directory the user saved in the file browser.
 *
 * ``path`` is the identity -- the backend upserts on it, so saving the same
 * directory twice relabels the one entry rather than making a second.
 */
export interface FavouriteDir {
  path: string;
  label: string;
  /** Unix seconds. Set once, on first save; a relabel does not move it. */
  added_at: number;
}

interface FavouritesResponse {
  favourites: FavouriteDir[];
}

interface LastDirResponse {
  path: string | null;
}

/** Read the saved favourite directories. */
export const getFavourites = (): Promise<FavouriteDir[]> =>
  withUnwrappedDetail(
    request<FavouritesResponse>("/api/settings/favourites").then((r) => r.favourites),
  );

/**
 * Save a directory as a favourite, or relabel one already saved.
 *
 * Resolves with the WHOLE list as the server now holds it, not just the entry
 * touched -- the caller adopts that rather than merging, so two tabs cannot
 * drift into two different lists. Rejects with an ``ApiError`` carrying the
 * human reason when the path is not an existing directory.
 */
export const addFavourite = (path: string, label?: string): Promise<FavouriteDir[]> =>
  withUnwrappedDetail(
    request<FavouritesResponse>("/api/settings/favourites", {
      method: "POST",
      body: JSON.stringify({ path, label: label ?? null }),
    }).then((r) => r.favourites),
  );

/** Remove a favourite. Resolves with the whole remaining list. */
export const removeFavourite = (path: string): Promise<FavouriteDir[]> =>
  withUnwrappedDetail(
    request<FavouritesResponse>(
      `/api/settings/favourites?path=${encodeURIComponent(path)}`,
      { method: "DELETE" },
    ).then((r) => r.favourites),
  );

/** The directory the file browser should reopen on, if the server knows one. */
export const getLastDir = (): Promise<string | null> =>
  withUnwrappedDetail(
    request<LastDirResponse>("/api/settings/last-dir").then((r) => r.path),
  );

/** Remember where the file browser was last used. */
export const setLastDir = (path: string): Promise<string | null> =>
  withUnwrappedDetail(
    request<LastDirResponse>("/api/settings/last-dir", {
      method: "PUT",
      body: JSON.stringify({ path }),
    }).then((r) => r.path),
  );
