/**
 * Fetch hook for the server-side upload directory.
 *
 * There is no react-query in this repo, so this is plain
 * ``useState``/``useEffect``/``useCallback`` -- the same shape as
 * ``pipeline/oracle/use-pcap-arm.ts``.
 *
 * Deliberately NOT backed by ``stores/settings-store.ts``: that store is a
 * zustand ``persist`` store (localStorage only). Caching the upload directory
 * there would let the browser claim a path the backend never accepted.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "@/api/client";
import { getUploadDir, setUploadDir, type SetUploadDirResult, type UploadDirStatus } from "@/api/settings";

function errorMessage(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

export interface UseUploadDir {
  /** Latest server status, or ``null`` until the first fetch resolves. */
  status: UploadDirStatus | null;
  /** True while a fetch or a save is in flight. */
  loading: boolean;
  /** Human reason for the last failed fetch/save, cleared on the next attempt. */
  error: string | null;
  /** Re-read the status from the backend. */
  refresh: () => Promise<void>;
  /**
   * Configure the directory.
   *
   * Resolves with the server result on success and with ``null`` on failure,
   * leaving the reason in ``error`` -- callers render it inline and stay open
   * (a 400 must not close the prompt), so a rejection would only force every
   * call site into its own try/catch.
   */
  save: (path: string, migrateLegacy?: boolean) => Promise<SetUploadDirResult | null>;
}

export function useUploadDir(): UseUploadDir {
  const [status, setStatus] = useState<UploadDirStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Guards a setState after unmount, and lets a save's fresh status win over a
  // refresh that was already in flight.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const next = await getUploadDir();
      if (mountedRef.current) setStatus(next);
    } catch (e) {
      if (mountedRef.current) setError(errorMessage(e));
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  const save = useCallback(
    async (path: string, migrateLegacy = false): Promise<SetUploadDirResult | null> => {
      setLoading(true);
      setError(null);
      try {
        const result = await setUploadDir(path, migrateLegacy);
        if (mountedRef.current) {
          // Fold the result into the cached status so callers see the new path
          // without a second round trip.
          setStatus((prev) => ({
            configured: result.configured,
            path: result.path,
            source: result.source,
            env_pinned: prev?.env_pinned ?? false,
            quota_bytes: prev?.quota_bytes ?? 0,
            // The legacy directory has just been consumed (or declined); either
            // way the backend no longer offers it.
          }));
        }
        return result;
      } catch (e) {
        if (mountedRef.current) setError(errorMessage(e));
        return null;
      } finally {
        if (mountedRef.current) setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { status, loading, error, refresh, save };
}
