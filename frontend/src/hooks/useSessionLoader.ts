import { useCallback, useState } from "react";
import { listSessions, loadSession } from "@/api/client";
import type { SessionInfo } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { applyHitsToStores } from "@/utils/apply-hits";

interface LoadOptions {
  onError?: (msg: string) => void;
  onSuccess?: (name: string) => void;
}

/**
 * Shared session loading logic used by SessionLanding and SessionManager.
 *
 * Exposes the session listing (with loading state + refresh) and a single
 * canonical load-and-restore path. Both consumers funnel through
 * applyHitsToStores so hit application (results panel + hex highlights +
 * candidate-key flag) stays consistent across the app. Components supply
 * their own success/error UI via the opts callbacks.
 */
export function useSessionLoader() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  // Initialized true to match the immediate fetch consumers fire on mount,
  // so the "No saved sessions" empty state does not flash for one frame
  // before that fetch resolves. refresh()'s finally always flips it false.
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listSessions();
      setSessions(data.sessions);
    } catch (e) {
      throw e instanceof Error ? e : new Error("Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAndRestore = useCallback(
    async (name: string, opts?: LoadOptions) => {
      try {
        const snap = await loadSession(name);
        useAppStore.getState().restoreSession(snap);
        if (snap.analysis_result) {
          const setResult = useAnalysisStore.getState().setResult;
          setResult(
            snap.analysis_result as unknown as Parameters<typeof setResult>[0],
          );
          applyHitsToStores(
            snap.analysis_result as unknown as Parameters<typeof applyHitsToStores>[0],
          );
        }
        opts?.onSuccess?.(name);
      } catch (e) {
        opts?.onError?.(e instanceof Error ? e.message : "Failed to load session");
      }
    },
    [],
  );

  return { sessions, loading, refresh, loadAndRestore };
}
