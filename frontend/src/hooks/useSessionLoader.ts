import { useCallback, useState } from "react";
import { listSessions, loadSession } from "@/api/client";
import type { SessionInfo } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { applyHitsToStores } from "@/utils/apply-hits";
import { buildSessionSnapshot } from "@/utils/buildSessionSnapshot";
import { beginPristineRestore, markSessionSaved } from "@/utils/session-persistence";
import { isRecoverySession } from "@/utils/session-names";

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
      // Opened BEFORE the first await, and that is the whole point. The restore
      // flips `appView` to "workspace" on its first line, so the workspace is on
      // screen and clickable long before this function reaches `markSessionSaved`
      // below. Without a window that is already open by then, everything in that
      // gap reads as unsaved work -- see `beginPristineRestore`.
      //
      // The recovery copy is the deliberate exception: it is a safety net the
      // user never asked for, so it stays dirty to nudge a real save.
      const restore = isRecoverySession(name) ? null : beginPristineRestore();
      try {
        const snap = await loadSession(name);
        await useAppStore.getState().restoreSession(snap);
        if (snap.analysis_result) {
          const setResult = useAnalysisStore.getState().setResult;
          setResult(
            snap.analysis_result as unknown as Parameters<typeof setResult>[0],
          );
          applyHitsToStores(
            snap.analysis_result as unknown as Parameters<typeof applyHitsToStores>[0],
          );
        }
        // A session that was just loaded is, by definition, saved, so the
        // unsaved-work guard must not prompt about it. Marking it here -- after
        // the restore has fully settled -- is what covers BOTH entry points,
        // since SessionLanding and SessionManager both come through this hook.
        //
        // It digests what `buildSessionSnapshot` WOULD write rather than the
        // snapshot the server just sent. Those are not the same object: the
        // stored file carries server-stamped fields the UI never produces, so
        // comparing against it would leave every restored session permanently
        // "dirty" and prompt on the very first click.
        //
        // The recovery copy is the deliberate exception: it is a safety net the
        // user never asked for, so it stays unsaved to nudge a real save under
        // a name they chose.
        if (!isRecoverySession(name)) {
          markSessionSaved(buildSessionSnapshot(""));
          // The restore's own chain is done. The window stays open until the
          // analyst touches the page, because effects downstream of the restore
          // are still landing; see `beginPristineRestore`.
          restore?.settle();
        }
        opts?.onSuccess?.(name);
      } catch (e) {
        // Never bless a half-applied restore as "saved": whatever did land is
        // not what the file says, and the analyst should be warned before it is
        // thrown away.
        restore?.abandon();
        opts?.onError?.(e instanceof Error ? e.message : "Failed to load session");
      }
    },
    [],
  );

  return { sessions, loading, refresh, loadAndRestore };
}
