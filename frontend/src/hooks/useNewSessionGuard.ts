/**
 * The one place that decides what "start a new session" does.
 *
 * There are two ways to ask for a new session — the toolbar button and Ctrl+N —
 * and before this hook both called `resetWizard` directly, which wiped the
 * workspace synchronously with no prompt and no save. Routing both through a
 * single `requestNewSession` is what makes the guard impossible to bypass by
 * one of the two.
 *
 * The hook owns the policy (dirty? prompt : reset) and the dialog's state;
 * `NewSessionDialog` renders it and owns nothing but the editable name. It is
 * called ONCE, from `Workspace`, because Ctrl+N is registered there while the
 * button lives in `Toolbar` two components away — a hook at the common ancestor
 * collapses that distance without putting transient view state into a store.
 */

import { useCallback, useMemo, useState } from "react";

import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useHexStore } from "@/stores/hex-store";
import {
  isWorkspaceDirty,
  persistRecoverySnapshot,
  persistSession,
} from "@/utils/session-persistence";
import { suggestSessionName } from "@/utils/session-names";

/** What the dialog tells the user is at stake. */
export interface UnsavedWorkSummary {
  dumps: number;
  bookmarks: number;
  hasAnalysisResult: boolean;
}

export interface NewSessionGuard {
  open: boolean;
  /** Pre-fill for the name input, computed when the dialog opens. */
  defaultName: string;
  summary: UnsavedWorkSummary;
  busy: boolean;
  error: string | null;
  /** True once a recovery write has failed and discarding needs confirming. */
  recoveryFailed: boolean;
  /** THE entry point. Dirty opens the dialog; clean resets immediately. */
  requestNewSession: () => void;
  saveAndStartNew: (name: string) => Promise<void>;
  discardAndStartNew: () => Promise<void>;
  /** Escape hatch offered only after a failed recovery write. */
  forceDiscardAndStartNew: () => void;
  cancel: () => void;
}

function describeUnsavedWork(): UnsavedWorkSummary {
  return {
    dumps: useDumpStore.getState().dumps.length,
    bookmarks: useHexStore.getState().bookmarks.length,
    hasAnalysisResult: useAnalysisStore.getState().result !== null,
  };
}

const NO_WORK: UnsavedWorkSummary = {
  dumps: 0,
  bookmarks: 0,
  hasAnalysisResult: false,
};

export function useNewSessionGuard(): NewSessionGuard {
  const [open, setOpen] = useState(false);
  const [defaultName, setDefaultName] = useState("");
  const [summary, setSummary] = useState<UnsavedWorkSummary>(NO_WORK);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveryFailed, setRecoveryFailed] = useState(false);

  const startNewSession = useCallback(() => {
    setOpen(false);
    setBusy(false);
    setError(null);
    setRecoveryFailed(false);
    useAppStore.getState().resetWizard();
  }, []);

  const requestNewSession = useCallback(() => {
    // Ctrl+N is bound on `window` and keeps firing while the dialog has focus;
    // without this the dialog would reset its own name field under the user.
    if (open) return;

    if (!isWorkspaceDirty()) {
      startNewSession();
      return;
    }

    const state = useAppStore.getState();
    setDefaultName(suggestSessionName(state.inputPath || state.datasetRoot));
    setSummary(describeUnsavedWork());
    setError(null);
    setRecoveryFailed(false);
    setOpen(true);
  }, [open, startNewSession]);

  const saveAndStartNew = useCallback(
    async (name: string) => {
      setBusy(true);
      setError(null);
      try {
        await persistSession(name.trim() || defaultName);
      } catch (e) {
        // Never reset after a failed save: that is the exact move that would
        // destroy the work the user just asked to keep.
        setError(e instanceof Error ? e.message : String(e));
        setBusy(false);
        return;
      }
      startNewSession();
    },
    [defaultName, startNewSession],
  );

  const discardAndStartNew = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      // Awaited before the wipe. `buildSessionSnapshot` reads the stores
      // synchronously so the payload is captured either way, but resetting on a
      // rejected write would lose the work this safety net exists to keep.
      await persistRecoverySnapshot();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRecoveryFailed(true);
      setBusy(false);
      return;
    }
    startNewSession();
  }, [startNewSession]);

  const cancel = useCallback(() => {
    setOpen(false);
    setError(null);
    setRecoveryFailed(false);
    setBusy(false);
  }, []);

  return useMemo(
    () => ({
      open,
      defaultName,
      summary,
      busy,
      error,
      recoveryFailed,
      requestNewSession,
      saveAndStartNew,
      discardAndStartNew,
      forceDiscardAndStartNew: startNewSession,
      cancel,
    }),
    [
      open,
      defaultName,
      summary,
      busy,
      error,
      recoveryFailed,
      requestNewSession,
      saveAndStartNew,
      discardAndStartNew,
      startNewSession,
      cancel,
    ],
  );
}
