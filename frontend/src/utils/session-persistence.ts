/**
 * Saving a session, and knowing whether it needs saving.
 *
 * Every path that writes a session goes through `persistSession` so that
 * "mark the workspace clean" cannot be forgotten at one call site and remembered
 * at another — a guard that nags after a successful save is as broken as one
 * that stays quiet after a real change.
 *
 * The I/O lives here rather than in `session-digest.ts` so that the comparison
 * logic stays pure and testable without mocking fetch.
 */

import { saveSession } from "@/api/client";
import type { SessionSnapshot } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { buildSessionSnapshot } from "@/utils/buildSessionSnapshot";
import { snapshotDigest } from "@/utils/session-digest";
import { RECOVERY_SESSION_NAME } from "@/utils/session-names";

/** Record that the workspace as it stands right now has been persisted. */
export function markSessionSaved(snap: Partial<SessionSnapshot>): void {
  useAppStore.getState().setLastSavedDigest(snapshotDigest(snap));
}

/**
 * Does the workspace hold changes that a "new session" would destroy?
 *
 * Answered on demand — at a click, a shortcut, or inside the `beforeunload`
 * handler — never by subscription, so normal editing pays nothing for it.
 *
 * Returns false outside the workspace. On the landing page and in the wizard
 * there is nothing to lose, and the never-saved digest of `null` would
 * otherwise read as "dirty" and prompt on an empty app.
 */
export function isWorkspaceDirty(): boolean {
  const state = useAppStore.getState();
  if (state.appView !== "workspace") return false;

  // Inside the workspace, `null` means the wizard was completed and nothing has
  // been saved since — which is exactly the case the reported bug lost.
  if (state.lastSavedDigest === null) return true;

  return snapshotDigest(buildSessionSnapshot("")) !== state.lastSavedDigest;
}

/**
 * Build the current workspace, POST it, and mark it clean.
 *
 * Rejects if the write failed, and in that case deliberately does NOT mark the
 * workspace clean: a caller that resets on a rejected save would destroy the
 * very work it was asked to keep.
 */
export async function persistSession(sessionName: string): Promise<string> {
  const snapshot = buildSessionSnapshot(sessionName);
  const result = await saveSession(snapshot);
  markSessionSaved(snapshot);
  return result.name;
}

/**
 * Write the workspace to the reserved recovery session.
 *
 * Deliberately does not mark the workspace clean. The recovery copy is a safety
 * net for work the analyst has just said they do not want, not a save they
 * asked for — and treating it as one would mean a later prompt claimed the work
 * was already stored under a name they chose.
 */
export async function persistRecoverySnapshot(): Promise<void> {
  await saveSession(buildSessionSnapshot(RECOVERY_SESSION_NAME));
}

/** How long after a restore late effects are still treated as part of it. */
const BASELINE_SETTLE_MS = 5000;
/** How often the baseline is refreshed inside that window. */
const BASELINE_POLL_MS = 250;

/**
 * Keep the "as saved" baseline in step with a restore that is still settling.
 *
 * Marking clean once, the moment `restoreSession` resolves, is not enough:
 * effects downstream of the restore keep mutating snapshot fields afterwards --
 * hex-store rehydrating that dump's bookmarks from localStorage, the algorithm
 * availability response adjusting the selection. None of that is the analyst's
 * work, but all of it changes the digest, so the workspace would start
 * reporting unsaved changes seconds after being opened and prompt on the very
 * first "New Session" click.
 *
 * So the baseline is refreshed for a short window -- and, crucially, only until
 * the user first touches the page. Listening for that interaction in the
 * CAPTURE phase means the very first pointerdown or keydown stops the refresh
 * before React handles it, so no real edit can ever be absorbed into the
 * baseline and silently declared "already saved".
 *
 * Returns a stop function; safe to call outside a browser.
 */
export function settleSessionBaseline(windowMs = BASELINE_SETTLE_MS): () => void {
  if (typeof window === "undefined") return () => {};

  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(poll);
    clearTimeout(deadline);
    window.removeEventListener("pointerdown", stop, true);
    window.removeEventListener("keydown", stop, true);
    window.removeEventListener("wheel", stop, true);
  };

  const poll = setInterval(() => {
    // Left the workspace (a reset, or another restore): there is nothing whose
    // baseline this still describes.
    if (useAppStore.getState().appView !== "workspace") {
      stop();
      return;
    }
    markSessionSaved(buildSessionSnapshot(""));
  }, BASELINE_POLL_MS);

  const deadline = setTimeout(stop, windowMs);
  window.addEventListener("pointerdown", stop, true);
  window.addEventListener("keydown", stop, true);
  window.addEventListener("wheel", stop, true);

  return stop;
}
