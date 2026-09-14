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

  // A restore that is still landing holds nothing of the analyst's. Asked
  // during one, the honest answer is "no" -- see `beginPristineRestore`.
  if (pristine !== null) return false;

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

/**
 * The restore that is still landing, if any. See `beginPristineRestore`.
 */
let pristine: {
  /** The restore's own promise chain has finished. */
  settled: boolean;
  /** The analyst has touched the page since the restore began. */
  touched: boolean;
  /** Detach the interaction listeners. */
  release: () => void;
} | null = null;

/** Take the baseline and end the window. Called at most once per window. */
function sealBaseline(): void {
  if (pristine === null) return;
  pristine.release();
  pristine = null;
  // A reset (or another restore) can land first. Re-baselining a workspace
  // that is no longer on screen would describe nothing.
  if (useAppStore.getState().appView !== "workspace") return;
  markSessionSaved(buildSessionSnapshot(""));
}

/**
 * The baseline is taken at max(restore finished, analyst first touched), which
 * is the last instant that is still provably before any edit of theirs.
 */
function sealWhenBothHappened(): void {
  if (pristine !== null && pristine.settled && pristine.touched) sealBaseline();
}

/**
 * Treat everything a restore does — including whatever it is still doing — as
 * "already saved", until the analyst touches the page.
 *
 * Two things this replaces a wall clock with a signal for, and both are real:
 *
 * 1. **The restore is not finished when the workspace appears.**
 *    `restoreSession` flips `appView` to "workspace" on its FIRST line and only
 *    then awaits the path-info resolution pass, so the workspace paints and
 *    becomes clickable while the caller has yet to reach `markSessionSaved`.
 *    For that whole gap `lastSavedDigest` is still `null`, which
 *    `isWorkspaceDirty` reads — correctly, by its own rules — as unsaved work.
 *    On a slow backend the analyst opens a session, clicks "New Session", and
 *    is told they have changes they never made. Starting the window BEFORE the
 *    first await is what closes that gap; a window opened after the restore
 *    could not, however generous it was.
 *
 * 2. **The restore is not finished when its promise resolves either.** Effects
 *    downstream of it keep mutating snapshot fields afterwards -- hex-store
 *    rehydrating that dump's bookmarks from localStorage, a scan result
 *    arriving over the task socket. None of that is the analyst's work.
 *
 * Both were previously approximated by re-digesting every 250 ms for 5 s. That
 * is a race against an unbounded, load-sensitive process, and under a loaded
 * backend it loses: past the deadline the digest moves on its own and the
 * workspace starts reporting changes nobody made.
 *
 * Listening in the CAPTURE phase is what makes the replacement safe rather than
 * merely longer. The first pointerdown/keydown/wheel is seen before React
 * handles it, so the baseline is taken from the state the analyst is about to
 * act on -- never from the state their action produced. There is no longer a
 * 250 ms window in which a real edit could be absorbed and declared saved.
 *
 * Returns `settle` (the restore's chain finished) and `abandon` (it failed --
 * leave the workspace dirty rather than blessing a half-applied restore).
 * Safe to call outside a browser.
 */
export function beginPristineRestore(): {
  settle: () => void;
  abandon: () => void;
} {
  // A second restore supersedes the first; the superseded one never seals,
  // because the workspace it described is already gone.
  abandonPristineRestore();

  if (typeof window === "undefined") {
    return { settle: () => {}, abandon: () => {} };
  }

  const onTouch = () => {
    if (pristine === null) return;
    pristine.touched = true;
    sealWhenBothHappened();
  };
  const release = () => {
    window.removeEventListener("pointerdown", onTouch, true);
    window.removeEventListener("keydown", onTouch, true);
    window.removeEventListener("wheel", onTouch, true);
  };
  window.addEventListener("pointerdown", onTouch, true);
  window.addEventListener("keydown", onTouch, true);
  window.addEventListener("wheel", onTouch, true);

  pristine = { settled: false, touched: false, release };

  return {
    settle: () => {
      if (pristine === null) return;
      pristine.settled = true;
      sealWhenBothHappened();
    },
    abandon: abandonPristineRestore,
  };
}

/** End the window WITHOUT taking a baseline. */
export function abandonPristineRestore(): void {
  if (pristine === null) return;
  pristine.release();
  pristine = null;
}

/** Test seam: is a restore currently being treated as pristine? */
export function isRestorePristine(): boolean {
  return pristine !== null;
}
