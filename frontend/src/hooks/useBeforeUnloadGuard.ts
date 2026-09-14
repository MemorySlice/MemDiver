/**
 * Ask the browser to confirm before a close or reload discards unsaved work.
 *
 * Mounted from `Workspace` only, so it is inert on the landing page and in the
 * wizard — `isWorkspaceDirty()` enforces that too, but not mounting it is the
 * cheaper half of the guarantee.
 */

import { useEffect } from "react";

import { isWorkspaceDirty } from "@/utils/session-persistence";

/**
 * Registers the prompt for as long as the caller is mounted.
 *
 * The effect has an empty dependency list on purpose: the handler asks
 * `isWorkspaceDirty()` at fire time (a `getState()` read, so there is no stale
 * closure), which means the listener never has to be torn down and re-added as
 * the workspace changes.
 *
 * No translated message. Every current browser ignores the page's own text and
 * shows its own fixed wording, so a translatable string here would be dead code
 * that reviewers keep mistaking for a missing translation.
 */
export function useBeforeUnloadGuard(): void {
  useEffect(() => {
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (!isWorkspaceDirty()) return;
      event.preventDefault();
      // Still required by some browsers to trigger the prompt at all.
      event.returnValue = "";
    };

    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, []);
}
