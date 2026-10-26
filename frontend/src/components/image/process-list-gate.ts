import type { ImageViewFactsState } from "@/hooks/useImageViewFacts";

/** What the process section shows for a view. */
export type ProcessListGate = "none" | "wait" | "physical" | "needProfile" | "list";

/**
 * Whether a view may be asked for its process list. The view's facts decide:
 * only `kernel` / `process` views WITH a profile can list. `primed` is the
 * profile flag the panel's own open-view job recorded (a fast path that skips
 * the wait). A failed facts request, or an older server without the `view`
 * block, falls back to asking: the backend's `kernel_view_required` answer is
 * then turned into the note.
 */
export function processListGate(
  viewPath: string, facts: ImageViewFactsState, primed: boolean | undefined,
): ProcessListGate {
  if (!viewPath) return "none";
  const view = facts.status === "ready" ? facts.preview.view ?? null : null;
  if (view?.kind === "physical") return "physical";
  if (primed !== undefined) return primed ? "list" : "needProfile";
  if (facts.status === "loading" || facts.status === "idle") return "wait";
  if (view) return view.has_profile ? "list" : "needProfile";
  return "list";
}
