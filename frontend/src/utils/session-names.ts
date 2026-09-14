/**
 * Session naming: the reserved recovery name, and the suggestion shown in the
 * "start a new session" dialog.
 *
 * This module is deliberately separate from `session-persistence.ts` and holds
 * nothing but pure functions. `app-store` needs `RECOVERY_SESSION_NAME` (it
 * special-cases restoring the recovery copy), but `session-persistence` imports
 * `app-store` — so folding these two constants in there would close an
 * import cycle at module-eval time. Keeping the pure half separate is what
 * breaks it.
 */

/**
 * The session the workspace is written to when the user chooses "discard".
 *
 * Two constraints shaped the value. It must be a bare filename, because the
 * server resolves a session name through `safe_filename` and rejects anything
 * containing a path separator. And it must be implausible as a user's own
 * choice, because saving over an existing name silently overwrites it.
 *
 * Note that the server has no notion of a reserved name: the file stem IS the
 * `session_name` IS the `display_name` it reports back. So the recovery entry
 * can only be relabelled at render time, in `SessionLanding` — never hidden
 * behind a friendlier `display_name` from the API.
 */
export const RECOVERY_SESSION_NAME = "__recovery__";

/** True when *name* addresses the reserved recovery session. */
export function isRecoverySession(name: string): boolean {
  return name === RECOVERY_SESSION_NAME;
}

/**
 * Characters `safe_filename` accepts without complaint. Anything else is
 * folded to `-` rather than dropped, so two different dumps cannot collapse
 * onto the same suggestion.
 */
const UNSAFE_NAME_CHARS = /[^A-Za-z0-9._-]+/g;

function twoDigits(value: number): string {
  return String(value).padStart(2, "0");
}

/** `YYYY-MM-DD-HHmm` in local time — the analyst's clock, not UTC. */
function timestamp(now: Date): string {
  return [
    now.getFullYear(),
    twoDigits(now.getMonth() + 1),
    twoDigits(now.getDate()),
  ].join("-") + `-${twoDigits(now.getHours())}${twoDigits(now.getMinutes())}`;
}

/**
 * A save name the user will recognise: what they were looking at, and when.
 *
 * *subject* is the dump or dataset path the workspace was built from; only its
 * last segment is used. Falls back to a bare timestamp when there is nothing to
 * name it after, so the result is never empty and never collides with the
 * reserved recovery name.
 */
export function suggestSessionName(subject: string, now: Date = new Date()): string {
  const leaf = subject.split("/").filter(Boolean).pop() ?? "";
  const stem = leaf.replace(UNSAFE_NAME_CHARS, "-").replace(/^-+|-+$/g, "");
  return stem ? `${stem}-${timestamp(now)}` : `session-${timestamp(now)}`;
}
