export const tab = (name: string) => `[data-testid="tab-${name}"]`;
export const stringsRow = `[data-testid="strings-row"]`;
export const formatPill = `[data-testid="format-pill"]`;

/** `[data-testid="…"]`, for ids that have no friendlier helper of their own. */
export const testId = (id: string) => `[data-testid="${id}"]`;

/**
 * The unsaved-work guard: the two entry points and the dialog they share.
 *
 * Grouped rather than exported one-by-one because the point of the feature is
 * that these belong together — the toolbar button, Ctrl+N and the dialog are
 * one policy, and a spec that reaches for one of them nearly always reaches
 * for the next.
 *
 * `overlay` is the backdrop `Modal` renders around the dialog; it is named
 * here because "clicking the backdrop does NOT close this dialog" is part of
 * the contract, so a spec has to be able to click it.
 */
export const newSession = {
  button: testId("new-session"),
  dialog: testId("new-session-dialog"),
  overlay: testId("new-session-dialog-overlay"),
  name: testId("new-session-name"),
  save: testId("new-session-save"),
  discard: testId("new-session-discard"),
  cancel: testId("new-session-cancel"),
  /** The pinned recovery row on the session landing page. */
  recoveryRow: testId("recovery-session"),
} as const;
