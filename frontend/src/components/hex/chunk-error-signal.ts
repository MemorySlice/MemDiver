/**
 * "Has the SET of failed chunks changed?", as one scalar.
 *
 * ── Why the viewers need this at all ─────────────────────────────────────────
 * `multi-hex-store.chunkVersionByPath` is bumped in `applyResponse` and nowhere
 * else, so it answers "did this pane's bytes arrive" — not "did this window's
 * request fail". A failed fetch writes only `chunkErrors` and `pending`, which
 * means the byte readers keyed on the version never rotate, `HexRow`'s memo
 * never re-runs, and the cells the store would now describe as `"error"` keep
 * painting the `··` they were painting while the request was in flight. The
 * `.byte-error` treatment, its high-contrast rule and the `Load failed` legend
 * swatch were all unreachable as a result: the banner appeared, the grid did
 * not change.
 *
 * ── Why a signature and not the Map ──────────────────────────────────────────
 * Subscribing a viewer to `chunkErrors` itself would re-render it on every
 * successful response too — `applyResponse` copies the Map to delete the key it
 * just satisfied, so the identity rotates whether or not anything failed. That
 * is the per-response churn the per-path `chunkVersionByPath` design exists to
 * avoid, and reintroducing it at the top of the tree would undo it for every
 * pane at once. A signature over the KEYS collapses the common case — no
 * failures, before and after — to the same `""`, so the readers rotate when a
 * chunk starts or stops failing and at no other time.
 *
 * Over-triggering is safe and under-triggering is not, which is why insertion
 * order is left in: a failure dropped and re-added yields a different string and
 * costs one repaint, where a set-equality test that ignored order could miss a
 * one-in-one-out change.
 */

/** The empty signature, so "nothing has failed" is one shared string. */
const NO_FAILURES = "";

/**
 * A cache key is `identity|offset`, and the identity carries dump PATHS,
 * which can hold anything but a NUL byte — so this separator cannot occur
 * inside a key and two different key sets cannot join to the same string.
 */
const KEY_SEP = "\u0000";

/**
 * A value that changes exactly when the failed-chunk SET changes.
 *
 * Takes the map rather than the store so it is a pure function of the one field
 * it reads, and can be called from a zustand selector without pulling the rest
 * of the state into the subscription.
 */
export function chunkErrorSignature(chunkErrors: ReadonlyMap<string, unknown>): string {
  if (chunkErrors.size === 0) return NO_FAILURES;
  let signature = "";
  for (const key of chunkErrors.keys()) signature += key + KEY_SEP;
  return signature;
}
