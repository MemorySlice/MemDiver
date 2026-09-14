import { useEffect, useRef, type RefObject } from "react";

/**
 * How many pages the sentinel will fetch on its own while it stays in view.
 *
 * The same shape, and the same reason, as `multi-hex-store.MAX_CHUNK_RETRIES`:
 * an automatic loader that re-arms on its own needs a budget, or one failing
 * request becomes an unbounded stream of them.
 *
 * Three is "one plus two retries", matching the byte cache. Healthy pagination
 * almost never reaches it: a page that really loads pushes the sentinel out of
 * view, and the next observation refills the budget.
 */
export const MAX_SENTINEL_AUTOLOADS = 3;

/**
 * Load the next page when a sentinel element scrolls into view.
 *
 * The only `IntersectionObserver` in this tree, and the two paginated lists
 * that want one — the dataset run list and the variance-region browser — had
 * verbatim copies of it. Both keep an explicit "Load more" button as the
 * accessible, keyboard-triggerable fallback; this is the convenience on top,
 * never the only way through.
 *
 * The observer is not created at all while `loading` or `!hasMore`, so a page
 * already in flight cannot be requested a second time by a scroll tick, and a
 * finished list stops observing entirely.
 *
 * ── The budget, and the POST storm it bounds ────────────────────────────────
 * `!hasMore || loading` has no FAILURE term, and neither list clears `hasMore`
 * when a page rejects: `variance-regions-store` leaves `nextAfter` untouched,
 * so `nextAfter !== -1` stays true. `loading` flips back to false, this effect
 * re-runs, builds a NEW observer, and `observe()` always delivers an initial
 * callback for a still-intersecting target — so a second page that fails is
 * requested again, and again, with no backoff and no end. (A FIRST-page failure
 * is safe only by accident: the cursor is still `-1`, so `hasMore` is false.)
 *
 * There is no failure signal to read: neither caller's `loadMore` rejects, both
 * swallow the error into their own store. So the fix is the one
 * `multi-hex-store` already uses for the same shape of latch — bound the
 * automatic attempts and require a gesture to resume:
 *
 *   - Every auto-triggered load spends one unit of `MAX_SENTINEL_AUTOLOADS`.
 *     At zero the observer is not created at all; nothing re-arms it by itself.
 *   - An observation that the sentinel is NOT intersecting refills the budget.
 *     That is what a successful load looks like from here: the list grew and
 *     pushed the sentinel out of view.
 *   - A load this hook did not trigger refills it too. That is the human
 *     gesture — the "Load more" button both lists keep — and it is the
 *     counterpart of `retryChunkAt`: a person asking again is not a retry.
 */
export function useInfiniteScrollSentinel(
  hasMore: boolean,
  loading: boolean,
  /** Stable identity, please: it is an effect dependency. May be async. */
  loadMore: () => void | Promise<void>,
): RefObject<HTMLDivElement | null> {
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  /** Automatic loads spent since the budget was last refilled. */
  const spent = useRef(0);
  /** Did THIS hook start the load that is currently running? */
  const mine = useRef(false);
  /** Previous value of `loading`, for the true -> false edge. */
  const wasLoading = useRef(false);

  // Declared BEFORE the observer effect so it runs first on a shared `loading`
  // change: the budget is refilled before the observer asks whether it has one.
  useEffect(() => {
    if (loading) {
      wasLoading.current = true;
      return;
    }
    if (!wasLoading.current) return;
    wasLoading.current = false;
    // A load ENDED. If this hook did not start it, a person did (the "Load
    // more" button, or the list's own mounted loader) and the budget starts
    // over. If this hook did start it, the unit stays spent — a failed page
    // looks exactly like a successful one from here, and only the sentinel
    // leaving the viewport tells the two apart.
    if (!mine.current) spent.current = 0;
    mine.current = false;
  }, [loading]);

  useEffect(() => {
    const node = sentinelRef.current;
    if (!node || !hasMore || loading) return;
    if (spent.current >= MAX_SENTINEL_AUTOLOADS) return;
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) {
        // Out of view: the list moved on under us, which is what a page that
        // actually loaded looks like. Refill.
        spent.current = 0;
        mine.current = false;
        return;
      }
      if (spent.current >= MAX_SENTINEL_AUTOLOADS) return;
      spent.current += 1;
      mine.current = true;
      void loadMore();
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasMore, loading, loadMore]);

  return sentinelRef;
}
