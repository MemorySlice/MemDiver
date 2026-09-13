import { useEffect, useRef, type RefObject } from "react";

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
 */
export function useInfiniteScrollSentinel(
  hasMore: boolean,
  loading: boolean,
  /** Stable identity, please: it is an effect dependency. May be async. */
  loadMore: () => void | Promise<void>,
): RefObject<HTMLDivElement | null> {
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = sentinelRef.current;
    if (!node || !hasMore || loading) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) void loadMore();
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasMore, loading, loadMore]);

  return sentinelRef;
}
