/**
 * The ONE mounted effect that keeps `variance-regions-store` loaded.
 *
 * `selectCategory` is deliberately synchronous and deliberately does NOT fetch
 * (see the store's own doc): selection is a state change, the fetch is a side
 * effect of it, and the store refuses to own an effect it cannot cancel. This
 * hook is that effect, in one place, so two mounted consumers — the chips in
 * the legend and the browser in the detail panel — cannot each fire their own
 * and page-two a list nobody scrolled.
 *
 * Idempotence comes from `liveRequestKey`, not from a ref: a ref is per-mount
 * and would re-fire on every remount, while the key is the store's OWN identity
 * for the query. If the store already holds page one for the key this render
 * resolves to, there is nothing to do — whichever consumer mounted first
 * already asked.
 *
 * The dependency list is the request identity spelled out, term for term. The
 * load-bearing one is `viewMode`: a `"vas"` <-> `"va"` switch changes the
 * coordinate `anchor_offset` is expressed in, so a list that survives it serves
 * offsets in the coordinate the viewer has already left.
 */

import { useEffect } from "react";

import { useConsensusStore } from "@/stores/consensus-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import {
  DEFAULT_BROWSE_CATEGORY,
  liveRequestKey,
  useVarianceRegionsStore,
} from "@/stores/variance-regions-store";

/**
 * Ensure the region list describes the query the app is currently in.
 *
 * Selects the default category on a cold store — the NON-INVARIANT UNION, the
 * only category that finds a real key whole — and (re)loads page one whenever
 * the request identity changes underneath it.
 */
export function useVarianceRegionsLoader(): void {
  const category = useVarianceRegionsStore((s) => s.category);
  const minLength = useVarianceRegionsStore((s) => s.minLength);
  // Subscribed, not merely read: when a load ENDS the effect has to look again.
  // A request that was in flight while the view mode changed is accepted by the
  // store (its key matched at send time) and is expressed in the coordinate the
  // viewer has already left, so the re-check on `loading -> false` is what
  // replaces it.
  const loading = useVarianceRegionsStore((s) => s.loading);
  const selectCategory = useVarianceRegionsStore((s) => s.selectCategory);
  const loadMore = useVarianceRegionsStore((s) => s.loadMore);

  // The three live terms of `requestKey` that this store does not own. Read as
  // subscriptions, not through `getState()`, precisely so the effect re-runs
  // when one of them changes.
  const viewMode = useHexStore((s) => s.viewMode);
  const anchorPath = useHexStore((s) => s.dumpPath);
  const consensusId = useConsensusStore((s) => s.consensusId);
  const lastRequest = useMultiHexStore((s) => s.lastRequest);

  useEffect(() => {
    if (category === null) {
      selectCategory(DEFAULT_BROWSE_CATEGORY);
      return;
    }
    const state = useVarianceRegionsStore.getState();
    // A request is already in flight for SOMETHING; `loadMore` would refuse
    // anyway, and the effect will run again when its answer lands.
    if (state.loading) return;
    // Page one for this exact query is already in the store.
    if (state.requestKey === liveRequestKey(category, minLength)) return;
    void loadMore();
  }, [
    category,
    minLength,
    loading,
    selectCategory,
    loadMore,
    viewMode,
    anchorPath,
    consensusId,
    lastRequest,
  ]);
}
