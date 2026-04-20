/**
 * Shared utility for grouping analysis hits by algorithm and dispatching
 * to the results store and hex store.
 *
 * Used by: AnalysisPanel (after analysis), SessionManager (after restore),
 * ScanResultsPanel (after re-run).
 */

import type { SecretHit } from "@/api/types";
import type { HighlightRegion } from "@/stores/hex-store";
import { useResultsStore } from "@/stores/results-store";
import { useHexStore } from "@/stores/hex-store";
import { useAppStore } from "@/stores/app-store";
import { secretTypeToHighlight } from "@/utils/highlight-types";

interface AnalysisResultLike {
  libraries: Array<{ hits: SecretHit[] }>;
}

/**
 * Group hits by algorithm, dispatch to results store, and optionally
 * update hex highlights and candidate-key flag.
 *
 * @param withHighlights  If true, also pushes highlight regions to hex store
 *                        and sets hasCandidateKeys. Pass false for lightweight
 *                        re-runs that only update the results panel.
 */
export function applyHitsToStores(
  result: AnalysisResultLike,
  withHighlights = true,
): void {
  const hitsByAlgorithm: Record<string, SecretHit[]> = {};
  let anyHits = false;

  for (const lib of result.libraries) {
    for (const hit of lib.hits) {
      const key = hit.secret_type;
      (hitsByAlgorithm[key] ??= []).push(hit);
      anyHits = true;
    }
  }

  const resultsState = useResultsStore.getState();
  for (const [algoName, hits] of Object.entries(hitsByAlgorithm)) {
    resultsState.setAlgorithmResults(algoName, hits);
  }

  if (withHighlights) {
    const allHits = result.libraries.flatMap((lib) => lib.hits);
    const regions: HighlightRegion[] = allHits.map((hit) => ({
      offset: hit.offset,
      length: hit.length,
      type: secretTypeToHighlight(hit.secret_type),
      label: `${hit.secret_type} (${hit.library || "unknown"})`,
    }));
    useHexStore.getState().setHighlightedRegions(regions);
    if (anyHits) useAppStore.getState().setHasCandidateKeys(true);
  }
}

/**
 * Group flat hits (e.g., from session restore) by secret_type and
 * dispatch to results store. Handles unknown/missing secret_type gracefully.
 */
export function applyFlatHitsToStore(hits: unknown[]): void {
  const hitsByAlgo: Record<string, SecretHit[]> = {};
  for (const hit of hits) {
    const key = (hit as Record<string, unknown>).secret_type as string ?? "restored";
    (hitsByAlgo[key] ??= []).push(hit as SecretHit);
  }
  const store = useResultsStore.getState();
  for (const [algo, algoHits] of Object.entries(hitsByAlgo)) {
    store.setAlgorithmResults(algo, algoHits);
  }
}
