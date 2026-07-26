/**
 * Typed client for the algorithm-availability gate.
 *
 * Mirrors ``GET /api/algorithms/availability`` (api/routers/algorithms.py),
 * the server-side source of truth for "which analysis algorithms can run given
 * the current inputs, and why not". Replaces the former client-side
 * ``algorithm-availability.ts`` decision logic; the reason strings are byte
 * identical because they now come from the backend.
 */

import { request } from "./client";

export interface AlgorithmAvailability {
  available: boolean;
  reason: string | null;
}

export interface AlgorithmAvailabilityParams {
  dumpCount: number;
  hasKeylog: boolean;
  hasCandidateKeys: boolean;
  /** Mirrors the old ``inputMode`` context field; accepted but ignored server-side. */
  mode?: string | null;
  /**
   * Algorithm names to evaluate. When provided, the response contains an entry
   * for every name (non-gated names default to available); when omitted, only
   * the gated algorithms are returned.
   */
  algorithms?: readonly string[];
}

/**
 * Fetch the ``{algo: {available, reason}}`` availability map for the given
 * input context. Pass ``algorithms`` with the full list the UI renders so the
 * map has an entry for each checkbox.
 */
export async function getAlgorithmAvailability(
  params: AlgorithmAvailabilityParams,
): Promise<{ availability: Record<string, AlgorithmAvailability> }> {
  const qs = new URLSearchParams({
    dump_count: String(params.dumpCount),
    has_keylog: String(params.hasKeylog),
    has_candidate_keys: String(params.hasCandidateKeys),
  });
  if (params.mode) qs.set("mode", params.mode);
  if (params.algorithms) {
    for (const algo of params.algorithms) qs.append("algorithms", algo);
  }
  return request<{ availability: Record<string, AlgorithmAvailability> }>(
    `/api/algorithms/availability?${qs.toString()}`,
  );
}
