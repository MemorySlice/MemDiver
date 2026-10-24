/**
 * The aligned window's per-dump MSL page-state runs, decoded and queried.
 *
 * Everything here is in WINDOW INDEX space, exactly as the backend sends it
 * (invariant W1, see `@/api/aligned-window`): a run is placed by its window
 * offset and nothing else, so no `va` / `offset` arithmetic ever happens on the
 * client — for the anchor or for a peer.
 */

import type { AlignedWindowPageState } from "@/api/aligned-window";

/** One decoded run: `[start, end)` in window index space, plus its state. */
export interface PageStateRun {
  start: number;
  end: number;
  state: AlignedWindowPageState;
}

const WIRE_STATES: ReadonlySet<string> = new Set(["FAILED", "UNMAPPED", "NOT_RESIDENT"]);

function isWireState(value: unknown): value is AlignedWindowPageState {
  return typeof value === "string" && WIRE_STATES.has(value);
}

/**
 * Decode `dumps[d].page_states` into sorted runs clipped to `[0, length)`.
 *
 * Defensive rather than trusting: an unknown state (a CAPTURED that slipped
 * through, a future state this client cannot name) or an empty run is dropped,
 * because a tint for a state the legend cannot explain is worse than no tint.
 * `undefined` (an older server) decodes to no runs at all.
 */
export function decodePageStateRuns(
  raw: readonly (readonly unknown[])[] | undefined,
  length: number,
): PageStateRun[] {
  if (!Array.isArray(raw)) return [];
  const runs: PageStateRun[] = [];
  for (const entry of raw) {
    const [start, runLength, state] = entry;
    if (typeof start !== "number" || typeof runLength !== "number") continue;
    if (!isWireState(state)) continue;
    const from = Math.max(0, start);
    const to = Math.min(length, start + runLength);
    if (to > from) runs.push({ start: from, end: to, state });
  }
  return runs.sort((a, b) => a.start - b.start);
}

/** The state of the run holding `index`, by binary search; `undefined` if none. */
export function pageStateInRuns(
  runs: readonly PageStateRun[],
  index: number,
): AlignedWindowPageState | undefined {
  let lo = 0;
  let hi = runs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const run = runs[mid];
    if (index < run.start) hi = mid - 1;
    else if (index >= run.end) lo = mid + 1;
    else return run.state;
  }
  return undefined;
}

/**
 * A bounded estimate of what a run list holds, for the store's byte budget.
 * Three numbers-ish per run; tiny next to the 16 KiB a pane chunk costs, but
 * counted so the budget stays an honest total.
 */
export const PAGE_STATE_RUN_COST_BYTES = 24;
