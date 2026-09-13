/**
 * The bridge between the byte cache and the weighted-plurality reducer.
 *
 * `@/utils/plurality` is deliberately pure — it knows nothing about stores — and
 * `multi-hex-store` is deliberately a cache — it knows nothing about weights.
 * This module is the one place that holds both, so the hex grid and the status
 * footer read the SAME consensus byte from the SAME votes rather than each
 * gathering its own and drifting apart.
 *
 * A `.ts` module beside the components that use it, following
 * `highlight-utils.ts` and `window-utils.ts`: it is grid plumbing, not a
 * component and not general-purpose enough to live in `utils/`.
 */

import { useMultiHexStore, type ByteAbsence } from "@/stores/multi-hex-store";
import {
  weightedPlurality,
  type ByteVote,
  type PluralityResult,
} from "@/utils/plurality";

/** How much one dump's vote counts. Supplied by `dump-rail-store`. */
export type WeightLookup = (path: string) => number;

/**
 * Every included dump's byte at `offset`, ready for the reducer.
 *
 * `isPresentAt` is consulted for every path and is the SOLE authority on
 * presence: `getByteAt` hands back the stored `0` for a byte no dump holds, so
 * a tally built without the mask would count phantom `0x00` votes and paint
 * a confident zero over a hole in the address space.
 */
/**
 * Gather the votes into `out`, REUSING its slots when it already has them.
 *
 * Deliberately still routed through `isPresentAt` / `getByteAt` rather than
 * reading the cache's chunks directly: those two methods are the store's
 * documented reading surface — the presence mask is the sole authority on
 * presence — and they are the seam every pane test swaps to seed a grid. The
 * cost they used to carry has been paid down inside the store instead, where
 * the chunk each of them resolves is now resolved once per chunk rather than
 * once per call (see `chunkWindowAt` / `currentChunk`).
 */
function fillVotes(
  offset: number,
  paths: readonly string[],
  weightFor: WeightLookup,
  out: ByteVote[],
): ByteVote[] {
  const state = useMultiHexStore.getState();
  out.length = paths.length;
  for (let i = 0; i < paths.length; i++) {
    const path = paths[i];
    const present = state.isPresentAt(path, offset);
    const byte = present ? state.getByteAt(path, offset) : undefined;
    const weight = weightFor(path);
    const slot = out[i];
    if (slot === undefined) out[i] = { byte, weight };
    else {
      slot.byte = byte;
      slot.weight = weight;
    }
  }
  return out;
}

export function overlayVotes(
  offset: number,
  paths: readonly string[],
  weightFor: WeightLookup,
): ByteVote[] {
  return fillVotes(offset, paths, weightFor, []);
}

/**
 * The tally buffer `pluralityAt` reuses.
 *
 * `pluralityAt` runs once per painted cell — ~1,040 times a frame — and the
 * array plus its N vote objects were thrown away each time. `weightedPlurality`
 * reads the votes and keeps no reference to them, so one buffer serves every
 * cell. `overlayVotes` above stays allocating, because it is the PUBLIC shape
 * and a caller may reasonably hold on to what it hands back.
 */
const VOTE_SCRATCH: ByteVote[] = [];

/** The weighted plurality across `paths` at `offset`. */
export function pluralityAt(
  offset: number,
  paths: readonly string[],
  weightFor: WeightLookup,
): PluralityResult {
  return weightedPlurality(fillVotes(offset, paths, weightFor, VOTE_SCRATCH));
}

/**
 * Precedence for "why is there no byte here" across SEVERAL dumps.
 *
 * The two client-side causes outrank the two analysis results, because a window
 * that has not arrived (or whose request failed) is this UI's own problem and
 * must never be reported as a finding about memory. Between the two analysis
 * results, `no-correspondence` outranks `not-in-dump` because it is a fact
 * about the ALIGNMENT (it holds nothing here for anybody) and therefore the
 * stronger, set-wide statement.
 */
const ABSENCE_PRECEDENCE: ByteAbsence[] = [
  "loading",
  "error",
  "no-correspondence",
  "not-in-dump",
];

/** `ABSENCE_PRECEDENCE` as a lookup, so the hot loop does not scan the list. */
const ABSENCE_RANK: Record<ByteAbsence, number> = {
  loading: 0,
  error: 1,
  "no-correspondence": 2,
  "not-in-dump": 3,
};

/**
 * WHY the overlay layer has no byte at `offset`, or `null` when it HAS one.
 *
 * "It has one" means ANY included dump is present there — the overlay reads the
 * whole included set, not the anchor alone, so a byte three dumps hold and the
 * anchor does not is real data and is painted. Only when nobody holds it does
 * the cell become a void, and then this reports the strongest reason any
 * included dump gave for it.
 */
export function overlayAbsenceAt(
  offset: number,
  paths: readonly string[],
): ByteAbsence | null {
  // No paths at all (every dump excluded) is not an absence anyone can explain
  // in terms of a dump, so it reads as the alignment holding nothing here.
  if (paths.length === 0) return "no-correspondence";

  // `absenceAt` stays the single authority, for the same reason `isPresentAt`
  // does above. Its two PATH-INDEPENDENT halves — "did this chunk's request
  // fail" and "does the alignment hold this index at all" — used to be
  // recomputed from scratch on every one of the N calls this loop makes; they
  // are now answered from the per-chunk resolution inside the store.
  const store = useMultiHexStore.getState();
  let strongest: ByteAbsence | null = null;
  let rank = ABSENCE_PRECEDENCE.length;
  for (let i = 0; i < paths.length; i++) {
    const absence = store.absenceAt(paths[i], offset);
    if (absence === null) return null;
    const candidate = ABSENCE_RANK[absence];
    if (candidate !== undefined && candidate < rank) {
      rank = candidate;
      strongest = absence;
    }
  }
  return strongest ?? "no-correspondence";
}
