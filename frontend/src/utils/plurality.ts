/**
 * The weighted-plurality reducer: N dumps' bytes at one offset → ONE byte.
 *
 * This is the arithmetic behind the `Σ Overlay` layer. It is deliberately a
 * pure function over votes rather than a method on a store, because two very
 * different surfaces have to agree about it to the last byte:
 *
 *   - the hex grid, which PAINTS the winner, and
 *   - the status footer, which reports `Agreement: k/N` about that same winner.
 *
 * A footer computing its own notion of agreement would eventually disagree with
 * the grid, and a byte the analyst reads with a disagreeing caption is worse
 * than no caption at all.
 *
 * ── Why this is client-side ──────────────────────────────────────────────────
 * `AlignedWindowResponse.variants` is weight-INDEPENDENT by design (it counts
 * distinct values, which no weight can change). The plurality is not: it must
 * answer the moment the user cycles a dump's weight, and a round trip per click
 * would make the control feel like a query rather than a lens. The client
 * already holds every dump's bytes for the visible window, so the tally is a
 * few hundred additions over data that is already in memory.
 *
 * ── The honest caveat, stated here and in the UI ─────────────────────────────
 * Where the dumps AGREE the winner is that agreed byte, which is exactly what
 * the overlay painted before this layer existed. Where they DISAGREE the winner
 * is a byte that may exist in no single dump at this offset — it is a computed
 * reading, not a read from a file. `DumpRail` says so in words next to the
 * `Σ Overlay` chip, and `OverlayByteInspector` remains the ground-truth surface
 * that shows every dump's true value unreduced.
 */

/** One dump's contribution to a tally. */
export interface ByteVote {
  /**
   * The byte this dump holds at the offset, or `undefined` when it holds none.
   *
   * `undefined` is NOT a value that can win: an absent byte is a different
   * finding from a byte, and letting absence out-vote data would paint holes
   * over bytes the other dumps really do hold. Absent dumps drop out of both
   * the tally and the `present` count.
   */
  byte: number | undefined;
  /** How much this dump's vote counts. Non-positive weights are ignored. */
  weight: number;
}

export interface PluralityResult {
  /** The winning byte, or `undefined` when no voter is present at all. */
  byte: number | undefined;
  /** How many PRESENT voters hold `byte`. `0` when `byte` is `undefined`. */
  agreeing: number;
  /** How many voters were present at all — the `N` of `Agreement: k/N`. */
  present: number;
  /** The winner's total weight, for callers that want the margin. */
  weight: number;
  /**
   * Whether every present voter holds the same byte.
   *
   * `false` when nobody is present: unanimity among nobody is not a finding,
   * and reporting it as one is how a void offset reads as perfect agreement.
   */
  unanimous: boolean;
}

const EMPTY: PluralityResult = {
  byte: undefined,
  agreeing: 0,
  present: 0,
  weight: 0,
  unanimous: false,
};

/**
 * ── Why the tally is a pair of SCRATCH ARRAYS and not a pair of Maps ─────────
 * This reducer runs once per painted cell. At 65 rendered rows x 16 bytes that
 * is 1,040 calls per frame, and the two `Map`s the first implementation
 * allocated were 2,080 short-lived objects per frame (12,480 at N=6) for a
 * tally over at most six votes in a 256-value key space.
 *
 * A byte IS its own index, so a flat array of 256 slots is a perfect hash: no
 * hashing, no allocation, no garbage. The arrays are module-level and reused,
 * and only the slots actually touched are cleared afterwards, so a call costs
 * O(votes) rather than O(256).
 *
 * Two escape hatches keep that an optimisation rather than a new contract:
 * `reduceViaMaps` is the original implementation verbatim, reached when a
 * caller hands us a `byte` outside 0..255 (the interface says "byte", but this
 * is a public util) and when a re-entrant call would otherwise share the
 * scratch.
 */
const SCRATCH_DOMAIN = 256;
const scratchWeight = new Float64Array(SCRATCH_DOMAIN);
const scratchCount = new Uint32Array(SCRATCH_DOMAIN);
const scratchTouched = new Int32Array(SCRATCH_DOMAIN);
let scratchBusy = false;

/** Is `byte` an index into the scratch tally? */
function inByteDomain(byte: number): boolean {
  return byte >= 0 && byte <= 0xff && (byte | 0) === byte;
}

/** The original Map-based tally, kept as the general (non-byte-domain) reducer. */
function reduceViaMaps(votes: readonly ByteVote[]): PluralityResult {
  const tally = new Map<number, number>();
  const counts = new Map<number, number>();
  let present = 0;

  for (const { byte, weight } of votes) {
    if (byte === undefined) continue;
    if (!(weight > 0)) continue;
    present += 1;
    tally.set(byte, (tally.get(byte) ?? 0) + weight);
    counts.set(byte, (counts.get(byte) ?? 0) + 1);
  }

  if (present === 0) return EMPTY;

  let winner = -1;
  let best = -1;
  for (const [byte, weight] of tally) {
    if (weight > best || (weight === best && byte < winner)) {
      winner = byte;
      best = weight;
    }
  }

  return {
    byte: winner,
    agreeing: counts.get(winner) ?? 0,
    present,
    weight: best,
    unanimous: tally.size === 1,
  };
}

/** The allocation-free tally, with the same traversal order and tie-break. */
function reduceVotes(votes: readonly ByteVote[]): PluralityResult {
  if (scratchBusy) return reduceViaMaps(votes);
  scratchBusy = true;
  let touched = 0;
  try {
    let present = 0;
    for (let i = 0; i < votes.length; i++) {
      const { byte, weight } = votes[i];
      if (byte === undefined) continue;
      if (!(weight > 0)) continue;
      if (!inByteDomain(byte)) return reduceViaMaps(votes);
      present += 1;
      if (scratchCount[byte] === 0) scratchTouched[touched++] = byte;
      scratchWeight[byte] += weight;
      scratchCount[byte] += 1;
    }

    if (present === 0) return EMPTY;

    // `scratchTouched` preserves FIRST-SEEN order, which is the order the Map
    // iterated in — the tie-break below is only total because of it.
    let winner = -1;
    let best = -1;
    for (let k = 0; k < touched; k++) {
      const byte = scratchTouched[k];
      const weight = scratchWeight[byte];
      if (weight > best || (weight === best && byte < winner)) {
        winner = byte;
        best = weight;
      }
    }

    return {
      byte: winner,
      agreeing: scratchCount[winner],
      present,
      weight: best,
      unanimous: touched === 1,
    };
  } finally {
    for (let k = 0; k < touched; k++) {
      const byte = scratchTouched[k];
      scratchWeight[byte] = 0;
      scratchCount[byte] = 0;
    }
    scratchBusy = false;
  }
}

/**
 * The weighted plurality over `votes`.
 *
 * ── The tie-break: LOWEST BYTE VALUE ─────────────────────────────────────────
 * Chosen over the two obvious alternatives on purpose.
 *
 *   - "the first voter wins" makes the painted byte depend on the ORDER the
 *     dumps happen to sit in the selection. Re-ordering the rail would silently
 *     repaint the grid, and the byte would be a fact about the UI rather than
 *     about memory.
 *   - "the anchor wins" reintroduces the anchor bias this layer exists to
 *     remove, and would make an excluded anchor's byte win a tie it is not
 *     voting in.
 *
 * The lowest value is arbitrary but TOTAL, stable and independent of both the
 * selection order and the weights, so the same set of dumps always paints the
 * same grid. A tie is in any case a disagreement, which the variance ramp, the
 * `differs` ring and the footer's `k/N` all report independently.
 *
 * ── Floating point ───────────────────────────────────────────────────────────
 * The three legal weights — 0.5, 1.0, 1.5 — are exact binary fractions, so
 * sums of them are exact and `>` compares them without an epsilon. That is a
 * property of the weight vocabulary, not of arithmetic in general; a weight
 * like 1/3 would need a tolerance here.
 */
export function weightedPlurality(votes: Iterable<ByteVote>): PluralityResult {
  // An array is already re-iterable, which is what both reducers need; only a
  // one-shot iterable pays for a copy, and the hot path never hands us one.
  return reduceVotes(Array.isArray(votes) ? (votes as ByteVote[]) : [...votes]);
}

/** `weightedPlurality(...).byte`, for the callers that only paint. */
export function weightedPluralityByte(votes: Iterable<ByteVote>): number | undefined {
  return weightedPlurality(votes).byte;
}
