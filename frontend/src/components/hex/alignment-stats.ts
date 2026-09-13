/**
 * Numbers derived from one aligned window's `alignment` block.
 *
 * Extracted from `HexAlignmentChip` when `DumpRail` began reporting the same
 * coverage figures: two copies of the identity below would be two chances to
 * get the denominator wrong, and the whole point of the comment on
 * `discardedFraction` is that the tempting one-liner IS wrong.
 */

import type { AlignedWindowAlignment } from "@/api/aligned-window";

/**
 * `bytes_discarded` as a share of everything the dumps offered.
 *
 * Mirrors `core/region_align.AlignmentCoverage.discarded_fraction` exactly,
 * including its denominator: the backend's own invariant is
 * `sum(bytes_available) == bytes_compared * n_sources + bytes_discarded`, so
 * dividing by `compared + discarded` (the tempting one-liner) would UNDERSTATE
 * the loss by a factor of the dump count. The field is not on the wire, so the
 * identity is restated here rather than guessed at.
 */
export function discardedFraction(alignment: AlignedWindowAlignment): number {
  const offered = alignment.bytes_compared * alignment.n_sources + alignment.bytes_discarded;
  return offered > 0 ? alignment.bytes_discarded / offered : 0;
}
