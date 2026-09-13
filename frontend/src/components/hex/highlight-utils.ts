import type { HighlightRegion } from "@/stores/hex-store";

/** Sorted region index for binary search lookup */
export interface RegionIndex {
  regions: HighlightRegion[];
  /**
   * The longest region's length — the bound that stops the left-walk below.
   *
   * Without it the walk runs to index 0 whenever NO region contains the offset,
   * which is the common case for a hex row: at the 500-hit cap that was ~500
   * iterations per uncovered cell, 520,000 per rendered frame.
   */
  maxLength: number;
}

export function buildRegionIndex(regions: HighlightRegion[]): RegionIndex {
  let maxLength = 0;
  for (const region of regions) {
    if (region.length > maxLength) maxLength = region.length;
  }
  return {
    regions: [...regions].sort((a, b) => a.offset - b.offset),
    maxLength,
  };
}

/** Find the highlight region containing the given offset, or null */
export function getRegionForOffset(
  index: RegionIndex,
  offset: number
): HighlightRegion | null {
  const { regions, maxLength } = index;
  // Binary search for the last region with offset <= target
  let lo = 0;
  let hi = regions.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (regions[mid].offset <= offset) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  // hi is now the index of the last region with offset <= target. Regions are
  // sorted by start offset only and may overlap, so the rightmost candidate is
  // not necessarily the one containing target — an earlier region with a
  // larger length can still span it. Walk left over candidates (offset <=
  // target) and return the first whose [offset, offset+length) contains target.
  // Regions are sorted ascending, so `offset - region.offset` only GROWS as the
  // walk goes left: once it reaches the longest region's length, no remaining
  // candidate can still span `offset`.
  for (let i = hi; i >= 0; i--) {
    const region = regions[i];
    if (offset - region.offset >= maxLength) break;
    if (offset < region.offset + region.length) {
      return region;
    }
  }
  return null;
}

export function highlightClass(type: HighlightRegion["type"]): string {
  return `highlight-${type}`;
}
