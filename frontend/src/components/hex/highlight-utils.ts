import type { HighlightRegion } from "@/stores/hex-store";

/** Sorted region index for binary search lookup */
export interface RegionIndex {
  regions: HighlightRegion[];
}

export function buildRegionIndex(regions: HighlightRegion[]): RegionIndex {
  return {
    regions: [...regions].sort((a, b) => a.offset - b.offset),
  };
}

/** Find the highlight region containing the given offset, or null */
export function getRegionForOffset(
  index: RegionIndex,
  offset: number
): HighlightRegion | null {
  const { regions } = index;
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
  for (let i = hi; i >= 0; i--) {
    const region = regions[i];
    if (offset < region.offset + region.length) {
      return region;
    }
  }
  return null;
}

export function highlightClass(type: HighlightRegion["type"]): string {
  return `highlight-${type}`;
}
