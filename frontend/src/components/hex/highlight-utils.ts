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
  // hi is now the index of the last region with offset <= target
  if (hi >= 0) {
    const region = regions[hi];
    if (offset < region.offset + region.length) {
      return region;
    }
  }
  return null;
}

export function highlightClass(type: HighlightRegion["type"]): string {
  return `highlight-${type}`;
}
