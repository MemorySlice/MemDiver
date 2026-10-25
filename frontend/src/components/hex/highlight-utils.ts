import type { HexViewMode, HighlightRegion } from "@/stores/hex-store";

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

/**
 * The regions that address bytes in the view on screen.
 *
 * A region tagged with a `view` (analysis hits carry the view their offsets
 * were computed in) is dropped in any other view of a dump that has several
 * DISTINCT views — there its offset names unrelated bytes. Untagged regions,
 * and every region on a single-view dump (`availableViews` of length <= 1,
 * including "not probed yet"), pass through unchanged.
 */
export function regionsForView(
  regions: HighlightRegion[],
  viewMode: HexViewMode,
  availableViews: readonly HexViewMode[],
  dumpPath?: string,
): HighlightRegion[] {
  const byDump =
    dumpPath === undefined
      ? regions
      : regions.filter((r) => r.dumpPath === undefined || r.dumpPath === dumpPath);
  if (availableViews.length <= 1) return byDump;
  if (!byDump.some((r) => r.view !== undefined && r.view !== viewMode)) return byDump;
  return byDump.filter((r) => r.view === undefined || r.view === viewMode);
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

/** Number of generic palette slots (`--md-hl-kind-0` .. `--md-hl-kind-7`). */
export const KIND_SLOT_COUNT = 8;

/**
 * Fixed slots for the analysis-record kinds the workbench itself produces, so
 * the ones that appear together (a key hit inside a vol3 task_struct row, a
 * heap chunk under an annotation) never share a colour. A pure hash put
 * `key_hit`, `table_rule` and every `vol3:*` kind on the same slot.
 */
const KNOWN_KIND_SLOTS: Readonly<Record<string, number>> = {
  annotation: 0,
  key_hit: 1,
  plugin_row: 2,
  structure_proposal: 3,
  heap_chunk: 4,
  yara_hit: 5,
  isf_draft: 6,
  table_rule: 7,
};

/** Every `vol3:<plugin or type>` kind paints like a plugin row. */
const VOL3_KIND_PREFIX = "vol3:";

/**
 * Stable palette slot (0..7) for a highlight kind. Known workbench kinds get
 * their fixed slot; any other kind falls back to FNV-1a 32-bit over the UTF-16
 * code units, modulo 8. Pure function of the string, so the same kind gets the
 * same colour in every pane and across reloads.
 */
export function kindSlot(kind: string): number {
  const known = KNOWN_KIND_SLOTS[kind];
  if (known !== undefined) return known;
  if (kind.startsWith(VOL3_KIND_PREFIX)) return KNOWN_KIND_SLOTS.plugin_row;
  return hashSlot(kind);
}

function hashSlot(kind: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < kind.length; i++) {
    h ^= kind.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % KIND_SLOT_COUNT;
}

/**
 * The CSS class a region paints.
 *
 * Precedence: a region with a `kind` paints `highlight-kind-<slot>` and NOT its
 * closed `highlight-<type>` class (one band per region, as before). Which
 * region wins a byte is unchanged (`getRegionForOffset`); generic kinds sit in
 * the same slot of the cell-class order as closed types, so everything that
 * outranks a closed highlight (variance, consensus, absence...) outranks them.
 */
export function regionHighlightClass(region: HighlightRegion): string {
  return region.kind ? `highlight-kind-${kindSlot(region.kind)}` : highlightClass(region.type);
}
