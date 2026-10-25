import type { YaraHitRow } from "@/api/yara";
import { placeRow } from "@/api/lossless-json";
import { applyAnnotations, type AnnotationEntry } from "@/utils/apply-hits";
import { useHexStore, type HexViewMode, type HighlightRegion } from "@/stores/hex-store";
import { useYaraStore } from "@/stores/yara-store";

/** The highlight kind of every YARA hit (a workbench kind with its own colour slot). */
export const YARA_HIT_KIND = "yara_hit";

const asView = (view: string): HexViewMode | undefined =>
  view === "raw" || view === "vas" || view === "va" ? view : undefined;

/** Where `row` lands in the viewer, or `null` when the address is not exact. */
const placeOf = (row: YaraHitRow, scanView: string) => {
  const hex = useHexStore.getState();
  return placeRow(row, scanView, hex.vaSpanStart, hex.availableViews);
};

/** Every placeable hit as a `yara_hit` highlight region spanning the whole match. */
export function planYaraHighlights(
  rows: readonly YaraHitRow[], scanView: string, vaSpanStart: number, dumpPath: string,
): { regions: HighlightRegion[]; skipped: number } {
  const regions: HighlightRegion[] = [];
  rows.forEach((row, n) => {
    const place = placeRow(row, scanView, vaSpanStart, useHexStore.getState().availableViews);
    if (place === null) return;
    const entry: AnnotationEntry = {
      id: `yara:${n}`, kind: YARA_HIT_KIND, label: `${row.rule} ${row.string_id}`,
      length: row.length,
      locations: [{ space: row.space, value: Number(row.addr), offset: place.offset }],
    };
    regions.push(...applyAnnotations([entry], {
      space: row.space, toOffset: (loc) => loc.offset as number,
      dumpPath, view: asView(place.view) as HexViewMode,
    }));
  });
  return { regions, skipped: rows.length - regions.length };
}

/** Paint `regions`, replacing this panel's earlier highlights and keeping all others. */
export function paintYaraHits(regions: HighlightRegion[]): void {
  const hex = useHexStore.getState();
  const store = useYaraStore.getState();
  const mine = new Set(store.painted);
  hex.setHighlightedRegions([...hex.highlightedRegions.filter((r) => !mine.has(r)), ...regions]);
  store.setPainted(regions);
}

/** Put the viewer on a hit: its view, the cursor, and the matched bytes selected. */
export function goToYaraHit(row: YaraHitRow, scanView: string): boolean {
  const hex = useHexStore.getState();
  const place = placeOf(row, scanView);
  if (place === null) return false;
  if (place.view !== hex.viewMode) hex.showView(place.view);
  hex.scrollToOffset(place.offset);
  hex.selectRange(place.offset, place.offset + Math.max(row.length, 1) - 1);
  return true;
}
