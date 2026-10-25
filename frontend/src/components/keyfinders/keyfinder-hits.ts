import type { KeyHitRow } from "@/api/keyfinders";
import { placeRow, wireIntOffset, wireIntToBigInt, type HexPlace, type WireInt } from "@/api/lossless-json";
import { applyAnnotations, type AnnotationEntry } from "@/utils/apply-hits";
import { useHexStore, type HexViewMode, type HighlightRegion } from "@/stores/hex-store";
import { useKeyFinderStore } from "@/stores/keyfinder-store";
import { useVerificationStore } from "@/stores/verification-store";

/** The highlight kind of every key-finder hit (an existing workbench kind with its own colour slot). */
export const KEY_HIT_KIND = "key_hit";

const isOffset = (n: number) => Number.isSafeInteger(n) && n >= 0;

/**
 * A scanned address as a hex-viewer offset. `va`-view addresses are rebased by the
 * view's span start; `vas`/`raw` addresses already are viewer offsets. `null` when the
 * result is not exact (a JSON number past 2^53 has been rounded).
 */
export function hexOffsetOf(addr: WireInt, scanView: string, vaSpanStart: number): number | null {
  return wireIntOffset(addr, scanView === "va" ? vaSpanStart : 0);
}

/** A viewer offset as a scan-request address (the inverse of {@link hexOffsetOf}). */
export function scanAddressOf(offset: number, scanView: string, vaSpanStart: number): number | null {
  const addr = scanView === "va" ? offset + vaSpanStart : offset;
  return isOffset(addr) ? addr : null;
}

/** Where `row` lands in the viewer (see {@link placeRow}), or `null` when it is not exact. */
const placeOf = (row: KeyHitRow, scanView: string): HexPlace | null => {
  const hex = useHexStore.getState();
  return placeRow(row, scanView, hex.vaSpanStart, hex.availableViews);
};

const asView = (view: string): HexViewMode | undefined =>
  view === "raw" || view === "vas" || view === "va" ? view : undefined;

/** Every placeable hit as a `key_hit` highlight region spanning the whole hit. */
export function planKeyHitHighlights(
  rows: readonly KeyHitRow[], scanView: string, vaSpanStart: number, dumpPath: string,
): { regions: HighlightRegion[]; skipped: number } {
  const regions: HighlightRegion[] = [];
  rows.forEach((row, n) => {
    const place = placeRow(row, scanView, vaSpanStart, useHexStore.getState().availableViews);
    if (place === null) return;
    const entry: AnnotationEntry = {
      id: `keyfinder:${n}`, kind: KEY_HIT_KIND, label: `${row.finder}: ${row.label}`,
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
export function paintKeyHits(regions: HighlightRegion[]): void {
  const hex = useHexStore.getState();
  const store = useKeyFinderStore.getState();
  const mine = new Set(store.painted);
  hex.setHighlightedRegions([...hex.highlightedRegions.filter((r) => !mine.has(r)), ...regions]);
  store.setPainted(regions);
}

/** Put the viewer on a hit: its view, the cursor, and the hit bytes selected. */
export function goToHit(row: KeyHitRow, scanView: string): boolean {
  const hex = useHexStore.getState();
  const place = placeOf(row, scanView);
  if (place === null) return false;
  if (place.view !== hex.viewMode) hex.showView(place.view);
  hex.scrollToOffset(place.offset);
  hex.selectRange(place.offset, place.offset + Math.max(row.length, 1) - 1);
  return true;
}

const CIPHER_OF_BITS: Record<number, string> = { 128: "AES-128-CBC", 256: "AES-256-CBC" };

/** The key's own span inside a hit: the finder's `key_offset` + key size, else the whole hit. */
export function keySpanOf(row: KeyHitRow): { addr: WireInt; length: number } {
  const keyOffset = row.metadata.key_offset;
  const bits = row.metadata.key_bits;
  if (wireIntToBigInt(keyOffset) !== null && typeof bits === "number" && bits % 8 === 0) {
    return { addr: keyOffset as WireInt, length: bits / 8 };
  }
  return { addr: row.addr, length: row.length };
}

/**
 * Hand a hit to the Verify Key flow: select the key's bytes (the verifier prefills its
 * offset/length from the selection), pre-pick the cipher from the key size, and ask the
 * workspace to open the Verify Key tab.
 */
export function handOffToVerification(row: KeyHitRow, scanView: string): boolean {
  const span = keySpanOf(row);
  const hex = useHexStore.getState();
  const place = placeOf(row, scanView);
  const hitAddr = wireIntToBigInt(row.addr);
  const keyAddr = wireIntToBigInt(span.addr);
  if (place === null || hitAddr === null || keyAddr === null) return false;
  // The key sits `keyAddr - hitAddr` bytes into the hit: exact BigInt delta, small Number.
  const offset = place.offset + Number(keyAddr - hitAddr);
  if (!isOffset(offset)) return false;
  if (place.view !== hex.viewMode) hex.showView(place.view);
  hex.scrollToOffset(offset);
  hex.selectRange(offset, offset + span.length - 1);
  const cipher = CIPHER_OF_BITS[Number(row.metadata.key_bits)];
  if (cipher) useVerificationStore.getState().setCipher(cipher);
  useKeyFinderStore.getState().requestVerifyTab();
  return true;
}
