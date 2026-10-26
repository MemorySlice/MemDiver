import { getVasNavigationMap } from "@/api/vol3";
import type { PageStateInterval } from "@/api/types";
import { useHexStore, type HexViewMode } from "@/stores/hex-store";

/** A hex selection expressed in the view's own address space (never a rounded number). */
export type SelectionAddress =
  | { ok: true; address: bigint; length: number }
  | { ok: false; hint: "noSelection" | "rawView" | "inexactSpan" | "notCaptured" | "unavailable" };

const refuse = (hint: Exclude<SelectionAddress, { ok: true }>["hint"]): SelectionAddress =>
  ({ ok: false, hint });

/** The address of packed (`vas`) offset `offset`: the CAPTURED interval that holds it. */
function addressOfVasOffset(offset: number, intervals: readonly PageStateInterval[]): bigint | null {
  for (const iv of intervals) {
    if (iv.state !== "CAPTURED" || iv.vas_offset === undefined) continue;
    if (offset >= iv.vas_offset && offset < iv.vas_offset + iv.length) {
      return BigInt(iv.va) + BigInt(offset - iv.vas_offset);
    }
  }
  return null;
}

async function intervalsOf(viewPath: string): Promise<PageStateInterval[] | null> {
  try {
    return (await getVasNavigationMap(viewPath)).regions.flatMap((r) => r.intervals);
  } catch {
    return null;
  }
}

/**
 * Where the current hex selection starts, in the active view's native address space.
 *
 * `va` view: span start + offset, only while the span start is an exact number (a kernel VA
 * is past 2^53 and arrives rounded — then the client refuses instead of computing a wrong
 * coordinate). `vas` view: the page-state interval holding the packed offset. A flat file
 * (one view) addresses by file offset. `raw` of a multi-view dump has no address map.
 */
export async function selectionAddress(viewPath: string): Promise<SelectionAddress> {
  const hex = useHexStore.getState();
  const sel = hex.selection;
  if (sel === null) return refuse("noSelection");
  const start = Math.min(sel.anchor, sel.active);
  const length = Math.abs(sel.active - sel.anchor) + 1;
  const mode: HexViewMode = hex.viewMode;
  if (hex.availableViews.length <= 1) return { ok: true, address: BigInt(start), length };
  if (mode === "raw") return refuse("rawView");
  if (mode === "va") {
    return Number.isSafeInteger(hex.vaSpanStart)
      ? { ok: true, address: BigInt(hex.vaSpanStart) + BigInt(start), length }
      : refuse("inexactSpan");
  }
  const intervals = await intervalsOf(viewPath);
  if (intervals === null) return refuse("unavailable");
  const address = addressOfVasOffset(start, intervals);
  return address === null ? refuse("notCaptured") : { ok: true, address, length };
}
