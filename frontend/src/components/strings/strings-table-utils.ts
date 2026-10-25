import type { StringsTableRow, StringsView } from "@/api/strings";
import { placeRow } from "@/api/lossless-json";
import type { HexViewMode } from "@/stores/hex-store";

export type GotoResult = { ok: true; offset: number; view?: HexViewMode } | { ok: false; hint: string };

/** The strings-table `view` matching the hex viewer: a view it cannot show is not asked for. */
export function viewForHex(mode: HexViewMode, available: readonly HexViewMode[]): StringsView {
  if (!available.includes("va") && !available.includes("vas")) return "raw";
  return mode === "vas" && available.includes("vas") ? "vas" : "va";
}

/** The hex offset of a row, or why it cannot be placed in the viewer's current view. */
export function gotoOffset(
  row: StringsTableRow,
  tableView: StringsView,
  hexMode: HexViewMode,
  vaSpanStart: number,
): GotoResult {
  if (tableView !== "raw" && tableView !== hexMode) return { ok: false, hint: "strings.table.viewMismatch" };
  const place = placeRow(row, tableView, vaSpanStart);
  if (place === null) return { ok: false, hint: "strings.table.outOfView" };
  // A kernel VA is placed by the server's `vas_offset`, in the packed view.
  return place.view === tableView ? { ok: true, offset: place.offset }
    : { ok: true, offset: place.offset, view: place.view };
}

/** Case-insensitive substring match; an empty query keeps every row. */
export function searchRows(rows: StringsTableRow[], query: string): StringsTableRow[] {
  if (!query) return rows;
  const needle = query.toLowerCase();
  return rows.filter((r) => r.value.toLowerCase().includes(needle));
}

export interface ValuePart {
  text: string;
  match: boolean;
}

/** `value` split into alternating plain / matching parts for highlighting. */
export function highlightParts(value: string, query: string): ValuePart[] {
  if (!query) return [{ text: value, match: false }];
  const lower = value.toLowerCase();
  const needle = query.toLowerCase();
  const parts: ValuePart[] = [];
  let at = 0;
  for (let hit = lower.indexOf(needle); hit >= 0; hit = lower.indexOf(needle, at)) {
    if (hit > at) parts.push({ text: value.slice(at, hit), match: false });
    parts.push({ text: value.slice(hit, hit + needle.length), match: true });
    at = hit + needle.length;
  }
  if (at < value.length) parts.push({ text: value.slice(at), match: false });
  return parts;
}
