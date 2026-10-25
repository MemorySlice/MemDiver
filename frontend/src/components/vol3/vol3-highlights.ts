import type { PageStateInterval } from "@/api/types";
import type { Vol3QueryResult, Vol3RunResult } from "@/api/vol3";
import { applyAnnotations, type AnnotationEntry } from "@/utils/apply-hits";
import { useHexStore, type HighlightRegion } from "@/stores/hex-store";
import { cellToBigInt } from "./vol3-address";
import { resolveOffset, type AddressRef, type NavResolution, type ViewContext } from "./vol3-navigation";

/** The highlight kind of a plugin's rows: one palette slot per plugin. */
export const highlightKind = (plugin: string) => `vol3:${plugin}`;

const columnIndex = (result: Vol3RunResult, name: string) =>
  result.columns.findIndex((c) => c.name === name);

/** The row's pid, from a column named `pid` (the backend's own rule). */
export function rowPid(result: Vol3RunResult, row: number): number | null {
  const at = result.columns.findIndex((c) => c.name.trim().toLowerCase() === "pid");
  const value = at < 0 ? null : result.rows[row].values[at];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

/** One row's address cell as an {@link AddressRef}; `null` when absent or rounded. */
export function addressRef(result: Vol3RunResult, row: number, column: string): AddressRef | null {
  const at = columnIndex(result, column);
  const space = at < 0 ? null : result.columns[at].space;
  const value = space ? cellToBigInt(result.rows[row].values[at]) : null;
  return space && value !== null ? { value, space, pid: rowPid(result, row) } : null;
}

function labelOf(result: Vol3RunResult, row: number, labelColumn: string | null): string {
  const at = labelColumn === null ? -1 : columnIndex(result, labelColumn);
  const cell = at < 0 ? null : result.rows[row].values[at];
  return cell === null || cell === undefined ? `${result.plugin} #${row}` : String(cell);
}

/** A usable byte length: a positive safe integer, else `null` (caller paints one byte). */
export const positiveSize = (value: unknown): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;

export interface HighlightPlan {
  regions: HighlightRegion[];
  placed: number;
  /** Rows of the column that could not be placed (absent, other pid, unmapped...). */
  skipped: number;
  /** Why the first skipped row was skipped. */
  firstRefusal: NavResolution | null;
}

/**
 * Every row of one address column that can be placed in the current view, as
 * generic `vol3:<plugin>` highlight regions via {@link applyAnnotations}.
 */
export function planColumnHighlights(
  result: Vol3RunResult,
  column: string,
  ctx: ViewContext,
  intervals: readonly PageStateInterval[] | null,
  opts: { dumpPath?: string; labelColumn?: string | null } = {},
): HighlightPlan {
  const meta = result.columns[columnIndex(result, column)];
  const space = meta?.space ?? "";
  const length = positiveSize(meta?.object_size);
  const objectType = meta?.object_type;
  const entries: AnnotationEntry[] = [];
  let firstRefusal: NavResolution | null = null;
  let skipped = 0;
  for (let row = 0; row < result.rows.length; row += 1) {
    const ref = addressRef(result, row, column);
    const placed = ref ? resolveOffset(ref, ctx, intervals) : null;
    if (!ref || !placed || !placed.ok) {
      skipped += 1;
      firstRefusal ??= placed;
      continue;
    }
    entries.push({
      id: `${result.plugin}:${row}`, kind: highlightKind(result.plugin),
      label: objectType
        ? `${labelOf(result, row, opts.labelColumn ?? null)} (${objectType})`
        : labelOf(result, row, opts.labelColumn ?? null),
      ...(length !== null ? { length } : {}),
      locations: [{ space, value: Number(ref.value), offset: placed.offset }],
    });
  }
  const regions = applyAnnotations(entries, {
    space, toOffset: (loc) => loc.offset as number,
    view: ctx.mode, ...(opts.dumpPath !== undefined ? { dumpPath: opts.dumpPath } : {}),
  });
  return { regions, placed: regions.length, skipped, firstRefusal };
}

/** Paint `regions`, replacing this plugin's earlier highlights and keeping all others. */
export function paintPluginHighlights(plugin: string, regions: HighlightRegion[]): void {
  const hex = useHexStore.getState();
  const kind = highlightKind(plugin);
  hex.setHighlightedRegions([...hex.highlightedRegions.filter((r) => r.kind !== kind), ...regions]);
}

/** The highlight kind of "Send rows to highlights" from the query box. */
export const QUERY_HIGHLIGHT_PLUGIN = "query";

const queryColumn = (q: Vol3QueryResult, name: string) =>
  q.columns.findIndex((c) => c.trim().toLowerCase() === name);

/** Can these rows be placed? They need `addr` and `space` columns (`pid` qualifies process VAs). */
export const queryHasAddresses = (q: Vol3QueryResult) =>
  queryColumn(q, "addr") >= 0 && queryColumn(q, "space") >= 0;

/**
 * A case-query's rows as `vol3:query` highlight regions. Each row carries its own
 * `space`, so rows are translated one by one and painted per space; a row that
 * cannot be placed is counted and explained, never guessed.
 */
export function planQueryHighlights(
  q: Vol3QueryResult,
  ctx: ViewContext,
  intervals: readonly PageStateInterval[] | null,
  opts: { dumpPath?: string } = {},
): HighlightPlan {
  const addrAt = queryColumn(q, "addr"), spaceAt = queryColumn(q, "space"), pidAt = queryColumn(q, "pid");
  const sizeAt = queryColumn(q, "size");
  const bySpace = new Map<string, AnnotationEntry[]>();
  let firstRefusal: NavResolution | null = null;
  let skipped = 0;
  q.rows.forEach((row, n) => {
    const value = addrAt < 0 ? null : cellToBigInt(row[addrAt]);
    const space = spaceAt < 0 ? null : row[spaceAt];
    const pid = pidAt >= 0 && typeof row[pidAt] === "number" ? (row[pidAt] as number) : null;
    const placed = value !== null && typeof space === "string"
      ? resolveOffset({ value, space, pid }, ctx, intervals) : null;
    if (value === null || typeof space !== "string" || !placed || !placed.ok) {
      skipped += 1;
      firstRefusal ??= placed;
      return;
    }
    const list = bySpace.get(space) ?? [];
    const length = sizeAt < 0 ? null : positiveSize(row[sizeAt]);
    list.push({
      ...(length !== null ? { length } : {}),
      id: `query:${n}`, kind: highlightKind(QUERY_HIGHLIGHT_PLUGIN), label: `query #${n}`,
      locations: [{ space, value: Number(value), offset: placed.offset }],
    });
    bySpace.set(space, list);
  });
  const regions = [...bySpace].flatMap(([space, entries]) => applyAnnotations(entries, {
    space, toOffset: (loc) => loc.offset as number, view: ctx.mode,
    ...(opts.dumpPath !== undefined ? { dumpPath: opts.dumpPath } : {}),
  }));
  return { regions, placed: regions.length, skipped, firstRefusal };
}
