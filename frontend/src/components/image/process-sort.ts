import type { ProcessRow } from "@/api/image";

export type ProcessSortKey = "pid" | "comm";

/** Filter by pid / name substring, then sort. Pure, so it is unit-testable. */
export function filterAndSort(
  rows: readonly ProcessRow[], filter: string, key: ProcessSortKey, desc: boolean,
): ProcessRow[] {
  const needle = filter.trim().toLowerCase();
  const kept = needle
    ? rows.filter((r) => String(r.pid).includes(needle) || r.comm.toLowerCase().includes(needle))
    : [...rows];
  kept.sort((a, b) => (key === "pid" ? a.pid - b.pid : a.comm.localeCompare(b.comm)));
  return desc ? kept.reverse() : kept;
}
