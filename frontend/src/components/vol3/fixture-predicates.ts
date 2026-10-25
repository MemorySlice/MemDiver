import type { Vol3Predicate } from "@/api/vol3";

export type PredicateKind = "min_rows" | "max_rows" | "row_where" | "column_all";
export const PREDICATE_KINDS: readonly PredicateKind[] = ["min_rows", "max_rows", "row_where", "column_all"];
export const COLUMN_OPS = ["==", "!=", "<", "<=", ">", ">=", "contains"] as const;

export interface PredicateDraft {
  kind: PredicateKind;
  count: string;      // min_rows / max_rows bound, row_where count_at_least
  column: string;     // row_where / column_all
  value: string;      // row_where / column_all
  op: string;         // column_all
}

export const emptyPredicateDraft = (): PredicateDraft =>
  ({ kind: "min_rows", count: "", column: "", value: "", op: "==" });

/** A numeric-looking text becomes a number so ordering ops compare as numbers. */
export const coerceValue = (text: string): string | number => {
  const trimmed = text.trim();
  return trimmed !== "" && Number.isFinite(Number(trimmed)) ? Number(trimmed) : text;
};

const bound = (text: string): number | null => {
  const n = Number(text.trim());
  return text.trim() !== "" && Number.isInteger(n) && n >= 0 ? n : null;
};

export type PredicateBuild = { ok: true; predicate: Vol3Predicate } | { ok: false; error: string };

/** The wire predicate for a draft, or the i18n key (under `editor.fixtures.error`) of what is missing. */
export function buildPredicate(d: PredicateDraft): PredicateBuild {
  if (d.kind === "min_rows" || d.kind === "max_rows") {
    const n = bound(d.count);
    return n === null ? { ok: false, error: "count" } : { ok: true, predicate: { [d.kind]: n } };
  }
  if (d.column.trim() === "" || d.value.trim() === "") return { ok: false, error: "columnValue" };
  if (d.kind === "row_where") {
    const predicate: Vol3Predicate = { row_where: { [d.column.trim()]: coerceValue(d.value) } };
    if (d.count.trim() !== "") {
      const n = bound(d.count);
      if (n === null) return { ok: false, error: "count" };
      predicate.count_at_least = n;
    }
    return { ok: true, predicate };
  }
  return { ok: true, predicate: {
    column_all: { column: d.column.trim(), op: d.op, value: coerceValue(d.value) } } };
}

/** One-line human text of a stored predicate (for the fixture list). */
export const describePredicate = (p: Vol3Predicate): string => JSON.stringify(p);
