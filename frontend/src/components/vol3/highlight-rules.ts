/**
 * Declarative highlight rules for result tables: `table` (plugin) + `column` +
 * `op` + `value` -> a style. Pure data and pure matching, so a rule can be
 * stored in the analysis record as the payload of a `table_rule` entry.
 */
import type { Vol3Column, Vol3Row } from "@/api/vol3";
import type { RecordEntry } from "@/api/annotations";

export const RULE_OPS = ["eq", "ne", "lt", "gt", "contains", "regex", "in"] as const;
export const RULE_STYLES = ["danger", "warn", "info", "ok"] as const;
export type RuleOp = (typeof RULE_OPS)[number];
export type RuleStyle = (typeof RULE_STYLES)[number];
export type RuleValue = string | number | string[];

/** The analysis-record entry kind that stores a user rule. */
export const TABLE_RULE_KIND = "table_rule";

export interface RuleCondition {
  column: string;
  op: RuleOp;
  value: RuleValue;
}

export interface HighlightRule extends RuleCondition {
  id: string;
  /** Plugin name or a dotted suffix of it (`pslist`, `proc.Maps`); `*` = every table. */
  table: string;
  style: RuleStyle;
  /** Further conditions that must ALL hold on the same row (a rule over two columns). */
  also?: RuleCondition[];
}

/** A rule loaded from the record: `entryId` is what retracting it needs. */
export interface StoredRule extends HighlightRule {
  entryId: string;
}

/** Strongest first: a row matching several rules shows the most severe one. */
const SEVERITY: Record<RuleStyle, number> = { danger: 3, warn: 2, info: 1, ok: 0 };

export const DEFAULT_RULES: readonly HighlightRule[] = [
  { id: "default:maps-wx", table: "proc.Maps", column: "Flags", op: "regex",
    value: "(?=.*w)(?=.*x)", style: "danger" },
  { id: "default:maps-anon-x", table: "proc.Maps", column: "File Path", op: "eq", value: "",
    also: [{ column: "Flags", op: "contains", value: "x" }], style: "warn" },
  { id: "default:pslist-dead", table: "pslist", column: "EXIT_STATE", op: "eq",
    value: "EXIT_DEAD", style: "info" },
  { id: "default:psscan-dead", table: "psscan", column: "EXIT_STATE", op: "eq",
    value: "EXIT_DEAD", style: "info" },
];

const norm = (s: string) => s.trim().toLowerCase();

/** `pslist` matches `linux.pslist.PsList`: whole dotted segments, case-insensitive. */
export function tableMatches(table: string, plugin: string): boolean {
  if (table === "*") return true;
  return `.${norm(plugin)}.`.includes(`.${norm(table)}.`);
}

/** An absent cell reads as the empty string, so "File Path eq ''" finds anonymous mappings. */
const text = (cell: unknown) => (cell === null || cell === undefined ? "" : String(cell));

const numeric = (v: unknown): number | null => {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return null;
};

const regexCache = new Map<string, RegExp | null>();
function compiled(pattern: string): RegExp | null {
  if (!regexCache.has(pattern)) {
    try { regexCache.set(pattern, new RegExp(pattern)); } catch { regexCache.set(pattern, null); }
  }
  return regexCache.get(pattern) ?? null;
}

const same = (cell: unknown, value: unknown) => {
  const a = numeric(cell), b = numeric(value);
  return a !== null && b !== null ? a === b : text(cell) === text(value);
};

const valueList = (value: RuleValue): string[] =>
  Array.isArray(value) ? value : String(value).split(",").map((v) => v.trim());

/** Does one cell satisfy `op value`? An invalid regex or non-numeric `lt`/`gt` never matches. */
export function cellMatches(cell: unknown, op: RuleOp, value: RuleValue): boolean {
  switch (op) {
    case "eq": return same(cell, value);
    case "ne": return !same(cell, value);
    case "lt":
    case "gt": {
      const a = numeric(cell), b = numeric(value);
      if (a === null || b === null) return false;
      return op === "lt" ? a < b : a > b;
    }
    case "contains": return text(cell).includes(text(value));
    case "regex": return compiled(text(value))?.test(text(cell)) ?? false;
    case "in": return valueList(value).some((v) => same(cell, v));
  }
}

export interface RowMatch {
  rule: HighlightRule;
  style: RuleStyle;
  /** Columns whose cell tripped a condition (these get the cell marker). */
  columns: string[];
}

const columnAt = (columns: readonly Vol3Column[], name: string) =>
  columns.findIndex((c) => norm(c.name) === norm(name));

function conditionHolds(cond: RuleCondition, columns: readonly Vol3Column[], row: Vol3Row): boolean {
  const at = columnAt(columns, cond.column);
  return at >= 0 && cellMatches(row.values[at], cond.op, cond.value);
}

/** The most severe rule of `rules` that holds on this row of `plugin`'s table, else `null`. */
export function matchRow(
  rules: readonly HighlightRule[], plugin: string, columns: readonly Vol3Column[], row: Vol3Row,
): RowMatch | null {
  let best: RowMatch | null = null;
  for (const rule of rules) {
    if (!tableMatches(rule.table, plugin)) continue;
    const conds = [rule, ...(rule.also ?? [])];
    if (!conds.every((c) => conditionHolds(c, columns, row))) continue;
    if (best && SEVERITY[best.style] >= SEVERITY[rule.style]) continue;
    best = { rule, style: rule.style, columns: conds.map((c) => c.column) };
  }
  return best;
}

// -- persistence as analysis-record entries ---------------------------------

const isOp = (v: unknown): v is RuleOp => RULE_OPS.includes(v as RuleOp);
const isStyle = (v: unknown): v is RuleStyle => RULE_STYLES.includes(v as RuleStyle);
const isValue = (v: unknown): v is RuleValue =>
  typeof v === "string" || typeof v === "number" ||
  (Array.isArray(v) && v.every((x) => typeof x === "string"));

function parseCondition(raw: unknown): RuleCondition | null {
  const r = raw as Record<string, unknown> | null;
  if (!r || typeof r.column !== "string" || !isOp(r.op) || !isValue(r.value)) return null;
  return { column: r.column, op: r.op, value: r.value };
}

/** A stored entry as a rule; `null` when the payload is not a well-formed rule. */
export function ruleFromEntry(entry: RecordEntry): StoredRule | null {
  const p = entry.payload as Record<string, unknown> | null | undefined;
  const cond = parseCondition(p);
  if (!p || !cond || typeof p.table !== "string" || !isStyle(p.style)) return null;
  const also = Array.isArray(p.also) ? p.also.map(parseCondition) : [];
  if (also.includes(null)) return null;
  return {
    ...cond, id: typeof p.id === "string" ? p.id : entry.id, table: p.table, style: p.style,
    ...(also.length ? { also: also as RuleCondition[] } : {}), entryId: entry.id,
  };
}

export const rulesFromEntries = (entries: readonly RecordEntry[]): StoredRule[] =>
  entries.filter((e) => e.kind === TABLE_RULE_KIND)
    .map(ruleFromEntry).filter((r): r is StoredRule => r !== null);

/** The `payload` that stores `rule` (no locations are needed). */
export const rulePayload = (rule: HighlightRule): Record<string, unknown> => ({ ...rule });

/** Editor input: split a comma list for `in`, keep numbers as text for the matcher. */
export const parseRuleValue = (op: RuleOp, raw: string): RuleValue =>
  op === "in" ? raw.split(",").map((v) => v.trim()).filter((v) => v !== "") : raw;

/** `true` when `regex` text compiles (the editor refuses a rule that could never match). */
export const isValidRegex = (pattern: string) => {
  try { new RegExp(pattern); return true; } catch { return false; }
};
