import { ApiError, readableFailure } from "@/api/client";
import { listYaraRules, putYaraRule } from "@/api/yara";

/** localStorage flag: set once the old browser-only rules have been dealt with. */
export const IMPORTED_FLAG = "memdiver.yara.rules.imported";

export interface ImportReport {
  imported: string[];
  /** Names already in the library: left untouched, never overwritten. */
  skipped: string[];
  /** Transient write failures (network): retried on the next mount. */
  failed: { name: string; error: string }[];
  /** Permanently unimportable (bad name, empty body, refused by the store): reported once, never retried. */
  invalid: { name: string; reason: string }[];
}

/** The store's rule-name grammar (`analysis/plugin_store.NAME_PATTERN`). */
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** A client-side refusal (4xx other than timeout/rate-limit) will fail the same way every time. */
const isPermanent = (e: unknown): boolean =>
  e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 408 && e.status !== 429;

/** Why a legacy entry can never be imported, or `null`. */
function invalidReason(name: string, body: string): string | null {
  if (!NAME_PATTERN.test(name)) return "invalid name";
  if (body.trim() === "") return "empty rule";
  return null;
}

export const STORAGE_KEY = "memdiver.yara.rules";

type RuleMap = Record<string, string>;

/**
 * Read the rules an earlier version kept in this browser; a missing, blocked or corrupt
 * store is simply empty. They now live in the backend store: this feeds the one-time
 * import below.
 */
export function readRules(): RuleMap {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>).filter(([, v]) => typeof v === "string"),
    ) as RuleMap;
  } catch {
    return {};
  }
}

const alreadyImported = (): boolean => {
  try { return localStorage.getItem(IMPORTED_FLAG) === "1"; } catch { return false; }
};

function markImported(): void {
  try { localStorage.setItem(IMPORTED_FLAG, "1"); } catch { /* blocked: harmless, nothing is overwritten */ }
}

// One run per page load even if several panels mount at once.
let inFlight: Promise<ImportReport | null> | null = null;

async function runImport(): Promise<ImportReport | null> {
  if (alreadyImported()) return null;
  const legacy = readRules();
  const names = Object.keys(legacy).sort();
  if (names.length === 0) { markImported(); return null; }
  const report: ImportReport = { imported: [], skipped: [], failed: [], invalid: [] };
  const existing = new Set((await listYaraRules()).rules.map((r) => r.name));
  for (const name of names) {
    const bad = invalidReason(name, legacy[name]);
    if (bad !== null) { report.invalid.push({ name, reason: bad }); continue; }
    if (existing.has(name)) { report.skipped.push(name); continue; }
    try {
      await putYaraRule(name, legacy[name], "library");
      report.imported.push(name);
    } catch (e) {
      if (isPermanent(e)) report.invalid.push({ name, reason: readableFailure(e) });
      else report.failed.push({ name, error: readableFailure(e) });
    }
  }
  // Only a transient failure keeps the import open (retried on the next mount, never
  // within this one): permanent failures are reported once and then count as dealt with.
  if (report.failed.length === 0) markImported();
  return report;
}

/**
 * One-time import of the rules an older version kept in this browser into the LIBRARY.
 * Returns `null` when there was nothing to do (already imported, no legacy rules, or the
 * backend could not be asked); otherwise what was imported, skipped (name already stored)
 * and failed. Existing stored rules are never overwritten and the legacy copies stay.
 */
export function importLocalRules(): Promise<ImportReport | null> {
  inFlight ??= runImport().catch(() => null).finally(() => { inFlight = null; });
  return inFlight;
}
