import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { Page } from "@playwright/test";
import { tab } from "./selectors";
import { enterWorkspaceWithMsl, switchToExplorationMode } from "./workspace";

export interface TabDef {
  id: string;
  kind: "side" | "bottom";
  exploration?: boolean;
}

export const TABS: TabDef[] = [
  { id: "bookmarks", kind: "side" },
  { id: "dumps", kind: "side" },
  { id: "format", kind: "side" },
  { id: "structures", kind: "side" },
  { id: "sessions", kind: "side" },
  { id: "import", kind: "side" },
  { id: "analysis", kind: "bottom" },
  { id: "results", kind: "bottom" },
  { id: "strings", kind: "bottom" },
  { id: "verify-key", kind: "bottom" },
  { id: "pipeline", kind: "bottom" },
  { id: "entropy", kind: "bottom", exploration: true },
  { id: "consensus", kind: "bottom", exploration: true },
  { id: "live-consensus", kind: "bottom", exploration: true },
  { id: "architect", kind: "bottom", exploration: true },
  { id: "experiment", kind: "bottom", exploration: true },
  { id: "convergence", kind: "bottom", exploration: true },
];

const BASELINE_PATH = path.resolve(__dirname, "a11y-baseline.json");

type BaselineKey = "axe" | "focusRing" | "accessibleName";
type Baseline = { [K in BaselineKey]?: Record<string, string[]> };

export function seedMode(): boolean {
  return process.env.A11Y_SEED === "1";
}

export function loadBaseline(): Baseline {
  if (!existsSync(BASELINE_PATH)) return {};
  try {
    return JSON.parse(readFileSync(BASELINE_PATH, "utf8")) as Baseline;
  } catch {
    return {};
  }
}

export function writeBaselineMerge(key: BaselineKey, tabId: string, values: string[]): void {
  const data = loadBaseline();
  if (!data[key]) data[key] = {};
  data[key]![tabId] = values;
  writeFileSync(BASELINE_PATH, JSON.stringify(data, null, 2) + "\n");
}

/**
 * Fail the test iff `actual` contains entries not present in the baseline
 * slice for this key+tab. New entries are new violations — that's the ratchet.
 */
export function diffAgainstBaseline(
  actual: string[],
  key: BaselineKey,
  tabId: string,
): { newHits: string[]; removedHits: string[] } {
  const data = loadBaseline();
  const baseline = new Set(data[key]?.[tabId] ?? []);
  const actualSet = new Set(actual);
  const newHits = actual.filter((a) => !baseline.has(a));
  const removedHits = [...baseline].filter((b) => !actualSet.has(b));
  return { newHits, removedHits };
}

export async function navigateToTab(page: Page, t: TabDef): Promise<void> {
  await enterWorkspaceWithMsl(page);
  if (t.exploration) await switchToExplorationMode(page);
  await page.locator(tab(t.id)).first().click();
  await page.waitForTimeout(400);
}
