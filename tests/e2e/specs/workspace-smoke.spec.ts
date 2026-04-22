import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  installErrorGuards,
} from "../fixtures/workspace";

type SideTab =
  | "bookmarks"
  | "dumps"
  | "format"
  | "structures"
  | "sessions"
  | "import";

type BottomTab =
  | "analysis"
  | "results"
  | "strings"
  | "entropy"
  | "consensus"
  | "live-consensus"
  | "architect"
  | "experiment"
  | "convergence"
  | "verify-key"
  | "pipeline";

const SIDE_TABS: readonly SideTab[] = [
  "bookmarks",
  "dumps",
  "format",
  "structures",
  "sessions",
  "import",
] as const;

// Note: in "verification" mode only a subset of bottom tabs is
// rendered. The store boots with mode="verification" so only these
// show up in the UI. The remaining bottom tabs are covered by
// separate exploration-mode specs (future scope).
const BOTTOM_TABS_VERIFICATION: readonly BottomTab[] = [
  "analysis",
  "results",
  "strings",
  "verify-key",
  "pipeline",
] as const;

test.describe("workspace tab smoke", () => {
  test.skip(
    !datasetAvailable,
    "Dataset not present on this machine; set MEMDIVER_DATASET or provide run_0001 MSL.",
  );

  test("every visible tab renders without console errors or 5xx", async ({
    page,
  }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page);

    for (const name of SIDE_TABS) {
      const selector = tab(name);
      await page.locator(selector).first().click();
      await expect(page.locator(selector).first()).toBeVisible();
    }

    for (const name of BOTTOM_TABS_VERIFICATION) {
      const selector = tab(name);
      await page.locator(selector).first().click();
      await expect(page.locator(selector).first()).toBeVisible();
    }

    guards.assertClean();
  });
});
