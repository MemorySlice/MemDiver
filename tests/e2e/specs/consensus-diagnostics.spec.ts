/**
 * The consensus `classification_basis_mixed` diagnostic renders as a
 * LOCALIZED banner in the dump list's consensus section.
 *
 * A real mixed-basis build needs both legacy and freshly imported dumps, so
 * (like consensus-overlay.spec.ts) the build result is injected through the
 * DEV-only `window.__useConsensusStore` hook. This covers the store field ->
 * DumpList -> ClassificationBasisBanner -> i18n path end-to-end.
 */
import { test, expect, type Page } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, switchToExplorationMode } from "../fixtures/workspace";

const BANNER = '[data-testid="classification-basis-warning"][data-scope="consensus"]';

const MIXED = {
  code: "classification_basis_mixed",
  message: "BACKEND ENGLISH MESSAGE",
  severity: "warning",
  details: { named_dumps: [0], stored_type_dumps: [1], total_dumps: 2, remedy: "re-import" },
};

async function setConsensusDiagnostics(page: Page, diagnostics: unknown[]): Promise<void> {
  await page.evaluate((diags) => {
    const store = (window as unknown as {
      __useConsensusStore: { setState: (s: Record<string, unknown>) => void };
    }).__useConsensusStore;
    store.setState({
      available: true,
      loading: false,
      error: null,
      counts: { invariant: 1 },
      diagnostics: diags,
    });
  }, diagnostics);
}

test.describe("Consensus classification-basis banner", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset MSL fixture not present.");
  test.setTimeout(120_000);

  test("renders the localized body + hint, and disappears with no diagnostics", async ({
    page,
  }) => {
    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);
    // DumpList (and its consensus section) lives on the sidebar's Dumps tab.
    await page.locator(tab("dumps")).first().click();

    await setConsensusDiagnostics(page, [MIXED]);
    const banner = page.locator(BANNER);
    await expect(banner).toBeVisible();
    await expect(banner.getByTestId("classification-basis-body")).toContainText(
      "1 of 2 dumps are classified by mapping names, 1 by stored region type only.",
    );
    await expect(banner.getByTestId("classification-basis-hint")).toHaveText(
      "Re-import older dumps to classify them by mapping names.",
    );
    await expect(banner).not.toContainText("BACKEND ENGLISH MESSAGE");

    await setConsensusDiagnostics(page, []);
    await expect(page.locator(BANNER)).toHaveCount(0);
  });
});
