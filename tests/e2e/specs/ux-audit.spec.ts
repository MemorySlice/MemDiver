import { test } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

type TabKind = "side" | "bottom";
type TabSpec = { id: string; kind: TabKind; exploration?: boolean };

const TABS: readonly TabSpec[] = [
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

type Findings = {
  tab: string;
  headingVisible: boolean;
  loadingOrEmpty: "loading" | "empty" | "neither";
  alertPresent: boolean;
  focusRingOk: "yes" | "no" | "unknown";
};

test.describe("UX audit across all tabs", () => {
  test.skip(!datasetAvailable, "Dataset not present.");
  test("screenshot + observe each tab", async ({ page }) => {
    test.setTimeout(180_000);
    const outDir = path.resolve(
      __dirname,
      "..",
      "playwright-report",
      "ux-screenshots",
    );
    mkdirSync(outDir, { recursive: true });

    await enterWorkspaceWithMsl(page);
    await switchToExplorationMode(page);

    const findings: Findings[] = [];

    for (const t of TABS) {
      await page.locator(tab(t.id)).first().click();
      await page.waitForTimeout(600);

      const headingVisible = await page
        .locator("h1, h2, h3, h4, [class*='font-semibold']")
        .first()
        .isVisible()
        .catch(() => false);

      const loadingText = await page
        .getByText(/loading|please wait/i)
        .first()
        .isVisible()
        .catch(() => false);
      const emptyText = await page
        .getByText(/no |empty|none|not (yet )?loaded|load a /i)
        .first()
        .isVisible()
        .catch(() => false);
      const loadingOrEmpty: Findings["loadingOrEmpty"] = loadingText
        ? "loading"
        : emptyText
          ? "empty"
          : "neither";

      const alertPresent = await page
        .locator("[role=alert]")
        .first()
        .isVisible()
        .catch(() => false);

      // Focus-ring check: press Tab a couple of times and see if any
      // element matches :focus-visible with a visible outline/ring.
      let focusRingOk: Findings["focusRingOk"] = "unknown";
      try {
        await page.keyboard.press("Tab");
        await page.keyboard.press("Tab");
        const hasRing = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el) return false;
          const cs = window.getComputedStyle(el);
          const outlineMeaningful =
            cs.outlineStyle !== "none" &&
            cs.outlineWidth !== "0px" &&
            cs.outlineColor !== "transparent";
          const shadowHasRing = /rgba?\(/.test(cs.boxShadow);
          return outlineMeaningful || shadowHasRing;
        });
        focusRingOk = hasRing ? "yes" : "no";
      } catch {
        focusRingOk = "unknown";
      }

      const screenshotPath = path.join(outDir, `${t.id}.png`);
      await page.screenshot({ path: screenshotPath, fullPage: false });

      findings.push({
        tab: t.id,
        headingVisible,
        loadingOrEmpty,
        alertPresent,
        focusRingOk,
      });
    }

    // Persist raw JSON findings next to screenshots for the audit doc.
    writeFileSync(
      path.join(outDir, "findings.json"),
      JSON.stringify(findings, null, 2),
    );
  });
});
