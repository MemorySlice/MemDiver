import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";
import { datasetAvailable } from "../fixtures/dataset";
import {
  TABS,
  seedMode,
  writeBaselineMerge,
  diffAgainstBaseline,
  navigateToTab,
} from "../fixtures/a11y";

const PER_TAB_GUARD = 30;

test.describe("a11y: axe-core (WCAG 2.0 A/AA, critical+serious only)", () => {
  test.skip(!datasetAvailable, "Dataset not present; cannot mount workspace.");

  for (const t of TABS) {
    test(`${t.id}`, async ({ page }) => {
      await navigateToTab(page, t);

      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa"])
        .disableRules(["color-contrast"])
        .analyze();

      const violations = results.violations
        .filter((v) => v.impact === "critical" || v.impact === "serious")
        .flatMap((v) => v.nodes.map((n) => `${v.id}#${n.target.join(" ")}`))
        .sort();

      expect(
        violations.length,
        `Guard: > ${PER_TAB_GUARD} critical+serious axe hits suggests misconfiguration, not real a11y debt.`,
      ).toBeLessThanOrEqual(PER_TAB_GUARD);

      if (seedMode()) {
        writeBaselineMerge("axe", t.id, violations);
        return;
      }

      const { newHits } = diffAgainstBaseline(violations, "axe", t.id);
      expect(
        newHits,
        `New axe violations on '${t.id}' tab. Fix or re-seed via 'npm run test:a11y:seed':\n  ${newHits.join("\n  ")}`,
      ).toEqual([]);
    });
  }
});
