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

test.describe("a11y: axe-core (WCAG 2.0 A/AA, critical+serious only)", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present; cannot mount workspace.");

  for (const t of TABS) {
    test(`${t.id}`, async ({ page }) => {
      await navigateToTab(page, t);

      // color-contrast (SC 1.4.3) is deliberately NOT disabled. It used to be,
      // which meant the single most common a11y defect in this app was the one
      // rule 17 green tabs were never checking -- the muted text token sat at
      // 2.9-3.3:1 everywhere and nothing said so. It is on here, on every tab,
      // in the same ratchet as the rest.
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();

      const violations = results.violations
        .filter((v) => v.impact === "critical" || v.impact === "serious")
        .flatMap((v) => v.nodes.map((n) => `${v.id}#${n.target.join(" ")}`))
        .sort();

      // The per-rule tally rides along in the guard message. Without it a trip
      // reports only a number, and a number cannot tell you whether 200+ hits
      // are one mid-render rule firing on every row of a grid or genuine debt.
      const byRule = results.violations
        .filter((v) => v.impact === "critical" || v.impact === "serious")
        .map((v) => `${v.id}:${v.nodes.length}`)
        .join(", ");
      // A guard trip prints the distinct failure signatures, deduplicated and
      // counted. A burst is almost always ONE defect multiplied by the number
      // of nodes it lands on, and the signature is what tells you which.
      if (violations.length > PER_TAB_GUARD) {
        const sigs = new Map<string, { n: number; ex: string }>();
        for (const v of results.violations) {
          for (const n of v.nodes) {
            const key = `${v.id} ${(n.failureSummary ?? "").replace(/\s+/g, " ").slice(0, 180)}`;
            const cur = sigs.get(key) ?? { n: 0, ex: n.target.join(" ") };
            cur.n += 1;
            sigs.set(key, cur);
          }
        }
        // eslint-disable-next-line no-console
        console.log(
          `axe burst on '${t.id}':\n` +
            [...sigs].map(([k, v]) => `  x${v.n}  ${k}\n        e.g. ${v.ex}`).join("\n"),
        );
      }

      expect(
        violations.length,
        `Guard: > ${PER_TAB_GUARD} critical+serious axe hits suggests misconfiguration, not real a11y debt. Tally: ${byRule}`,
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
