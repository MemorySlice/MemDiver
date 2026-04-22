import { test, expect } from "@playwright/test";
import { datasetAvailable } from "../fixtures/dataset";
import {
  TABS,
  seedMode,
  writeBaselineMerge,
  diffAgainstBaseline,
  navigateToTab,
} from "../fixtures/a11y";

test.describe("a11y: every icon-only button has an accessible name", () => {
  test.skip(!datasetAvailable, "Dataset not present; cannot mount workspace.");

  for (const t of TABS) {
    test(`${t.id}`, async ({ page }) => {
      await navigateToTab(page, t);

      const offenders = await page.evaluate(() => {
        const bad: string[] = [];
        const seen = new Set<string>();
        document.querySelectorAll<HTMLButtonElement>("button:not([aria-label])").forEach((b) => {
          const text = (b.textContent ?? "").replace(/\s+/g, " ").trim();
          const hasLabelledBy = !!b.getAttribute("aria-labelledby");
          const hasTitle = !!b.getAttribute("title");
          const hasImgAlt = !!b.querySelector("img[alt]:not([alt=''])");
          if (text.length >= 2 || hasLabelledBy || hasTitle || hasImgAlt) return;
          const snippet = b.outerHTML.slice(0, 140).replace(/\s+/g, " ");
          if (!seen.has(snippet)) {
            seen.add(snippet);
            bad.push(snippet);
          }
        });
        return bad;
      });

      const sorted = offenders.sort();

      if (seedMode()) {
        writeBaselineMerge("accessibleName", t.id, sorted);
        return;
      }

      const { newHits } = diffAgainstBaseline(sorted, "accessibleName", t.id);
      expect(
        newHits,
        `Nameless button(s) on '${t.id}' tab. Add aria-label, visible text, or aria-labelledby.\n  ${newHits.join("\n  ")}`,
      ).toEqual([]);
    });
  }
});
