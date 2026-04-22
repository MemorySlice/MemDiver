import { test, expect } from "@playwright/test";
import { datasetAvailable } from "../fixtures/dataset";
import {
  TABS,
  seedMode,
  writeBaselineMerge,
  diffAgainstBaseline,
  navigateToTab,
} from "../fixtures/a11y";

const MAX_TABS = 30;

test.describe("a11y: visible focus ring on keyboard-focusable elements", () => {
  test.skip(!datasetAvailable, "Dataset not present; cannot mount workspace.");

  for (const t of TABS) {
    test(`${t.id}`, async ({ page }) => {
      await navigateToTab(page, t);

      // Anchor keyboard focus into the document by focusing <body>, then Tab
      // repeatedly — this is what triggers :focus-visible (programmatic
      // .focus() doesn't fire the pseudo-class in headless chromium).
      await page.evaluate(() => (document.body as HTMLElement).focus());

      const offenders: string[] = [];
      for (let i = 0; i < MAX_TABS; i++) {
        await page.keyboard.press("Tab");
        const result = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return { skip: true };
          if (el.matches(".no-focus-ring, [data-virtualized-row]")) return { skip: true };
          if ((el as HTMLButtonElement).disabled) return { skip: true };
          const cs = getComputedStyle(el);
          if (cs.display === "none" || cs.visibility === "hidden") return { skip: true };
          const hasOutline =
            cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) > 0;
          const hasRingShadow = /rgba?\(|\bring/.test(cs.boxShadow);
          const label =
            el.getAttribute("data-testid") ||
            el.getAttribute("aria-label") ||
            el.tagName.toLowerCase() + (el.textContent?.trim().slice(0, 30) ?? "");
          return {
            skip: false,
            label,
            visible: hasOutline || hasRingShadow,
          };
        });
        if ((result as { skip: boolean }).skip) continue;
        const r = result as { skip: false; label: string; visible: boolean };
        if (!r.visible) offenders.push(r.label);
      }

      const unique = [...new Set(offenders)].sort();

      if (seedMode()) {
        writeBaselineMerge("focusRing", t.id, unique);
        return;
      }

      const { newHits } = diffAgainstBaseline(unique, "focusRing", t.id);
      expect(
        newHits,
        `New focus-ring offenders on '${t.id}' tab. Fix or re-seed.\n  ${newHits.join("\n  ")}`,
      ).toEqual([]);
    });
  }
});
