import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { MSL } from "./dataset";

/**
 * The FTUE store (frontend/src/ftue/store.ts) persists "seen" tours to
 * localStorage under this key. Pre-seeding it with entries whose
 * `version` matches the current tour versions makes `shouldShow()`
 * return false, so the driver.js overlay never mounts in the first
 * place. IDs + versions come directly from
 * frontend/src/ftue/tours/*.ts — bump here when those bump.
 */
const FTUE_STORAGE_KEY = "memdiver:ftue:seen";
const FTUE_SEEN_PAYLOAD = [
  { id: "workspace-layout-101", version: 1, seenAt: 0, completed: true },
  { id: "structure-overlay-101", version: 1, seenAt: 0, completed: true },
];

/**
 * Preemptively disable the FTUE tour before the app boots by seeding
 * localStorage via an init script. This runs before every navigation
 * on the page, so reloads and redirects stay covered.
 */
async function disableFtueViaStorage(page: Page): Promise<void> {
  const payload = JSON.stringify(FTUE_SEEN_PAYLOAD);
  await page.addInitScript(
    ({ key, value }) => {
      try {
        window.localStorage.setItem(key, value);
      } catch {
        /* localStorage unavailable — click-to-dismiss fallback will catch it */
      }
    },
    { key: FTUE_STORAGE_KEY, value: payload },
  );
}

/**
 * Fallback: if the driver.js overlay is present anyway (version bump,
 * storage disabled, race condition), close it by clicking the popover's
 * close button and wait for the overlay SVG to detach.
 */
async function dismissFtueIfPresent(page: Page): Promise<void> {
  const overlay = page.locator("svg.driver-overlay");
  try {
    // Quick probe — don't block the happy path.
    await overlay.first().waitFor({ state: "attached", timeout: 750 });
  } catch {
    return; // overlay never appeared — FTUE was suppressed.
  }

  const closeBtn = page
    .locator(".driver-popover .driver-popover-close-btn")
    .first();
  if (await closeBtn.isVisible().catch(() => false)) {
    await closeBtn.click();
  } else {
    // Last-ditch: press Escape (driver.js binds Esc to destroy).
    await page.keyboard.press("Escape");
  }

  await overlay.first().waitFor({ state: "detached", timeout: 5_000 });
}

/**
 * Drive the landing+wizard UI until the workspace is active for a
 * single-file MSL session. Tests then have the full workspace mounted
 * and can click the data-testid-marked tabs.
 *
 * Assumes the backend is up (playwright.config webServer handles that).
 */
export async function enterWorkspaceWithMsl(page: Page): Promise<void> {
  // Suppress the driver.js welcome tour before the app hydrates. The
  // init script fires on every nav; the post-mount sweep is a belt-and-
  // suspenders fallback for version drift.
  await disableFtueViaStorage(page);

  await page.goto("/");
  await dismissFtueIfPresent(page);
  // Landing -> Wizard
  await page.getByRole("button", { name: /New Session/i }).first().click();

  // Step 1: Select Data — fill the path input with the MSL file path.
  const pathInput = page.getByPlaceholder("Enter path to file or directory");
  await expect(pathInput).toBeVisible({ timeout: 15_000 });
  await pathInput.fill(MSL);

  // Click Next. The wizard validates via /api/path/info and advances
  // to the Analysis step (MSL is a single file so Directory Type is
  // skipped).
  await page.getByRole("button", { name: /^Next$/ }).click();

  // Wait for the "Start Analysis" button to appear (final step).
  const startBtn = page.getByRole("button", { name: /Start Analysis/i });
  await expect(startBtn).toBeVisible({ timeout: 20_000 });

  // Opt out of Auto-Analyze before starting the workspace. The default
  // "Auto-Analyze" approach kicks off a long-running backend analysis
  // on the 215 MB MSL file (via AnalysisPanel's auto-run effect) that
  // can wedge the backend for later specs. "Inspect Only" enters the
  // workspace without starting analysis; specs that need analysis can
  // trigger it explicitly via the Analysis panel.
  const inspectOnly = page
    .getByRole("button", { name: /^Inspect Only/i })
    .first();
  if (await inspectOnly.isVisible().catch(() => false)) {
    await inspectOnly.click();
  }

  await startBtn.click();

  // Workspace shell: toolbar contains "MemDiver" brand and the side
  // tabs render with data-testid="tab-*".
  await expect(page.locator('[data-testid="tab-bookmarks"]')).toBeVisible({
    timeout: 20_000,
  });

  // The workspace-layout tour auto-starts when the workspace mounts; even
  // with the init script above, a timing race (driver.js mounts before
  // the store reads localStorage) can still pop it. Sweep once more.
  await dismissFtueIfPresent(page);
}

/**
 * Switch the mode-banner to "exploration", which unlocks the
 * exploration-only bottom tabs (entropy, consensus, live-consensus,
 * architect, experiment, convergence). The banner is rendered by
 * `<ModeBanner/>` inside the BottomTabs panel; both modes are plain
 * buttons with capitalized labels. Call this after
 * `enterWorkspaceWithMsl` when the tab-under-test is exploration-only.
 */
export async function switchToExplorationMode(page: Page): Promise<void> {
  await page
    .getByRole("button", { name: /^exploration$/i })
    .first()
    .click();
}

/**
 * Lightweight console & response collector. Returns helpers to assert
 * absence of console errors / 5xx responses.
 */
export function installErrorGuards(page: Page) {
  const consoleErrors: string[] = [];
  const serverErrors: string[] = [];

  page.on("console", (msg) => {
    if (msg.type() === "error") {
      consoleErrors.push(msg.text());
    }
  });
  page.on("response", (resp) => {
    if (resp.status() >= 500) {
      serverErrors.push(`${resp.status()} ${resp.url()}`);
    }
  });

  return {
    consoleErrors,
    serverErrors,
    assertClean: () => {
      if (consoleErrors.length > 0) {
        throw new Error(
          `Unexpected console errors:\n  ${consoleErrors.join("\n  ")}`,
        );
      }
      if (serverErrors.length > 0) {
        throw new Error(
          `Unexpected 5xx responses:\n  ${serverErrors.join("\n  ")}`,
        );
      }
    },
  };
}
