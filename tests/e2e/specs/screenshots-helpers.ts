import { existsSync } from "node:fs";
import { mkdirSync } from "node:fs";
import path from "node:path";
import type { Page, ViewportSize } from "@playwright/test";

/**
 * Absolute path to docs/_static/screenshots/. Computed from this file's
 * location so it works regardless of cwd.
 */
export const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
export const STATIC_SHOTS = path.join(
  REPO_ROOT,
  "docs",
  "_static",
  "screenshots",
);
export const TRIPTYCH_WORKDIR = path.join(STATIC_SHOTS, ".triptych_parts");

export const VIEWPORT_DEFAULT: ViewportSize = { width: 1440, height: 900 };
export const VIEWPORT_HERO: ViewportSize = { width: 1920, height: 1080 };

export function ensureDirs(): void {
  mkdirSync(STATIC_SHOTS, { recursive: true });
  mkdirSync(TRIPTYCH_WORKDIR, { recursive: true });
}

/**
 * Seed localStorage BEFORE any page navigation so ThemeProvider picks up
 * the desired state during its initial render. Must be called before
 * `page.goto()`.
 */
export async function primeTheme(
  page: Page,
  theme: "light" | "dark",
  highContrast = false,
  mode: "exploration" | "verification" = "exploration",
): Promise<void> {
  await page.addInitScript(
    ({ theme, hc, mode }) => {
      try {
        localStorage.setItem("memdiver-theme", theme);
        localStorage.setItem("memdiver-high-contrast", String(hc));
        localStorage.setItem("memdiver-mode", mode);
      } catch {
        /* opaque origin, ignored */
      }
    },
    { theme, hc: highContrast, mode },
  );
}

/**
 * Suppress FTUE tour overlay before app mounts. Mirrors the payload
 * shape expected by frontend/src/ftue/store.ts. Duplicated here from
 * workspace.ts so tests that don't use enterWorkspaceWithMsl (e.g., the
 * landing shot) can still be overlay-free.
 */
export async function primeFtueSeen(page: Page): Promise<void> {
  const payload = JSON.stringify([
    { id: "workspace-layout-101", version: 1, seenAt: 0, completed: true },
    { id: "structure-overlay-101", version: 1, seenAt: 0, completed: true },
    { id: "pipeline-101", version: 1, seenAt: 0, completed: true },
  ]);
  await page.addInitScript(
    ({ key, value }) => {
      try {
        localStorage.setItem(key, value);
      } catch {
        /* ignore */
      }
    },
    { key: "memdiver:ftue:seen", value: payload },
  );
}

/**
 * Freeze time and RNG so Plotly tick labels, session timestamps, and
 * sparklines render identically across runs. Same strategy as
 * docs/screenshots/capture.py.
 */
export async function freezeClockAndRng(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const fixed = new Date("2026-04-21T12:00:00Z").getTime();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (Date as any).now = () => fixed;
    let s = 0x12345678 | 0;
    Math.random = () => {
      s = (s + 0x6d2b79f5) | 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  });
}

/**
 * Strip caret, animations, scrollbars so pixels are stable even under
 * webkit font-hinting quirks.
 */
export async function injectStableStyles(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        caret-color: transparent !important;
      }
      ::-webkit-scrollbar { display: none; }
      * { scrollbar-width: none; }
    `,
  });
}

/**
 * Force the hex viewer into "raw" mode for every test. The viewMode
 * is persisted to localStorage under `memdiver:hex:viewMode` (see
 * frontend/src/stores/hex-store.ts VIEW_MODE_KEY), so a previous
 * context that switched to VAS can poison this one — rows render as
 * `--` placeholders because the VAS mapping is sparse on MSL files
 * that were loaded with raw data. Seeding "raw" before hydration
 * guarantees a valid render path.
 */
export async function primeHexRawMode(page: Page): Promise<void> {
  await page.addInitScript(() => {
    try {
      localStorage.setItem("memdiver:hex:viewMode", "raw");
    } catch {
      /* ignore */
    }
  });
}

/**
 * Block until the first hex row has real bytes (not `--` placeholders).
 * The `data-index="0"` wrapper exists as soon as the virtualiser mounts,
 * but the chunk fetch is still in-flight; bytes only become real when
 * the `.hex-byte` span loses its `.hex-loading` class. Wait for ≥4
 * loaded bytes to tolerate partial prefetch.
 */
export async function waitForHexBytes(
  page: Page,
  rowIndex = 0,
  timeout = 30_000,
): Promise<void> {
  await page.waitForSelector(`[data-index="${rowIndex}"]`, { timeout });
  await page
    .waitForFunction(
      (idx: number) => {
        const row = document.querySelector(`[data-index="${idx}"]`);
        if (!row) return false;
        return row.querySelectorAll(".hex-byte:not(.hex-loading)").length >= 4;
      },
      rowIndex,
      { timeout },
    )
    .catch(() => {
      /* capture whatever is rendered — don't hard-fail the screenshot */
    });
  // Let chunkVersion propagate through React memoization.
  await page.waitForTimeout(300);
}

/**
 * Shared pre-nav priming. Call this first, then page.goto(...).
 */
export async function primeAll(
  page: Page,
  opts: {
    theme: "light" | "dark";
    highContrast?: boolean;
    mode?: "exploration" | "verification";
  },
): Promise<void> {
  await primeTheme(
    page,
    opts.theme,
    opts.highContrast ?? false,
    opts.mode ?? "exploration",
  );
  await primeFtueSeen(page);
  await primeHexRawMode(page);
  await freezeClockAndRng(page);
}

/**
 * Take a screenshot to docs/_static/screenshots/<slug>.png.
 */
export async function takeShot(page: Page, slug: string): Promise<string> {
  ensureDirs();
  const file = path.join(STATIC_SHOTS, `${slug}.png`);
  await page.screenshot({
    path: file,
    fullPage: false,
    animations: "disabled",
    caret: "hide",
  });
  return file;
}

/**
 * Take a triptych intermediate into the workdir (not the final filename).
 */
export async function takeTriptychPart(
  page: Page,
  part: "light" | "dark" | "dark_hc",
): Promise<string> {
  ensureDirs();
  const file = path.join(TRIPTYCH_WORKDIR, `part_${part}.png`);
  await page.screenshot({ path: file, fullPage: false, caret: "hide" });
  return file;
}

/**
 * Six small fixture dumps used for Live Consensus uploads (shot 07).
 * These live at tests/fixtures/dataset/TLS13/... and are 512 bytes each.
 */
export function consensusFixtureDumps(): string[] {
  const base = path.join(
    REPO_ROOT,
    "tests",
    "fixtures",
    "dataset",
    "TLS13",
    "scenario_a",
    "boringssl",
    "boringssl_run_13_1",
  );
  const names = [
    "20240101_120000_000001_pre_handshake.dump",
    "20240101_120001_000002_post_handshake.dump",
    "20240101_120002_000003_pre_abort.dump",
    "20240101_120003_000004_post_abort.dump",
  ];
  return names
    .map((n) => path.join(base, n))
    .filter((p) => existsSync(p));
}
