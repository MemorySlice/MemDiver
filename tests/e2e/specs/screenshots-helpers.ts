import { existsSync, readFileSync } from "node:fs";
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

/**
 * Pre-computed gocryptfs n-sweep fixture for shots 09 and 10.
 *
 * Produced offline by `scripts/precompute_pipeline_fixtures.py` against
 * the gocryptfs reference dataset — commit the three JSONs under
 * tests/e2e/fixtures/pipeline/ so the screenshot tests don't need a
 * live 20-min compute.
 */
export const PIPELINE_FIXTURE_DIR = path.join(
  REPO_ROOT,
  "tests",
  "e2e",
  "fixtures",
  "pipeline",
);

export interface PipelineFixture {
  events: Array<Record<string, unknown>>;
  record: Record<string, unknown>;
  summary: Record<string, unknown>;
}

export function loadPipelineFixture(): PipelineFixture | null {
  const eventsPath = path.join(PIPELINE_FIXTURE_DIR, "nsweep_events.json");
  const recordPath = path.join(PIPELINE_FIXTURE_DIR, "run_record.json");
  const summaryPath = path.join(PIPELINE_FIXTURE_DIR, "summary.json");
  if (!existsSync(eventsPath) || !existsSync(recordPath)) return null;
  return {
    events: JSON.parse(readFileSync(eventsPath, "utf8")),
    record: JSON.parse(readFileSync(recordPath, "utf8")),
    summary: existsSync(summaryPath)
      ? JSON.parse(readFileSync(summaryPath, "utf8"))
      : {},
  };
}

/**
 * Route backend pipeline calls to a static mock record so PipelinePanel
 * doesn't reset the store when it tries to rehydrate a fixture taskId.
 * Must be called before navigation.
 */
export async function routePipelineToFixture(
  page: Page,
  taskId: string,
  fixture: PipelineFixture,
): Promise<void> {
  await page.route(`**/api/pipeline/runs/${taskId}`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ...fixture.record, task_id: taskId }),
    });
  });
  // Long-poll fallback (used by useTaskProgress when WS isn't
  // available) returns empty — we push events via evaluate() instead.
  await page.route(`**/api/tasks/${taskId}/events*`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ events: [] }),
    });
  });
}

/**
 * Drain a list of fixture events into the pipeline store via the
 * DEV-only window.__usePipelineStore hook. Must be called AFTER the app
 * has mounted (i.e., after the first navigation + wait).
 *
 * @param cutoffType  If set, events of that type and later are skipped.
 *                    Use "nsweep_point" to produce a "mid-run" state for
 *                    shot 09 (stages started, no n-sweep data yet).
 */
/**
 * Seed `settings.display.chartBackend` in the zustand-persisted
 * `memdiver-settings` key before the app hydrates, so the chart
 * dispatchers pick up the chosen renderer on first render.
 */
export async function primeChartBackend(
  page: Page,
  backend: "plotly" | "svg",
): Promise<void> {
  await page.addInitScript(
    ({ key, backend }) => {
      try {
        const existing = localStorage.getItem(key);
        const parsed = existing
          ? JSON.parse(existing)
          : { state: { display: {}, analysis: {}, general: {} }, version: 1 };
        parsed.state = parsed.state ?? {};
        parsed.state.display = {
          ...(parsed.state.display ?? {}),
          chartBackend: backend,
        };
        parsed.version = parsed.version ?? 1;
        localStorage.setItem(key, JSON.stringify(parsed));
      } catch {
        /* opaque origin */
      }
    },
    { key: "memdiver-settings", backend },
  );
}

export async function injectPipelineEvents(
  page: Page,
  events: Array<Record<string, unknown>>,
  cutoffType?: string,
): Promise<void> {
  const filtered = cutoffType
    ? events.slice(
        0,
        events.findIndex((e) => e.type === cutoffType) === -1
          ? events.length
          : events.findIndex((e) => e.type === cutoffType),
      )
    : events;
  await page.evaluate((evts) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const store = (window as any).__usePipelineStore;
    if (!store) return;
    for (const ev of evts) {
      try {
        store.getState().ingestEvent(ev);
      } catch {
        /* tolerate: malformed synthetic events never crash the app */
      }
    }
  }, filtered);
}
