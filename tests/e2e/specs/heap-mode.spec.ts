import { test, expect, type Locator } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  glibcHeapExpectedPath,
  glibcHeapMslAvailable,
  glibcHeapMslPath,
  heapStackMslAvailable,
  heapStackMslPath,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

/**
 * Heap app mode: the third ModeBanner button adds the heap side tab, the heap
 * bottom panel and the hex-toolbar heap-layer toggle; leaving the mode takes
 * them away again.
 *
 * Only the UI chrome is asserted. What the allocator parser makes of the
 * small synthetic fixture (detected allocator, chunk count) is the backend's
 * business and covered by the Python heap tests, so a 4xx/5xx from
 * `/api/heap/*` on this fixture must not fail a spec about the mode switch.
 */
test.describe("heap mode", () => {
  test.skip(!heapStackMslAvailable, "heap_stack_msl fixture missing");

  test("entering heap mode shows the heap tabs, panel and layer toggle", async ({ page }) => {
    await enterWorkspaceWithMsl(page, heapStackMslPath);

    await page.getByTestId("mode-heap").click();
    await expect(page.getByTestId("mode-heap")).toHaveAttribute("aria-pressed", "true");

    // Toolbar mode badge (rendered uppercase by CSS; the text node is "heap").
    await expect(
      page.locator('[data-tour-id="workspace-toolbar"]').getByText("heap", { exact: true }),
    ).toBeVisible();

    // Side tab (heap overview) opens by default on entering the mode; the
    // bottom panel gains its own heap tab.
    await expect(page.getByTestId("tab-heap-overview")).toBeVisible();
    await expect(page.getByTestId("tab-heap")).toBeVisible();
    await expect(page.getByTestId("heap-overview")).toBeVisible({ timeout: 15_000 });

    // Bottom panel switches to the heap tab.
    await expect(page.getByTestId("heap-panel")).toBeVisible({ timeout: 15_000 });

    // The heap layer is on for the active dump.
    const toggle = page.getByTestId("heap-layer-toggle");
    await expect(toggle).toBeVisible({ timeout: 15_000 });
    await expect(toggle).toHaveAttribute("aria-pressed", "true");

    // Leaving heap mode removes the heap tabs and the toggle.
    await page.getByTestId("mode-exploration").click();
    await expect(page.getByTestId("tab-heap-overview")).toHaveCount(0);
    await expect(page.getByTestId("tab-heap")).toHaveCount(0);
    await expect(page.getByTestId("heap-panel")).toHaveCount(0);
    await expect(page.getByTestId("heap-layer-toggle")).toHaveCount(0);
  });
});

/**
 * Heap analysis on a dump that really holds an allocator heap.
 *
 * `glibc_heap_msl` carries the synthetic glibc ptmalloc2 `[heap]` from
 * tests/fixtures/synth_heap.py, and expected.json is that builder's chunk
 * oracle. Unlike the chrome-only spec above, every heap route must succeed
 * here: a 4xx/5xx from `/api/heap/*` fails the test.
 */
interface ExpectedChunk {
  va: number;
  size: number;
  state: string;
  header_len: number;
  bin: string | null;
}
interface ExpectedHeap {
  allocator: string;
  base_va: number;
  chunk_count: number;
  tcache_bins: string[];
  chunks: ExpectedChunk[];
}

const SCREENSHOT_DIR =
  process.env.HEAP_E2E_SCREENSHOT_DIR ??
  path.join(__dirname, "..", "test-results", "heap-e2e");

const HEAP_CELL = (cls: string) => `.hex-byte.${cls}`;

/** A chunk row's view offset, read from its Offset column ("0x…"; "--" = unmapped). */
async function rowViewOffset(row: Locator): Promise<number> {
  const text = (await row.locator("span").nth(1).textContent())?.trim() ?? "";
  expect(text, "chunk must map into the hex view").toMatch(/^0x[0-9a-f]+$/);
  return parseInt(text, 16);
}

test.describe("heap mode on a real glibc heap", () => {
  test.skip(!glibcHeapMslAvailable, "glibc_heap_msl fixture missing");

  test("ptmalloc2 analysis drives overview, chunk table, hex layer, histogram and free lists", async ({ page }) => {
    const expected: ExpectedHeap = JSON.parse(readFileSync(glibcHeapExpectedPath, "utf8"));
    const heapFailures: string[] = [];
    page.on("response", (res) => {
      if (res.url().includes("/api/heap/") && res.status() >= 400) {
        heapFailures.push(`${res.status()} ${res.url()}`);
      }
    });
    // Start in the light theme; the dark screenshot toggles it in-app.
    await page.addInitScript(() => {
      try {
        if (!sessionStorage.getItem("heap-e2e-theme-seeded")) {
          localStorage.setItem("memdiver-theme", "light");
          sessionStorage.setItem("heap-e2e-theme-seeded", "1");
        }
      } catch {
        /* storage unavailable: the screenshots just share a theme */
      }
    });

    await enterWorkspaceWithMsl(page, glibcHeapMslPath);
    await page.getByTestId("mode-heap").click();
    await expect(page.getByTestId("mode-heap")).toHaveAttribute("aria-pressed", "true");

    // Overview: detected allocator + confidence.
    const overview = page.getByTestId("heap-overview");
    await expect(overview).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("heap-allocator-badge")).toHaveText("glibc ptmalloc2", { timeout: 20_000 });
    await expect(page.getByTestId("heap-allocator-badges")).toContainText(/\d+% confidence/);
    await expect(page.getByTestId("heap-badge-heuristic")).toHaveCount(0);

    // Chunk table: every chunk of the oracle, in VA order.
    const panel = page.getByTestId("heap-panel");
    await expect(panel).toBeVisible();
    const rows = panel.getByTestId("heap-chunk-row");
    await expect(rows).toHaveCount(expected.chunk_count, { timeout: 15_000 });
    await expect(panel).toContainText(`${expected.chunk_count} chunks`);
    const vas = await rows.evaluateAll((els) => els.map((e) => Number(e.getAttribute("data-va"))));
    expect(vas).toEqual(expected.chunks.map((c) => c.va));

    // An .msl's raw view is the container, so heap mode shows the memory view.
    await expect(page.getByRole("tab", { name: "Memory (VAS)" })).toHaveAttribute("aria-selected", "true");
    const firstOffset = await rowViewOffset(rows.first());

    // Hex layer: the first chunk (tcache_perthread_struct) is allocator
    // metadata and carries the chunk-start tick on its first byte.
    const firstCell = page.locator(`.hex-byte[data-offset="${firstOffset}"]`);
    await expect(firstCell).toHaveClass(/heap-chunk-start/, { timeout: 15_000 });
    await expect(firstCell).toHaveClass(/heap-meta/);
    await expect(page.locator(HEAP_CELL("heap-chunk-start")).first()).toBeVisible();

    // Clicking a tcache'd chunk selects it and moves the hex cursor to its
    // first byte; its user data starts with the tcache `next` link.
    const cachedIdx = expected.chunks.findIndex((c) => c.state === "cached");
    const cached = expected.chunks[cachedIdx];
    const cachedOffset = await rowViewOffset(rows.nth(cachedIdx));
    await rows.nth(cachedIdx).click();
    await expect(rows.nth(cachedIdx)).toHaveAttribute("aria-selected", "true");
    const cachedCell = page.locator(`.hex-byte[data-offset="${cachedOffset}"]`);
    await expect(cachedCell).toHaveClass(/\bcursor\b/);
    await expect(cachedCell).toHaveClass(/heap-chunk-start/);
    await expect(cachedCell).toHaveClass(/heap-header/);
    await expect(
      page.locator(`.hex-byte[data-offset="${cachedOffset + cached.header_len}"]`),
    ).toHaveClass(/heap-freelink/);
    // The in-use chunk just before it shows user data on screen too.
    const inUseBefore = await rowViewOffset(rows.nth(cachedIdx - 1));
    await expect(
      page.locator(`.hex-byte[data-offset="${inUseBefore + expected.chunks[cachedIdx - 1].header_len}"]`),
    ).toHaveClass(/heap-user/);
    for (const cls of ["heap-header", "heap-user", "heap-freelink", "heap-chunk-start"]) {
      await expect(page.locator(HEAP_CELL(cls)).first()).toBeVisible();
    }

    // Inspector: ptmalloc header fields and the decoded size-word flags.
    const inspector = page.getByTestId("heap-inspector");
    await expect(page.getByTestId("heap-inspector-va")).toHaveText(`0x${cached.va.toString(16)}`);
    await expect(page.getByTestId("heap-inspector-flags")).toContainText("PREV_INUSE");
    await expect(inspector).toContainText(`Size${cached.size}`);
    await expect(inspector).toContainText(cached.bin ?? "");
    // NOTE: the ptmalloc2 parser (heap/allocators/ptmalloc2.py `_to_chunk`)
    // puts no prev_size/next/key into a chunk's `extra`, so the inspector's
    // "Allocator fields" section only appears for the tcache_perthread_struct
    // chunk. Assert that rendering there rather than a field the API lacks.
    await rows.first().click();
    const extra = page.getByTestId("heap-inspector-extra");
    await expect(extra.locator('[data-field="struct"]')).toContainText("tcache_perthread_struct");
    await rows.nth(cachedIdx).click();

    // The last (top) chunk sits far below the first screen: the row click
    // must scroll the hex view there.
    const lastIdx = expected.chunk_count - 1;
    const top = expected.chunks[lastIdx];
    const topOffset = await rowViewOffset(rows.nth(lastIdx));
    await rows.nth(lastIdx).click();
    const topCell = page.locator(`.hex-byte[data-offset="${topOffset}"]`);
    await expect(topCell).toBeInViewport();
    await expect(topCell).toHaveClass(/\bcursor\b/);
    await expect(topCell).toHaveClass(/heap-chunk-start/);
    await expect(page.getByTestId("heap-inspector-va")).toHaveText(`0x${top.va.toString(16)}`);
    await expect(page.locator(HEAP_CELL("heap-top")).first()).toBeVisible();

    // Light-theme screenshot of the whole heap workspace (cached chunk view).
    await rows.nth(cachedIdx).click();
    await expect(cachedCell).toHaveClass(/\bcursor\b/);
    mkdirSync(SCREENSHOT_DIR, { recursive: true });
    await expect(page.locator("html")).not.toHaveClass(/\bdark\b/);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "heap-light.png") });

    // Histogram view.
    await page.getByTestId("heap-view-histogram").click();
    await expect(panel.getByTestId("heap-histogram")).toBeVisible({ timeout: 15_000 });

    // Free lists: one tcache list per occupied bin, one entry per cached chunk.
    await page.getByTestId("heap-view-freeLists").click();
    await expect(panel.getByTestId("heap-free-lists")).toBeVisible({ timeout: 15_000 });
    const tcacheLists = panel.locator('[data-testid="heap-free-list"][data-kind*="tcache"]');
    await expect(tcacheLists).toHaveCount(expected.tcache_bins.length);
    const cachedCount = expected.chunks.filter((c) => c.state === "cached").length;
    await expect(tcacheLists.getByTestId("heap-free-list-entry")).toHaveCount(cachedCount);
    await expect(panel.getByTestId("heap-free-list-corrupt")).toHaveCount(0);
    await expect(panel.getByTestId("heap-free-list-cycle")).toHaveCount(0);

    // Dark-theme screenshot via the in-app theme toggle.
    await page.getByTestId("heap-view-chunks").click();
    await page.getByTitle(/^Theme: Light/).click();
    await expect(page.locator("html")).toHaveClass(/\bdark\b/);
    await expect(cachedCell).toHaveClass(/heap-chunk-start/);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "heap-dark.png") });

    // Layer off: every heap ground and tick leaves the hex view.
    const toggle = page.getByTestId("heap-layer-toggle");
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    for (const cls of ["heap-header", "heap-user", "heap-freelink", "heap-free", "heap-meta", "heap-top", "heap-chunk-start"]) {
      await expect(page.locator(`.hex-byte.${cls}, .hex-char.${cls}`)).toHaveCount(0);
    }
    // ...and comes back when re-enabled.
    await toggle.click();
    await expect(page.locator(HEAP_CELL("heap-header")).first()).toBeVisible({ timeout: 15_000 });

    expect(heapFailures, "no /api/heap request may fail on a real heap").toEqual([]);
  });
});
