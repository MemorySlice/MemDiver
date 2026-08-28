/**
 * E2E for A6: the Consensus tab becomes usable.
 *
 * Before this, an analyst who loaded N dumps and clicked "Run Consensus" got a
 * four-bar histogram and nothing else — the only filter form in the app lived
 * inside the Pipeline wizard, which refuses to run without an oracle or a
 * pcap. This spec drives the whole exploratory path the way a human does it:
 *
 *   load 3 phase dumps -> Run Consensus -> a ranked candidate table appears
 *   -> narrow it with a filter -> click a row -> the hex viewer jumps there.
 *
 * It runs on the REAL phase-series corpus (3 same-size 11 MB dumps of one
 * OpenSSL process), not a synthetic fixture, because the two things worth
 * guarding here — that the class filter is applied at all, and that a row's
 * offset lands on a real byte in the viewer — are both properties of real
 * variance data.
 */
import { test, expect, type Page, type Request } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { tlsPhaseDumps, tlsPhaseDumpsAvailable } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
  installErrorGuards,
} from "../fixtures/workspace";

const CANDIDATES_URL = "/api/analysis/candidates";

/** Bodies of every POST /api/analysis/candidates the page has sent. */
function recordCandidateRequests(page: Page): Record<string, unknown>[] {
  const bodies: Record<string, unknown>[] = [];
  page.on("request", (req: Request) => {
    if (req.method() === "POST" && req.url().includes(CANDIDATES_URL)) {
      try {
        bodies.push(JSON.parse(req.postData() ?? "{}") as Record<string, unknown>);
      } catch {
        /* a body we cannot parse is not a body we can assert on */
      }
    }
  });
  return bodies;
}

/** Set one of the numeric filter inputs by its visible label. */
async function setNumberFilter(page: Page, label: RegExp, value: string) {
  const input = page.getByLabel(label);
  await input.fill(value);
}

test.describe("Consensus tab candidate table", { tag: "@requires-dataset" }, () => {
  test.skip(!tlsPhaseDumpsAvailable, "TLS phase-dump corpus not present.");
  test.setTimeout(300_000);

  test("N dumps -> ranked candidates -> filter -> click a row -> hex jumps", async ({
    page,
  }) => {
    const guards = installErrorGuards(page);
    const sent = recordCandidateRequests(page);
    const dumps = tlsPhaseDumps(3);

    // --- load 3 dumps: the first through the wizard, the rest through the
    // Dumps panel's path input (the same route variance-overlay.spec takes).
    await enterWorkspaceWithMsl(page, dumps[0]);
    await page.locator(tab("dumps")).first().click();
    const addInput = page.getByPlaceholder("Server path to dump file");
    await expect(addInput).toBeVisible({ timeout: 15_000 });
    for (const dumpPath of dumps.slice(1)) {
      await addInput.fill(dumpPath);
      await addInput.press("Enter");
      // AddDumpButton clears its input in a `finally` AFTER an async
      // /api/path/info round trip. Firing the next fill before that lands
      // wipes the typed value and the dump is silently never added -- which
      // used to leave this spec running at N=2, below MIN_N_FOR_VARIANCE,
      // where the backend skips the class gate and the filter assertions
      // below would have been testing nothing. Wait for the row.
      await expect(
        page.locator(`[title="${dumpPath}"]`).first(),
      ).toBeVisible({ timeout: 20_000 });
    }

    // --- Run Consensus (exploration mode; the button needs >= 2 dumps).
    await switchToExplorationMode(page);
    const runBtn = page.getByRole("button", { name: "Run Consensus" });
    await expect(runBtn).toBeEnabled({ timeout: 20_000 });
    await runBtn.click();

    // --- the candidate table appears under the histogram, in the SAME tab.
    await page.locator(tab("consensus")).first().click();
    const table = page.getByTestId("candidate-table");
    await expect(table).toBeVisible({ timeout: 180_000 });

    // The alignment provenance is always on screen: these dumps are equal in
    // size, so the flat path is correct here and the banner stays quiet.
    const banner = page.getByTestId("candidate-alignment-banner");
    await expect(banner).toBeVisible();
    await expect(page.getByTestId("candidate-alignment-method")).toContainText(
      /file offset|module|virtual/i,
    );

    // The default query is all-non-invariant, never key_candidate-only: a real
    // TLS secret is class-mixed and the narrow query loses it.
    expect(sent.length).toBeGreaterThan(0);
    const firstBody = sent[0];
    expect(firstBody.classes).toEqual(["structural", "pointer", "key_candidate"]);
    expect(Object.prototype.hasOwnProperty.call(firstBody, "min_variance")).toBe(false);
    expect(firstBody.dump_paths).toHaveLength(3);

    // N >= MIN_N_FOR_VARIANCE, so the class gate really ran: rows carry a
    // classification rather than the entropy-only fallback's "Unclassified".
    await expect(page.getByTestId("candidate-entropy-only")).toHaveCount(0);

    const rowsBefore = await page.getByTestId("candidate-row").count();
    expect(rowsBefore).toBeGreaterThan(0);

    // --- apply a filter: nothing shorter than 48 bytes.
    const sentBefore = sent.length;
    await setNumberFilter(page, /Min length/i, "48");
    await page.getByTestId("candidate-apply").click();
    await expect
      .poll(() => sent.length, { timeout: 180_000 })
      .toBeGreaterThan(sentBefore);
    expect(sent[sent.length - 1].min_region).toBe(48);

    // Whatever survives must actually satisfy the filter. (Vacuously true on
    // an empty result, which the request assertion above already covers.)
    await expect(page.getByTestId("candidate-apply")).toBeEnabled({ timeout: 180_000 });
    const lengths = await page
      .getByTestId("candidate-row")
      .evaluateAll((rows) =>
        rows.map((r) => Number((r as HTMLElement).dataset.length ?? "0")),
      );
    expect(lengths.every((n) => n >= 48)).toBe(true);

    // --- widen back so there is certainly a row to click, then click it.
    const sentBeforeWiden = sent.length;
    await setNumberFilter(page, /Min length/i, "16");
    await page.getByTestId("candidate-apply").click();
    await expect
      .poll(() => sent.length, { timeout: 180_000 })
      .toBeGreaterThan(sentBeforeWiden);

    const firstRow = page.getByTestId("candidate-row").first();
    await expect(firstRow).toBeVisible({ timeout: 180_000 });
    const offset = Number(await firstRow.getAttribute("data-offset"));
    expect(Number.isFinite(offset)).toBe(true);
    await firstRow.click();

    // --- the hex viewer jumped: the shared scrollToOffset path (the one the
    // variance minimap uses) moved the cursor to this offset...
    await expect
      .poll(
        () =>
          page.evaluate(() => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return (window as any).__useHexStore.getState().cursorOffset as number;
          }),
        { timeout: 20_000 },
      )
      .toBe(offset);

    // ...and the byte at that offset is rendered, not merely bookkept.
    await expect(
      page.locator(`[data-offset="${offset}"][data-col="hex"]`).first(),
    ).toBeVisible({ timeout: 30_000 });

    guards.assertClean();
  });
});
