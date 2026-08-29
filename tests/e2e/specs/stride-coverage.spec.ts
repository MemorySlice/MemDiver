import path from "node:path";
import os from "node:os";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import {
  pcapFixtureAvailable,
  pcapMatchedMslPath,
  pcapCapturePath,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

/**
 * Regression: a partial-coverage run used to be silent.
 *
 * Brute force tests candidate offsets on an ABSOLUTE stride grid, so a stride
 * of N only ever tests offsets divisible by N. On a real corpus dump the true
 * TLS secret sat at offset 585148 (585148 % 8 == 4), so the then-default
 * stride of 8 never tested it: the run ended `succeeded` with zero hits and NO
 * diagnostic — a correct recovery was indistinguishable from "the key is not
 * in this dump". The default is now stride 1 (full coverage), but a user who
 * raises the stride can still reach this state, so the diagnostic still has to
 * be there.
 *
 * This drives the same pathology deterministically on the committed fixture,
 * whose secret sits at offset 512. Measured against the real reduce stage:
 *   stride 1 -> 4065 candidates, secret covered
 *   stride 3 -> 1355 candidates (33.3%), secret NOT covered  <- used here
 *   stride 8 -> 509 candidates,  secret covered
 * So stride 3 yields a guaranteed zero-hit run that MUST now explain itself.
 */

const mslCopyPath = path.join(os.tmpdir(), "memdiver-stride-coverage-copy.msl");
const PARTIAL_COVERAGE_CODE = "brute_force.partial_coverage";

function isDpktSkip(message: string): boolean {
  return /\bdpkt\b|no module named ['"]?dpkt|pcap support unavailable/i.test(message);
}

test.describe("Brute-force coverage diagnostics", { tag: "@requires-pcap" }, () => {
  test.skip(!pcapFixtureAvailable, "pcap fixture (matched.msl + session_tls13.pcap) missing");

  // B0 made the upload dir configure-on-first-use, so /api/pcaps/upload answers
  // 409 until something chooses one — and this spec uploads a real capture
  // below. Same idempotent hook as pcap-upload-run.spec.ts: the response is
  // deliberately not asserted, because a 200 (configured) and a 409 (pinned by
  // MEMDIVER_UPLOAD_DIR) are equally fine. Its purpose is to remove this spec's
  // dependence on an earlier spec having configured the directory first. Not a
  // temp dir: api/upload_dir.validate_candidate rejects every temp root.
  test.beforeAll(async ({ request }) => {
    const uploadDir = path.join(os.homedir(), ".memdiver", "e2e-uploads");
    mkdirSync(uploadDir, { recursive: true });
    await request.post(
      `http://127.0.0.1:${process.env.BACKEND_PORT ?? "8091"}/api/settings/upload-dir`,
      { data: { path: uploadDir } },
    );
  });

  test.beforeAll(() => {
    if (pcapFixtureAvailable) copyFileSync(pcapMatchedMslPath, mslCopyPath);
  });
  test.afterAll(() => {
    rmSync(mslCopyPath, { force: true });
  });

  test("a zero-hit run caused by stride explains itself instead of failing silently", async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);

    await enterWorkspaceWithMsl(page, pcapMatchedMslPath, { autoAnalyze: false });
    await page.locator(tab("pipeline")).first().click();
    await page.getByRole("button", { name: /Start blank/i }).click();

    // N=2 (the web pipeline's consensus stage needs >= 2 dumps).
    await page
      .locator('textarea[placeholder*="gdb_raw.bin"]')
      .fill(`${pcapMatchedMslPath}\n${mslCopyPath}`);
    await page.getByRole("button", { name: "Add paths" }).click();
    await page.getByRole("button", { name: /Next: Oracle/i }).click();

    // Arm the real capture so the run has a genuine oracle to fail against —
    // the point is that the key IS present and IS confirmable, and the only
    // reason it is not found is that its offset is off the stride grid.
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      page.getByTestId("pcap-upload-dropzone").click(),
    ]);
    await chooser.setFiles(pcapCapturePath);

    const sessionRow = page.getByTestId("pcap-session-row").first();
    const uploadError = page.getByTestId("pcap-upload-error");
    await expect(sessionRow.or(uploadError)).toBeVisible({ timeout: 30_000 });
    if (await uploadError.isVisible().catch(() => false)) {
      const msg = (await uploadError.innerText()).trim();
      test.skip(isDpktSkip(msg), `pcap support unavailable: ${msg}`);
    }
    await sessionRow.click();
    await page.getByRole("button", { name: /Next: Thresholds/i }).click();

    // Stride 3 puts offset 512 off the grid: the secret is present but unreachable.
    await page.locator('label:has-text("stride") input[type="number"]').fill("3");
    await page.getByRole("button", { name: /Run pipeline/i }).click();

    await expect(page.getByRole("button", { name: /New run/i })).toBeVisible({
      timeout: 90_000,
    });
    await expect(page.getByText("succeeded", { exact: true })).toBeVisible();

    // No hit — that part is expected and correct.
    await expect(page.getByTestId("pipeline-hit-row")).toHaveCount(0);

    // …but the run must NOT be silent about why. Coverage is always reported.
    const coverage = page.getByTestId("pipeline-coverage");
    await expect(coverage).toBeVisible({ timeout: 15_000 });
    const fraction = Number(await coverage.getAttribute("data-coverage-fraction"));
    expect(fraction).toBeGreaterThan(0);
    expect(fraction).toBeLessThan(1);

    // …and a partial-coverage warning names the cause and the remedy.
    const warning = page.getByTestId("pipeline-warning").first();
    await expect(warning).toBeVisible({ timeout: 15_000 });
    await expect(warning).toHaveAttribute("data-warning-code", PARTIAL_COVERAGE_CODE);
    await expect(warning).toHaveText(/stride=3/);
    // The remedy must point at a FINER grid: at stride 3 the only useful
    // suggestion is 1, and it must never advise a coarser stride like 4.
    await expect(warning).toHaveText(/--stride 1/);
    await expect(warning).not.toHaveText(/--stride 4/);

    guards.assertClean();
  });
});
