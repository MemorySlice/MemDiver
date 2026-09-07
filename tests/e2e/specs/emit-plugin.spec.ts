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
 * Regression: the emit stage was unreachable from the UI.
 *
 * `emit` is fully implemented end to end — `EmitParams` on
 * `PipelineRunRequest`, the `emit_plugin` stage gated on
 * `state.emit_params is not None`, the `vol3_plugin` artifact — but the
 * threshold form built its request body without ever mentioning the key.
 * Because `ArtifactsTabs` opens on the Plugin tab, the first thing a user
 * saw after a successful run was "No vol3_plugin artifact in this run.",
 * and `PluginPreview`'s copy/download buttons were dead code.
 *
 * This drives the whole loop on the committed pcap fixture (whose secret
 * sits at offset 512, covered by the default stride of 1): opt into the
 * plugin, run, and require that the Plugin tab shows real Python.
 */

const mslCopyPath = path.join(os.tmpdir(), "memdiver-emit-plugin-copy.msl");
const PLUGIN_NAME = "e2e_emit_plugin";

function isDpktSkip(message: string): boolean {
  return /\bdpkt\b|no module named ['"]?dpkt|pcap support unavailable/i.test(message);
}

test.describe("Emitted Volatility 3 plugin", { tag: "@requires-pcap" }, () => {
  test.skip(!pcapFixtureAvailable, "pcap fixture (matched.msl + session_tls13.pcap) missing");

  // Same idempotent upload-dir hook as stride-coverage.spec.ts: /api/pcaps/
  // upload answers 409 until an upload dir is chosen, and either answer here
  // is fine (200 = configured, 409 = already pinned by MEMDIVER_UPLOAD_DIR).
  // Not a temp dir: api/upload_dir.validate_candidate rejects every temp root.
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

  test("the Plugin tab shows real plugin source after an emit-enabled run", async ({
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

    // The opt-in that used to be missing. The N-sweep box next to it is now
    // live on a pcap run too (P2.2): the harness re-runs whichever oracle the
    // run armed, so it sweeps against the capture with no BYO oracle FILE.
    // Left unchecked here — this spec is about the emit stage, and a sweep
    // would add a full consensus + reduce + verify pass per N.
    await expect(page.getByTestId("nsweep-enable")).toBeEnabled();
    await page.getByTestId("emit-enable").check();
    await page.getByTestId("emit-name").fill(PLUGIN_NAME);
    // min_static_ratio is left at the backend default (0.3): raising it can
    // legitimately abort the stage on a low-static neighborhood.

    await page.getByRole("button", { name: /Run pipeline/i }).click();

    await expect(page.getByRole("button", { name: /New run/i })).toBeVisible({
      timeout: 90_000,
    });
    await expect(page.getByText("succeeded", { exact: true })).toBeVisible();
    // The stage only emits when brute force actually found something; stride 1
    // covers offset 512, so a hit is required for this assertion to mean anything.
    await expect(page.getByTestId("pipeline-hit-row").first()).toBeVisible({
      timeout: 15_000,
    });

    // Plugin is the DEFAULT tab, so no click is needed — this is literally the
    // first thing the user sees on the results screen.
    await expect(
      page.getByText("No vol3_plugin artifact in this run."),
    ).toHaveCount(0);
    await expect(page.getByText("vol3_plugin.py")).toBeVisible({ timeout: 15_000 });

    // Real generated Python, and the name the user typed reached the emitter
    // (PatternGenerator.generate(name=...) renders it into the module docstring).
    const source = page.locator("pre").filter({ hasText: "volatility3" }).first();
    await expect(source).toContainText("volatility3.framework");
    await expect(source).toContainText(PLUGIN_NAME);

    guards.assertClean();
  });
});
