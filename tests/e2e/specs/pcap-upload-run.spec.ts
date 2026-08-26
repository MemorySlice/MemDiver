import os from "node:os";
import path from "node:path";
import { copyFileSync, readFileSync, rmSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import {
  pcapFixtureAvailable,
  pcapMatchedMslPath,
  pcapCapturePath,
  pcapManifestPath,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

/**
 * C3 — pcap-oracle pipeline run, browser-driven end to end (@requires-pcap).
 *
 * Drives the whole wizard: load the committed matched.msl, upload the matching
 * session_tls13.pcap as the oracle, run the pipeline, poll the header to a
 * terminal ``succeeded`` state, and prove a ``confirmed_by == "pcap"`` hit whose
 * ``key_hex`` equals the embedded secret.
 *
 * The proof is asserted twice, on purpose. First from the DOM: the results view
 * renders each hit with a provenance badge reading "Verified via pcap capture",
 * which is the user-visible Phase-1 claim. Then from the backend event stream,
 * which remains authoritative for ``key_hex``/``offset`` because those exact
 * bytes are never rendered in the hits list.
 *
 * Why two source paths: the web pipeline's consensus stage requires >= 2 dumps
 * ("Need at least 2 dumps"), whereas the fixture is a single (N=1) MSL. Folding
 * the same MSL twice yields N=2, which (< MIN_N_FOR_VARIANCE = 3) reduces on
 * entropy alone — the exact fallback the fixture's self-verify exercises — so the
 * embedded secret still survives to brute-force. The UI dedups identical paths,
 * so the second copy is a byte-identical .msl at a distinct temp path.
 *
 * Skips (rather than fails) when the launched backend lacks the ``pcap`` extra
 * (dpkt) — the pcap parse/oracle cannot run without it.
 */

const MANIFEST = JSON.parse(readFileSync(pcapManifestPath, "utf8")) as {
  secret_hex: string;
  secret_label: string;
  offset: number;
  client_random: string;
  key_size: number;
  stride: number;
};

interface WireHit {
  offset?: number;
  key_hex?: string;
  confirmed_by?: string;
  length?: number;
}

// A byte-identical second copy of the fixture MSL at a distinct path, so the
// dedup-on-paste UI accepts two source dumps (see file docstring).
const mslCopyPath = path.join(os.tmpdir(), `memdiver-e2e-matched-copy-${process.pid}.msl`);

// Only a genuine "the pcap extra (dpkt) is not installed" signal should skip.
// Deliberately narrow: it must NOT swallow real pipeline/oracle regressions whose
// messages merely mention "pcap" (e.g. "failed to parse pcap", "no TLS session
// matched", "pcap oracle: ...") — those must fail loudly.
function isDpktSkip(message: string): boolean {
  return /\bdpkt\b|no module named ['"]?dpkt|pcap support unavailable/i.test(message);
}

test.describe("Pcap-oracle pipeline run", { tag: "@requires-pcap" }, () => {
  test.skip(!pcapFixtureAvailable, "pcap fixture (matched.msl + session_tls13.pcap) missing");

  test.beforeAll(() => {
    if (pcapFixtureAvailable) copyFileSync(pcapMatchedMslPath, mslCopyPath);
  });
  test.afterAll(() => {
    rmSync(mslCopyPath, { force: true });
  });

  test("upload pcap → run → confirmed_by=pcap hit with the embedded key", async ({
    page,
  }) => {
    test.setTimeout(120_000);

    // Capture the run task_id straight off the POST response so we can read the
    // backend event stream for the hit's confirmed_by/key_hex afterwards.
    let taskId: string | null = null;
    page.on("response", async (resp) => {
      // Exact endpoint match: `/api/pipeline/run` (POST launches the run). Must
      // NOT match `/api/pipeline/runs/{id}/refine`, which would clobber taskId.
      if (
        new URL(resp.url()).pathname.endsWith("/api/pipeline/run") &&
        resp.request().method() === "POST" &&
        resp.ok()
      ) {
        try {
          taskId = ((await resp.json()) as { task_id?: string }).task_id ?? null;
        } catch {
          /* non-JSON body — ignore */
        }
      }
    });

    await enterWorkspaceWithMsl(page, pcapMatchedMslPath, { autoAnalyze: false });
    await page.locator(tab("pipeline")).first().click();

    // Stage 0 — recipe: start blank (defaults are fine; an N=2 run reduces on
    // entropy alone so the variance thresholds don't gate the embedded secret).
    await page.getByRole("button", { name: /Start blank/i }).click();

    // Stage 1 — dumps: fold the fixture MSL + its byte-identical copy (N=2).
    await page
      .locator('textarea[placeholder*="gdb_raw.bin"]')
      .fill(`${pcapMatchedMslPath}\n${mslCopyPath}`);
    await page.getByRole("button", { name: "Add paths" }).click();
    await expect(page.getByText(pcapMatchedMslPath, { exact: false })).toBeVisible();
    await expect(page.getByText(mslCopyPath, { exact: false })).toBeVisible();
    await page.getByRole("button", { name: /Next: Oracle/i }).click();

    // Stage 2 — oracle: upload the pcap via the detached filechooser.
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      page.getByTestId("pcap-upload-dropzone").click(),
    ]);
    await chooser.setFiles(pcapCapturePath);

    // Either sessions parse (dpkt present) or an error surfaces (dpkt missing).
    const sessionRow = page.getByTestId("pcap-session-row").first();
    const uploadError = page.getByTestId("pcap-upload-error");
    await expect(sessionRow.or(uploadError)).toBeVisible({ timeout: 30_000 });
    if (await uploadError.isVisible().catch(() => false)) {
      const msg = (await uploadError.innerText()).trim();
      test.skip(isDpktSkip(msg), `pcap support unavailable: ${msg}`);
    }

    // The uploaded server-side path is populated, and the parsed session shows up.
    await expect(page.getByTestId("pcap-uploaded-path")).not.toBeEmpty();
    await expect(sessionRow).toBeVisible();

    // Restrict matching to the fixture's TLS session (its client_random).
    await sessionRow.click();
    await page.getByRole("button", { name: /Next: Thresholds/i }).click();

    // Stage 3 — thresholds: launch the run.
    await page.getByRole("button", { name: /Run pipeline/i }).click();

    // Poll the header to a terminal state: the "New run" button appears on any
    // terminal status (succeeded / failed / cancelled).
    await expect(page.getByRole("button", { name: /New run/i })).toBeVisible({
      timeout: 90_000,
    });

    // On a dpkt-missing backend the run fails; inspect the record and skip if the
    // failure is pcap/dpkt-related, otherwise surface it.
    if (await page.getByText("failed", { exact: true }).isVisible().catch(() => false)) {
      let errMsg = "pipeline run failed";
      if (taskId) {
        const rec = await page.request.get(
          `/api/pipeline/runs/${encodeURIComponent(taskId)}`,
        );
        if (rec.ok()) errMsg = ((await rec.json()) as { error?: string }).error ?? errMsg;
      }
      test.skip(isDpktSkip(errMsg), `pipeline pcap run unavailable: ${errMsg}`);
      throw new Error(`pipeline run failed: ${errMsg}`);
    }

    // Rendered terminal success.
    await expect(page.getByText("succeeded", { exact: true })).toBeVisible();

    // The Phase-1 proof is visible in the app, not merely on the wire: the
    // results view keeps the hits list mounted after the run flips terminal,
    // and each hit carries the provenance badge for whatever confirmed it.
    const hitRow = page.getByTestId("pipeline-hit-row").first();
    await expect(hitRow).toBeVisible({ timeout: 15_000 });
    await expect(hitRow).toHaveAttribute("data-hit-offset", String(MANIFEST.offset));
    const badge = hitRow.getByTestId("verification-badge");
    await expect(badge).toHaveAttribute("data-confirmed-by", "pcap");
    await expect(badge).toHaveText(/Verified via pcap capture/);

    // Authoritative check: read the backend event stream for the brute_force
    // stage_end and assert a pcap-confirmed hit whose key == the embedded secret.
    expect(taskId, "captured pipeline run task_id").toBeTruthy();
    const resp = await page.request.get(
      `/api/tasks/${encodeURIComponent(taskId!)}/events?since=0`,
    );
    expect(resp.ok()).toBeTruthy();
    const { events } = (await resp.json()) as {
      events: Array<{ type: string; stage?: string; extra?: { hits?: WireHit[] } }>;
    };
    const bfEnd = events.find(
      (e) => e.type === "stage_end" && e.stage === "brute_force",
    );
    expect(bfEnd, "brute_force stage_end event present").toBeTruthy();
    const hits = bfEnd!.extra?.hits ?? [];
    const confirmed = hits.find(
      (h) => h.confirmed_by === "pcap" && h.key_hex === MANIFEST.secret_hex,
    );
    expect(
      confirmed,
      `a confirmed_by=="pcap" hit with key_hex==${MANIFEST.secret_hex}; got ${JSON.stringify(hits)}`,
    ).toBeTruthy();
    expect(confirmed!.offset).toBe(MANIFEST.offset);
  });
});
