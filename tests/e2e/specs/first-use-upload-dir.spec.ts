import os from "node:os";
import path from "node:path";
import { mkdirSync, statSync } from "node:fs";
import { test, expect, type Page } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import {
  pcapFixtureAvailable,
  pcapMatchedMslPath,
  pcapCapturePath,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

/**
 * B0 — configure-on-first-use upload directory, browser-driven end to end.
 *
 * ``api/config.Settings.upload_dir`` no longer defaults to
 * ``/tmp/memdiver_uploads``; unconfigured is a first-class state that fails
 * *closed* with HTTP 409 (``api/dependencies.upload_dir_or_409``). This spec
 * proves the resulting user journey is not a dead end:
 *
 *   1. Settings -> Storage renders the "Not configured" state.
 *   2. Dropping a capture on the pipeline's pcap dropzone gets a 409 instead
 *      of a silent write to a world-writable temp dir.
 *   3. ``UploadDirPrompt`` opens on that 409 (never the raw error text) and the
 *      directory is picked with the wizard ``FileBrowser`` it reuses.
 *   4. On save, PcapUpload **re-POSTs the File it was still holding** — the
 *      user does not have to find the capture again. That is the load-bearing
 *      claim, and it is asserted on the wire (``filename`` + ``size`` of the
 *      second POST equal the fixture's) rather than merely "a path appeared".
 *
 * FILE NAME: this must sort before ``pcap-upload-run.spec.ts`` (and before
 * ``stride-coverage.spec.ts``), because Playwright runs spec files in path
 * order with ``fullyParallel: false, workers: 1`` and both of those now
 * configure the directory in a ``beforeAll``. "first-use-…" does; the
 * originally-briefed "upload-dir-first-use…" would have sorted *after* both.
 *
 * DETERMINISM CAVEAT (read before "fixing" the conditional stub below): the
 * chosen directory is persisted to ``memdiver_home()/config.json`` and the
 * running server keeps it in its ``@lru_cache``d ``Settings``. There is
 * deliberately no un-configure endpoint, so after the first green run on a
 * machine the real backend can never emit the first-use 409 again. When the
 * server reports itself already configured we therefore serve the backend's
 * byte-exact 409 body once and fall through, so steps 2-4 are identical on a
 * virgin machine and a warm one. On a fresh checkout / CI the server reports
 * unconfigured and the REAL 409 flows with nothing stubbed.
 */

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

/**
 * The 409 detail, byte-for-byte from ``api/dependencies.upload_dir_or_409``.
 * The ``upload_dir_unconfigured:`` token is the contract
 * ``frontend/src/components/settings/upload-dir-error.ts`` matches on, so a
 * paraphrase here would stub a 409 the product would not recognise.
 */
const UNCONFIGURED_DETAIL =
  "upload_dir_unconfigured: no upload directory configured; " +
  "choose one in Settings -> Storage";

/**
 * The directory the spec chooses.
 *
 * NOT under ``os.tmpdir()``: ``api/upload_dir.validate_candidate`` rejects
 * every temp root (``tempfile.gettempdir()``, ``/tmp``, ``/var/tmp``) with a
 * 400 — eliminating that exact location is what B0 is for. A subdirectory of
 * ``$HOME`` is the nearest persistent, private location that passes every
 * check (home *itself* is also rejected).
 *
 * Stable rather than ``mkdtemp``-random, and never deleted: the backend keeps
 * using it for the rest of the suite (and for later suite runs), so a
 * per-run temp dir would either leak or be pulled out from under it.
 */
const UPLOAD_DIR = path.join(os.homedir(), ".memdiver", "e2e-uploads");

/** Substring every path under UPLOAD_DIR carries — see the toHaveValue notes. */
const UPLOAD_DIR_LEAF = "e2e-uploads";

const CAPTURE_NAME = path.basename(pcapCapturePath);

interface UploadDirStatus {
  configured: boolean;
  path: string | null;
  source: "env" | "user_config" | null;
  env_pinned: boolean;
  quota_bytes: number;
  legacy?: {
    path: string;
    file_count: number;
    total_bytes: number;
    owned_by_us: boolean;
  };
}

interface UploadAttempt {
  status: number;
  filename?: string;
  size?: number;
  pcapPath?: string;
}

/** Same narrow dpkt predicate the sibling pcap specs use. */
function isDpktSkip(message: string): boolean {
  return /\bdpkt\b|no module named ['"]?dpkt|pcap support unavailable/i.test(message);
}

/** Open the settings popover and return its Storage block. */
async function openStorageSection(page: Page) {
  await page.getByRole("button", { name: /settings/i }).first().click();
  const storage = page.getByTestId("settings-storage");
  await expect(storage).toBeVisible();
  return storage;
}

/**
 * Close the settings popover by re-clicking its trigger. The trigger sits
 * inside SettingsMenu's own ref, so the outside-mousedown listener ignores it
 * and the onClick toggle wins.
 */
async function closeSettings(page: Page): Promise<void> {
  await page.getByRole("button", { name: /settings/i }).first().click();
  await expect(page.getByTestId("settings-storage")).toBeHidden();
}

test.describe("B0 — configure-on-first-use upload directory", { tag: "@requires-pcap" }, () => {
  test.skip(!pcapFixtureAvailable, "pcap fixture (matched.msl + session_tls13.pcap) missing");

  // The FileBrowser can only "Select This Directory" for a directory it managed
  // to browse into, so the target must exist before the picker is driven.
  test.beforeAll(() => {
    mkdirSync(UPLOAD_DIR, { recursive: true });
  });

  test("unconfigured upload dir → prompt → save → the upload finishes by itself", async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);

    const probe = await request.get(`${BACKEND_URL}/api/settings/upload-dir`);
    expect(
      probe.status(),
      "GET /api/settings/upload-dir must answer 200 even while unconfigured",
    ).toBe(200);
    const state = (await probe.json()) as UploadDirStatus;
    test.skip(
      state.env_pinned,
      "MEMDIVER_UPLOAD_DIR is set on this backend; the UI cannot configure a pinned dir.",
    );

    // Record every upload attempt so "the file was re-sent, not lost" is a
    // wire fact. The uuid-named destination cannot carry that proof: the
    // backend stores captures as `<uuid>.pcap`, so `filename`/`size` from the
    // response body are the only evidence of *which* bytes were posted.
    const uploads: UploadAttempt[] = [];
    page.on("response", async (resp) => {
      if (
        new URL(resp.url()).pathname.endsWith("/api/pcaps/upload") &&
        resp.request().method() === "POST"
      ) {
        const attempt: UploadAttempt = { status: resp.status() };
        try {
          const body = (await resp.json()) as {
            filename?: string;
            size?: number;
            pcap_path?: string;
          };
          attempt.filename = body.filename;
          attempt.size = body.size;
          attempt.pcapPath = body.pcap_path;
        } catch {
          /* the 409 envelope, or a non-JSON body — status is enough */
        }
        uploads.push(attempt);
      }
    });

    // See the DETERMINISM CAVEAT in the file docstring.
    let stubServed = false;
    if (state.configured) {
      await page.route("**/api/pcaps/upload", async (route) => {
        if (stubServed) {
          await route.fallback();
          return;
        }
        stubServed = true;
        await route.fulfill({
          status: 409,
          contentType: "application/json",
          body: JSON.stringify({ detail: UNCONFIGURED_DETAIL }),
        });
      });
    }

    await enterWorkspaceWithMsl(page, pcapMatchedMslPath, { autoAnalyze: false });

    // --- Settings → Storage reflects the SERVER, not a localStorage guess ---
    await openStorageSection(page);
    await expect(page.getByText("Storage", { exact: true })).toBeVisible();
    await expect(page.getByText("Upload Directory", { exact: true })).toBeVisible();
    if (state.configured) {
      await expect(page.getByTestId("settings-upload-dir-path")).toHaveText(state.path!);
    } else {
      const unset = page.getByTestId("settings-upload-dir-unset");
      await expect(unset).toBeVisible();
      await expect(unset).toHaveText("Not configured");
      await expect(page.getByTestId("settings-upload-dir-choose")).toHaveText("Choose...");
    }
    await closeSettings(page);

    // --- Reach the pcap dropzone: pipeline → recipe → dumps → oracle ---
    await page.locator(tab("pipeline")).first().click();
    await page.getByRole("button", { name: /Start blank/i }).click();

    // One dump is enough (StageDumps advances at >= 1); this spec never runs
    // the pipeline, it only needs the oracle stage mounted.
    await page
      .locator('textarea[placeholder*="gdb_raw.bin"]')
      .fill(pcapMatchedMslPath);
    await page.getByRole("button", { name: "Add paths" }).click();
    await expect(page.getByText(pcapMatchedMslPath, { exact: false })).toBeVisible();
    await page.getByRole("button", { name: /Next: Oracle/i }).click();

    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      page.getByTestId("pcap-upload-dropzone").click(),
    ]);
    await chooser.setFiles(pcapCapturePath);

    // --- The 409 becomes a prompt, not a dead end ---
    const prompt = page.getByTestId("upload-dir-prompt");
    await expect(prompt).toBeVisible({ timeout: 30_000 });
    await expect(prompt).toContainText(
      "MemDiver has no upload directory yet. Pick a folder where uploaded captures and dumps should be stored.",
    );
    // The raw upload error is what this feature exists to replace.
    await expect(page.getByTestId("pcap-upload-error")).toHaveCount(0);
    await expect.poll(() => uploads.length, { timeout: 15_000 }).toBeGreaterThanOrEqual(1);
    expect(uploads[0].status, "the first upload attempt is rejected with 409").toBe(409);

    // --- Pick UPLOAD_DIR with the wizard FileBrowser the prompt reuses ---
    await prompt.getByTestId("upload-dir-choose").click();
    const pathBar = page.getByPlaceholder("Type a path and press Enter");
    await expect(pathBar).toBeVisible();
    await pathBar.click();
    await pathBar.fill(UPLOAD_DIR);
    await pathBar.press("Enter");
    // Prove the browse actually LANDED in UPLOAD_DIR before selecting: on a
    // failed browse FileBrowser keeps `currentPath`, so "Select This Directory"
    // would silently commit whatever directory it was showing before. Matched
    // by suffix because /api/path/browse echoes its own normalised form.
    await expect(pathBar).toHaveValue(new RegExp(`${UPLOAD_DIR_LEAF}/?$`));
    const selectDir = page.getByRole("button", { name: "Select This Directory" });
    await expect(selectDir).toBeEnabled();
    await selectDir.click();
    await expect(prompt.getByTestId("upload-dir-chosen-path")).toHaveText(
      new RegExp(`${UPLOAD_DIR_LEAF}/?$`),
    );

    // --- Save ---
    const savePost = page.waitForResponse(
      (resp) =>
        new URL(resp.url()).pathname.endsWith("/api/settings/upload-dir") &&
        resp.request().method() === "POST",
    );
    await prompt.getByTestId("upload-dir-save").click();
    const saved = await savePost;
    expect(saved.status(), "POST /api/settings/upload-dir").toBe(200);
    const savedBody = (await saved.json()) as UploadDirStatus & {
      migrated: number;
      skipped: number;
    };
    expect(savedBody.configured).toBe(true);
    expect(savedBody.source).toBe("user_config");
    expect(savedBody.path).toContain(UPLOAD_DIR_LEAF);
    expect(typeof savedBody.migrated).toBe("number");
    expect(typeof savedBody.skipped).toBe("number");

    // --- THE CLAIM: the upload completes automatically, same file ---
    await expect(prompt).toBeHidden({ timeout: 15_000 });

    // Asserted on the wire FIRST, and deliberately so: on a backend without
    // the `pcap` extra the *validate* half fails and use-pcap-arm clears
    // `form.pcapPath` (clearPathOnFailure), so a DOM-first assertion would
    // race that teardown. `filename` + `size` are also the only evidence of
    // WHICH bytes were posted — the destination is uuid-named.
    await expect.poll(() => uploads.length, { timeout: 30_000 }).toBe(2);
    const retry = uploads[1];
    expect(retry.status, "the automatic re-upload").toBe(200);
    // Same bytes, without the user touching the file picker again.
    expect(retry.filename).toBe(CAPTURE_NAME);
    expect(retry.size).toBe(statSync(pcapCapturePath).size);
    expect(
      retry.pcapPath,
      "the capture landed in the directory just chosen in the prompt",
    ).toContain(UPLOAD_DIR_LEAF);

    // --- Storage now shows the chosen directory ---
    await openStorageSection(page);
    await expect(page.getByTestId("settings-upload-dir-unset")).toHaveCount(0);
    await expect(page.getByTestId("settings-upload-dir-path")).toContainText(
      UPLOAD_DIR_LEAF,
    );
    await closeSettings(page);

    // Either the sessions parsed (dpkt present) or the arm half errored. A
    // dpkt-missing backend is orthogonal to B0 and must not fail this spec;
    // any OTHER error here is a real regression.
    const sessionRow = page.getByTestId("pcap-session-row").first();
    const uploadError = page.getByTestId("pcap-upload-error");
    await expect(sessionRow.or(uploadError)).toBeVisible({ timeout: 30_000 });
    if (await uploadError.isVisible().catch(() => false)) {
      const msg = (await uploadError.innerText()).trim();
      test.skip(isDpktSkip(msg), `pcap support unavailable: ${msg}`);
      throw new Error(`unexpected error after the automatic re-upload: ${msg}`);
    }

    // dpkt present: the user-visible path is inside the new directory.
    const uploadedPath = page.getByTestId("pcap-uploaded-path");
    await expect(uploadedPath).toBeVisible();
    await expect(uploadedPath).toContainText(UPLOAD_DIR_LEAF);
    await expect(uploadedPath).toHaveText(/\.pcap$/);
  });

  test("the settings endpoint reports the configured dir and rejects a bad path", async ({
    request,
  }) => {
    // Runs after the journey above (workers: 1, declaration order within a
    // file), so "configured" is a post-condition of it, not an assumption.
    const resp = await request.get(`${BACKEND_URL}/api/settings/upload-dir`);
    expect(resp.status()).toBe(200);
    const status = (await resp.json()) as UploadDirStatus;
    expect(status.configured).toBe(true);
    expect(typeof status.path).toBe("string");
    expect(status.source).toBe(status.env_pinned ? "env" : "user_config");
    expect(typeof status.env_pinned).toBe("boolean");
    expect(typeof status.quota_bytes).toBe("number");

    // A relative path is refused with 400 + a human reason, so a typo in the
    // prompt can never point uploads (and therefore the containment root every
    // write-path check measures against) at the server's cwd. An env-pinned
    // backend answers 409 instead — the pin is checked before validation.
    const bad = await request.post(`${BACKEND_URL}/api/settings/upload-dir`, {
      data: { path: "relative/not/absolute" },
    });
    expect(bad.status()).toBe(status.env_pinned ? 409 : 400);
    expect(typeof ((await bad.json()) as { detail?: unknown }).detail).toBe("string");
  });
});
