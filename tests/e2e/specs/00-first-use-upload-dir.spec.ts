import os from "node:os";
import path from "node:path";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";
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
 * FILE NAME: the ``00-`` prefix is load bearing, not decoration. Playwright
 * runs spec files in path order with ``fullyParallel: false, workers: 1``, and
 * THREE other specs configure the upload directory in a ``beforeAll`` so they
 * can run standalone: ``emit-plugin``, ``pcap-upload-run`` and
 * ``stride-coverage``. Any of them running first leaves the backend configured
 * and silently costs this file its first-use test. The original name only
 * cleared two of the three — ``emit-plugin`` sorts before "first-use-…", which
 * is exactly what happened: in a full-suite run the first-use test skipped
 * while the spec still reported green. A prefix that sorts before every letter
 * is the only version of this that a new spec name cannot break.
 *
 * WARM BACKENDS, and why this is two tests rather than one.
 *
 * The chosen directory is persisted to ``memdiver_home()/config.json`` and the
 * running server keeps it in its ``@lru_cache``d ``Settings``; the POST handler
 * mutates that instance in place rather than clearing the cache, and there is
 * deliberately no un-configure endpoint. So a server that has been configured
 * can never emit the first-use 409 again — only a fresh process can.
 *
 * ``playwright.config.ts`` therefore gives the backend an ``XDG_DATA_HOME`` of
 * its own and deletes the preferences file as part of the spawn command, which
 * makes "a freshly spawned e2e backend is unconfigured" true by construction.
 * What it cannot cover is ``reuseExistingServer``: run the suite twice locally
 * without stopping the server and the second run meets a warm one.
 *
 * That case is why the journey below is split in two:
 *
 *   - The FIRST-USE test states facts about the BACKEND — the 409 and the
 *     "Not configured" screen. Against a warm server those facts are not
 *     observable, so it SKIPS, loudly and with the remedy in the message. It
 *     never stubs, so a green tick there always means the real thing happened.
 *   - The RECOVERY test states a fact about the UI — that a 409 becomes a
 *     prompt and the held File is re-POSTed by itself. A 409 is a 409 whoever
 *     produced it, so against a warm server this one serves the backend's
 *     byte-exact body once and carries on, and annotates the run to say so.
 *
 * The old shape ran both claims in one test with the stub always available,
 * which meant a warm machine reported a green "configure-on-first-use" check
 * having verified neither the 409 nor the screen that explains it.
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

/**
 * What the backend says about its upload directory.
 *
 * Answering 200 while unconfigured is itself part of the contract: the screen
 * that offers to fix the problem is rendered from this response, so a 404 or a
 * 500 here would take the remedy down with the fault.
 */
async function uploadDirStatus(request: APIRequestContext): Promise<UploadDirStatus> {
  const probe = await request.get(`${BACKEND_URL}/api/settings/upload-dir`);
  expect(
    probe.status(),
    "GET /api/settings/upload-dir must answer 200 even while unconfigured",
  ).toBe(200);
  return (await probe.json()) as UploadDirStatus;
}

/** The skip reason a warm backend earns, with the remedy in it. */
function warmBackendSkip(state: UploadDirStatus): string {
  return (
    `this backend already has an upload directory (${state.path}) and cannot be ` +
    "returned to the first-use state — get_settings() is lru_cached and the POST " +
    "handler mutates it in place. Stop the server on BACKEND_PORT and re-run: a " +
    "spawned e2e backend starts from a cleared preferences file."
  );
}

test.describe("B0 — configure-on-first-use upload directory", { tag: "@requires-pcap" }, () => {
  test.skip(!pcapFixtureAvailable, "pcap fixture (matched.msl + session_tls13.pcap) missing");

  // The FileBrowser can only "Select This Directory" for a directory it managed
  // to browse into, so the target must exist before the picker is driven.
  test.beforeAll(() => {
    mkdirSync(UPLOAD_DIR, { recursive: true });
  });

  /**
   * The BACKEND half of B0, and the half that cannot be faked.
   *
   * Nothing here is stubbed or branched: either the server really is in the
   * first-use state and every assertion below is about it, or this test skips
   * and says so. That is the whole point of splitting it out — a warm machine
   * used to report this claim green having checked the opposite branch.
   *
   * Declared first so the recovery test that follows still meets an
   * unconfigured server: this one reads, it never chooses a directory.
   */
  test("fails closed, and says so on screen, until a directory is chosen", async ({
    page,
    request,
  }) => {
    const state = await uploadDirStatus(request);
    test.skip(
      state.env_pinned,
      "MEMDIVER_UPLOAD_DIR is set on this backend; the UI cannot configure a pinned dir.",
    );
    test.skip(state.configured, warmBackendSkip(state));

    // --- The wire: fails CLOSED, not into a world-writable temp dir ---
    // Driven from the API rather than the browser: this is a statement about
    // the endpoint, and the UI journey that consumes it is the next test.
    const rejected = await request.post(`${BACKEND_URL}/api/pcaps/upload`, {
      multipart: {
        file: {
          name: CAPTURE_NAME,
          mimeType: "application/vnd.tcpdump.pcap",
          buffer: readFileSync(pcapCapturePath),
        },
      },
    });
    expect(rejected.status(), "an upload with nowhere to go is refused").toBe(409);
    // The token, not the prose: `upload-dir-error.ts` matches on it, so a
    // backend that reworded the sentence would still be recognised — and one
    // that dropped the token would silently stop opening the prompt.
    expect((await rejected.json()) as { detail: string }).toHaveProperty(
      "detail",
      expect.stringContaining("upload_dir_unconfigured:"),
    );

    // --- The screen: Storage reflects the SERVER, not a localStorage guess ---
    await enterWorkspaceWithMsl(page, pcapMatchedMslPath, { autoAnalyze: false });
    await openStorageSection(page);
    await expect(page.getByText("Storage", { exact: true })).toBeVisible();
    await expect(page.getByText("Upload Directory", { exact: true })).toBeVisible();
    const unset = page.getByTestId("settings-upload-dir-unset");
    await expect(unset).toBeVisible();
    await expect(unset).toHaveText("Not configured");
    await expect(page.getByTestId("settings-upload-dir-choose")).toHaveText("Choose...");
    await closeSettings(page);
  });

  /**
   * The UI half: a 409 becomes a prompt, and the File the user already picked
   * is re-POSTed by itself.
   *
   * A 409 is a 409 whoever produced it, so this one runs against a warm backend
   * too — serving the body byte-for-byte once and annotating the run to say the
   * fault was injected. What it must never do is imply the BACKEND was checked;
   * that claim belongs to the test above.
   */
  test("turns the 409 into a prompt that finishes the upload by itself", async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);

    const state = await uploadDirStatus(request);
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

    // See "WARM BACKENDS" in the file docstring. The annotation is the point:
    // a reader of the report can tell an injected 409 from a real one without
    // reading this file.
    let stubServed = false;
    if (state.configured) {
      test.info().annotations.push({
        type: "injected-fault",
        description:
          `the backend is already configured (${state.path}), so the first-use 409 ` +
          "was served by this spec, not by the server",
      });
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

    // The "Not configured" screen is the previous test's claim, and the
    // configured one is asserted at the end of this test against the directory
    // the prompt actually chose — which is a sharper check than echoing back
    // whatever the server happened to hold on the way in.

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
    /**
     * Prove the browse actually LANDED in UPLOAD_DIR before selecting.
     *
     * `FileBrowser` renders the path bar as `editPath ?? currentPath` and only
     * clears `editPath` when a browse SUCCEEDS, so while the field is being
     * edited its value is the text just typed into it — identical whether the
     * browse succeeded, failed, or is still in flight. Asserting that value
     * therefore proves nothing, and on a failed or pending browse
     * `currentPath` is still the home directory the browser opens on, which
     * "Select This Directory" would then commit in silence. Under full-suite
     * load that is precisely what happened: the guard passed and the prompt
     * was handed `/Users/danielbaier`, which `validate_candidate` rejects.
     *
     * The response the backend gave for THIS directory is the fact worth
     * waiting for, so it is what the spec waits for.
     */
    const browsed = page.waitForResponse(async (resp) => {
      if (!new URL(resp.url()).pathname.endsWith("/api/path/browse")) return false;
      if (!resp.ok()) return false;
      const body = (await resp.json().catch(() => null)) as { current?: string } | null;
      return typeof body?.current === "string" && body.current.endsWith(UPLOAD_DIR_LEAF);
    });
    await pathBar.press("Enter");
    await browsed;
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
