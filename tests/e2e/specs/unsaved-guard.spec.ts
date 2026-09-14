import {
  test,
  expect,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

import { newSession, tab } from "../fixtures/selectors";
import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import {
  enterWorkspaceWithMsl,
  switchToExplorationMode,
} from "../fixtures/workspace";

/**
 * The unsaved-work guard: what "New Session" does to work you have not saved.
 *
 * Before the guard, both entry points — the toolbar button and Ctrl+N — called
 * `resetWizard` directly and the workspace was gone with no prompt. The unit
 * suite already proves the hook's decision table; what only a browser can prove
 * is that the two entry points really do land on the ONE guard, that the dialog
 * is a real dialog (a modal whose backdrop deliberately does not dismiss a
 * three-way choice about losing work), and that "discard" leaves a recovery
 * copy on disk that can actually be reopened.
 *
 * Fixture choice: the committed synthetic MSL, not the private dataset. The
 * guard has nothing to do with what is in the dump — it reads store state — so
 * gating these on the 215 MB corpus would only make them skip on machines that
 * could have run them. `syntheticMslAvailable` is the same tolerate-a-missing-
 * fixture gate the other synthetic specs use (see workspace-smoke.spec.ts); it
 * is effectively always true because the fixture is in the repo.
 *
 * Housekeeping: sessions are REAL server state (`~/.memdiver/sessions`, or the
 * suite's own `XDG_DATA_HOME` when the config's webServer spawned the backend).
 * Every name this file creates carries a per-run suffix and is deleted in
 * `afterAll`; nothing else is touched. `__recovery__` is the one name this spec
 * cannot make unique — it is reserved — so a pre-existing recovery copy is
 * saved before the run and written back afterwards rather than deleted.
 */

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
const SESSIONS = `${BACKEND_URL}/api/sessions`;

/** The reserved name the discard path writes to. Mirrors session-names.ts. */
const RECOVERY = "__recovery__";

/** Per-run suffix, so a crashed earlier run cannot collide with this one. */
const RUN_ID = Date.now().toString(36);
const uniqueName = (label: string) => `e2e-unsaved-guard-${label}-${RUN_ID}`;

/** Names this spec created, and is therefore allowed to delete. */
const created = new Set<string>();

interface SessionRow {
  name: string;
  display_name: string;
}

async function listSessionNames(request: APIRequestContext): Promise<string[]> {
  const res = await request.get(`${SESSIONS}/`);
  expect(res.status(), "GET /api/sessions/").toBe(200);
  const body = (await res.json()) as { sessions: SessionRow[] };
  return body.sessions.map((s) => s.name);
}

async function loadSessionJson(
  request: APIRequestContext,
  name: string,
): Promise<Record<string, unknown> | null> {
  const res = await request.get(`${SESSIONS}/${encodeURIComponent(name)}`);
  if (res.status() === 404) return null;
  expect(res.status(), `GET /api/sessions/${name}`).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

/**
 * Enter the workspace and make it dirty in the way a user does.
 *
 * The mode toggle is the smallest real change that is both part of the session
 * snapshot (so the digest moves) and independently visible on screen (the
 * exploration-only bottom tabs appear), which is what lets "cancel changed
 * nothing" and "the recovery copy really holds the discarded work" be asserted
 * against something other than the guard's own dialog.
 */
async function enterDirtyWorkspace(page: Page): Promise<void> {
  await enterWorkspaceWithMsl(page, syntheticMslPath);
  await switchToExplorationMode(page);
  await expect(page.locator(tab("entropy"))).toBeVisible();
}

/** The session landing page — where every reset is supposed to end up. */
function sessionList(page: Page) {
  return page.getByRole("heading", { name: "Sessions", exact: true });
}

test.describe("unsaved work guard", () => {
  test.skip(!syntheticMslAvailable, "Synthetic MSL fixture missing.");

  /** A recovery copy that was already on disk is borrowed, not destroyed. */
  let priorRecovery: Record<string, unknown> | null = null;

  test.beforeAll(async ({ request }) => {
    priorRecovery = await loadSessionJson(request, RECOVERY);
  });

  test.afterAll(async ({ request }) => {
    for (const name of created) {
      await request.delete(`${SESSIONS}/${encodeURIComponent(name)}`);
    }
    created.clear();

    await request.delete(`${SESSIONS}/${encodeURIComponent(RECOVERY)}`);
    if (priorRecovery) {
      // Put the user's own discarded work back exactly as it was found. The
      // save endpoint ignores the server-stamped fields the load returned.
      await request.post(`${SESSIONS}/`, { data: priorRecovery });
    }
  });

  test("clean workspace: a loaded session starts a new one with no dialog", async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);

    // Arrange a session to load. A freshly LOADED session is the only clean
    // workspace there is: completing the wizard leaves `lastSavedDigest` null,
    // which the guard reads (correctly) as unsaved.
    const name = uniqueName("clean");
    await enterDirtyWorkspace(page);
    await page.locator(newSession.button).click();
    await page.locator(newSession.name).fill(name);
    created.add(name);
    await page.locator(newSession.save).click();
    await expect(sessionList(page)).toBeVisible();

    const row = page.locator(".md-panel").filter({ hasText: name }).first();
    await row.getByRole("button", { name: "Load", exact: true }).click();

    // Restored, and restored INTO exploration mode — the change that was saved.
    await expect(page.locator(tab("bookmarks"))).toBeVisible({ timeout: 60_000 });
    await expect(page.locator(tab("entropy"))).toBeVisible();

    // The act under test: nothing is unsaved, so the guard must not ask.
    await page.locator(newSession.button).click();
    await expect(sessionList(page)).toBeVisible();
    await expect(page.locator(newSession.dialog)).toHaveCount(0);

    // Nothing extra was written behind the reset. The recovery check is
    // against the state this run INHERITED, not against "absent": a developer
    // who discarded something yesterday has a recovery copy on disk, and a
    // clean reset must neither add one nor touch theirs.
    const names = await listSessionNames(request);
    expect(names.filter((n) => n === name)).toHaveLength(1);
    expect(names.includes(RECOVERY)).toBe(priorRecovery !== null);
  });

  test("dirty workspace: the toolbar button opens a real dialog, and cancel changes nothing", async ({
    page,
  }) => {
    await enterDirtyWorkspace(page);

    await page.locator(newSession.button).click();
    const dialog = page.locator(newSession.dialog);
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute("role", "dialog");
    await expect(dialog).toHaveAttribute("aria-modal", "true");

    // Pre-filled with <dump-leaf>-YYYY-MM-DD-HHmm, and editable.
    await expect(page.locator(newSession.name)).toHaveValue(
      /^sample\.msl-\d{4}-\d{2}-\d{2}-\d{4}$/,
    );

    // The backdrop deliberately does NOT dismiss a three-way choice about
    // losing work. Click its top-left corner: the dialog itself is centred, so
    // this lands on the overlay and nothing else.
    await page
      .locator(newSession.overlay)
      .click({ position: { x: 4, y: 4 } });
    await expect(dialog).toBeVisible();

    await page.locator(newSession.cancel).click();
    await expect(dialog).toHaveCount(0);

    // "Exactly as it was": still in the workspace, still in exploration mode.
    await expect(page.locator(tab("bookmarks"))).toBeVisible();
    await expect(page.locator(tab("entropy"))).toBeVisible();
    await expect(sessionList(page)).toHaveCount(0);
  });

  test("dirty workspace: Ctrl+N reaches the same guard as the button", async ({
    page,
  }) => {
    await enterDirtyWorkspace(page);

    await page.keyboard.press("Control+n");

    const dialog = page.locator(newSession.dialog);
    await expect(dialog).toBeVisible();
    await expect(page.locator(newSession.name)).toHaveValue(
      /^sample\.msl-\d{4}-\d{2}-\d{2}-\d{4}$/,
    );

    // The shortcut stays bound while the dialog has focus; pressing it again
    // must not re-open (and so must not reset the name field under the user).
    await page.locator(newSession.name).fill("typed-by-the-user");
    await page.keyboard.press("Control+n");
    await expect(page.locator(newSession.name)).toHaveValue("typed-by-the-user");

    await page.locator(newSession.cancel).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.locator(tab("entropy"))).toBeVisible();
  });

  test("save: persists under the typed name, then resets to the session list", async ({
    page,
    request,
  }) => {
    const name = uniqueName("save");
    await enterDirtyWorkspace(page);

    await page.locator(newSession.button).click();
    await page.locator(newSession.name).fill(name);
    created.add(name);
    await page.locator(newSession.save).click();

    await expect(sessionList(page)).toBeVisible();
    await expect(page.locator(newSession.dialog)).toHaveCount(0);
    await expect(page.getByText(name, { exact: true })).toBeVisible();

    // On the server, under the typed name, holding the change that was made.
    expect(await listSessionNames(request)).toContain(name);
    const saved = await loadSessionJson(request, name);
    expect(saved?.mode).toBe("exploration");
    expect(saved?.input_path).toBe(syntheticMslPath);
  });

  test("discard: writes a recovery copy first, pins it, relabels it, and can reopen it", async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);

    // A decoy session so "pinned first" means something. Filenames are listed
    // in DESCENDING order, so a "zz-" name outranks "__recovery__" server-side
    // and only the landing page's own partition can put recovery on top.
    const decoy = `zz-${uniqueName("decoy")}`;
    const decoyRes = await request.post(`${SESSIONS}/`, {
      data: { session_name: decoy, input_mode: "single_file", mode: "verification" },
    });
    expect(decoyRes.status(), "POST decoy session").toBe(200);
    created.add(decoy);

    await enterDirtyWorkspace(page);

    await page.locator(newSession.button).click();
    await page.locator(newSession.discard).click();

    await expect(sessionList(page)).toBeVisible();
    await expect(page.locator(newSession.dialog)).toHaveCount(0);

    const recovery = page.locator(newSession.recoveryRow);
    await expect(recovery).toBeVisible();

    // Written BEFORE the reset — proved by its contents, which only existed
    // in the stores that the reset went on to wipe.
    const copy = await loadSessionJson(request, RECOVERY);
    expect(copy?.mode).toBe("exploration");
    expect(copy?.input_path).toBe(syntheticMslPath);

    // Pinned first, ahead of a session the API listed before it.
    await expect(page.getByText(decoy, { exact: true })).toBeVisible();
    const pinnedFirst = await recovery.evaluate(
      (el) => el.parentElement?.firstElementChild === el,
    );
    expect(pinnedFirst, "recovery row is the first row in the list").toBe(true);

    // Relabelled, badged — and the reserved name never reaches the screen.
    await expect(recovery).toContainText("Recovered work");
    await expect(recovery).toContainText("RECOVERED");
    const rendered = await page.locator("body").innerText();
    expect(rendered).not.toContain(RECOVERY);

    // And it is a real way back: loading it restores the discarded work.
    await recovery.getByRole("button", { name: "Load", exact: true }).click();
    await expect(page.locator(tab("bookmarks"))).toBeVisible({ timeout: 60_000 });
    await expect(page.locator(tab("entropy"))).toBeVisible();
  });

  test("a dirty workspace prompts the browser before it is closed", async ({
    page,
  }) => {
    await enterDirtyWorkspace(page);

    const dialog = page.waitForEvent("dialog");
    await page.close({ runBeforeUnload: true });
    const beforeUnload = await dialog;
    expect(beforeUnload.type()).toBe("beforeunload");
    await beforeUnload.accept();
  });
});
