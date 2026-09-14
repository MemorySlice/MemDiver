import { test, expect } from "@playwright/test";
import { newSession, tab } from "../fixtures/selectors";
import { datasetAvailable } from "../fixtures/dataset";
import { enterWorkspaceWithMsl } from "../fixtures/workspace";

const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
const SESSIONS = `http://127.0.0.1:${BACKEND_PORT}/api/sessions`;

/** Per-run suffix so a crashed earlier run cannot collide with this one. */
const SAVED_NAME = `e2e-sessions-tab-${Date.now().toString(36)}`;

test.describe("Sessions side tab mounts", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present.");

  // Sessions are real server state. Only the name created below is removed.
  test.afterAll(async ({ request }) => {
    await request.delete(`${SESSIONS}/${encodeURIComponent(SAVED_NAME)}`);
  });

  test("mounts without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("response", (res) => {
      if (res.status() >= 500) errors.push(`${res.status()} ${res.url()}`);
    });
    await enterWorkspaceWithMsl(page);
    await page.locator(tab("sessions")).first().click();
    await expect(page.locator(tab("sessions")).first()).toBeVisible();
    await page.waitForTimeout(800);
    expect(errors).toEqual([]);
  });

  /**
   * Saving from this panel goes through `persistSession`, which marks the
   * workspace clean — so the unsaved-work guard must stay out of the way
   * afterwards. A guard that nags right after a successful save is as broken as
   * one that stays quiet after a real change, and this panel is the save the
   * user is most likely to make before reaching for "New Session".
   *
   * The dirty half of the guard lives in unsaved-guard.spec.ts.
   */
  test("saving here leaves the workspace clean, so New Session does not prompt", async ({
    page,
  }) => {
    test.setTimeout(120_000);

    await enterWorkspaceWithMsl(page);
    await page.locator(tab("sessions")).first().click();

    const nameInput = page.getByPlaceholder("Session name");
    await expect(nameInput).toBeVisible();
    await nameInput.fill(SAVED_NAME);
    await nameInput
      .locator("..")
      .getByRole("button", { name: "Save", exact: true })
      .click();
    await expect(page.getByText("Session saved")).toBeVisible();

    await page.locator(newSession.button).click();

    // No prompt, and straight to the session list.
    await expect(page.locator(newSession.dialog)).toHaveCount(0);
    await expect(
      page.getByRole("heading", { name: "Sessions", exact: true }),
    ).toBeVisible();
    await expect(page.getByText(SAVED_NAME, { exact: true })).toBeVisible();
  });
});
