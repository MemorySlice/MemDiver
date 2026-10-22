import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test, expect, type Page } from "@playwright/test";
import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

/**
 * Regression: the Investigation side panel described the byte at the hex
 * cursor's NUMBER in the raw view, whatever view the viewer showed. It read
 * `/api/inspect/hex` (and the local entropy) without the viewer's view, so on
 * the gcore fixture, with the cursor on the planted secret at VAS 0x1100,
 * it said "Hex 0x33" (raw 0x1100) instead of 0x73 ('s').
 *
 * The invariant checked: the panel's byte equals the hex cell under the
 * cursor, and both equal the fixture's known byte, in every view.
 */

const GCORE_DIR = path.resolve(__dirname, "../fixtures/gcore_planted");
const CORE = path.join(GCORE_DIR, "planted.core");
const META_PATH = path.join(GCORE_DIR, "planted.json");
const gcoreAvailable = fs.existsSync(CORE) && fs.existsSync(META_PATH);

/** Byte the panel reports, as "0x.." (waits until it is loaded). */
function panelByte(page: Page) {
  return page.getByTestId("investigation-byte-hex");
}

async function goToOffset(page: Page, offset: number): Promise<void> {
  // The hex toolbar's go-to box: the "0x offset" input right before "Go"
  // (the Bookmarks side tab has another input with the same placeholder).
  const go = page.getByRole("button", { name: /^Go$/ }).first();
  await go.locator("xpath=preceding-sibling::input[1]").fill(`0x${offset.toString(16)}`);
  await go.click();
}

/** Put the cursor on `offset` and assert panel byte == hex cell == `hex`. */
async function expectByteAt(page: Page, offset: number, hex: string, view: string): Promise<void> {
  await goToOffset(page, offset);
  const panel = page.getByTestId("investigation-panel");
  await expect(panel).toHaveAttribute("data-view", view, { timeout: 10_000 });
  await expect(panel).toContainText(offset.toString(16).padStart(8, "0"));
  await expect(page.locator(`.hex-byte[data-offset="${offset}"]`)).toHaveText(hex, { timeout: 15_000 });
  await expect(panelByte(page)).toHaveText(`0x${hex}`, { timeout: 15_000 });
}

function hexViewTabs(page: Page) {
  // "Dump view mode" (gcore et al.) or "MSL view mode" (.msl).
  return page.getByRole("tablist", { name: /^(Dump|MSL) view mode$/ });
}

test.describe("investigation panel — reads the byte in the hex viewer's view", () => {
  test("gcore: VAS 0x1100 and raw 0x1b0 are the secret's 's'; raw 0x1100 is the raw byte", async ({ page }) => {
    test.skip(!gcoreAvailable, "gcore_planted fixture missing (run its generate.py)");
    test.setTimeout(90_000);
    const meta = JSON.parse(fs.readFileSync(META_PATH, "utf8")) as { raw_offset: number; vas_offset: number };
    expect(meta.vas_offset).toBe(0x1100);
    expect(meta.raw_offset).toBe(0x1b0);
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, CORE);

    const views = hexViewTabs(page);
    await expect(views).toBeVisible({ timeout: 15_000 });

    // VAS: the secret's first byte.
    const entropyRequest = page.waitForRequest(
      (r) => r.url().includes("/api/inspect/entropy") && new URL(r.url()).searchParams.get("view") === "vas",
      { timeout: 15_000 },
    );
    await views.getByRole("tab", { name: "Memory (VAS)" }).click();
    await expectByteAt(page, meta.vas_offset, "73", "vas");
    await entropyRequest; // local entropy is read in the same view
    await expect(page.getByTestId("investigation-panel")).toContainText("VAS offset 0x00001100");
    await page.screenshot({ path: test.info().outputPath("investigation-gcore-vas.png") });

    // Bookmark it in VAS (the bookmark records its view).
    const addBookmark = page.getByRole("button", { name: "Add bookmark" });
    const bookmarkRow = addBookmark.locator("xpath=..");
    await bookmarkRow.getByPlaceholder("0x offset").fill("0x1100");
    await bookmarkRow.getByPlaceholder("Label").fill("secret-vas");
    await addBookmark.click();
    await expect(page.getByTestId("bookmark-entry")).toHaveAttribute("data-view", "vas");

    // Raw: the same secret byte at its container offset ...
    await views.getByRole("tab", { name: "Raw file" }).click();
    await expectByteAt(page, meta.raw_offset, "73", "raw");
    // ... and at raw 0x1100 the container byte that the bug used to show.
    await expectByteAt(page, meta.vas_offset, "33", "raw");

    // Jumping to the VAS bookmark from the raw view lands on the same byte.
    await page.getByTestId("bookmark-entry").getByText("secret-vas").click();
    await expect(views.getByRole("tab", { name: "Memory (VAS)" })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByTestId("investigation-panel")).toHaveAttribute("data-view", "vas");
    await expect(panelByte(page)).toHaveText("0x73", { timeout: 15_000 });
    await expect(page.locator(`.hex-byte[data-offset="${meta.vas_offset}"]`)).toHaveText("73", { timeout: 15_000 });

    guards.assertClean();
  });

  test(".msl: VAS / VA / raw each read their own byte at the cursor", async ({ page }) => {
    test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
    test.setTimeout(90_000);
    // synthetic_msl/sample.msl: one captured region; VAS/VA 0x40 = 'g' (0x67),
    // stored at container offset 0x180; container offset 0x40 = 0x4d.
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath);
    const views = hexViewTabs(page);
    await expect(views).toBeVisible({ timeout: 15_000 });

    await views.getByRole("tab", { name: "Memory (VAS)" }).click();
    await expectByteAt(page, 0x40, "67", "vas");

    await views.getByRole("tab", { name: "VA", exact: true }).click();
    await expectByteAt(page, 0x40, "67", "va");
    await expect(page.getByTestId("investigation-va")).toContainText(/Virtual address 0x[0-9a-f]+/, { timeout: 10_000 });

    await views.getByRole("tab", { name: "Raw file" }).click();
    await expectByteAt(page, 0x40, "4d", "raw");
    await expectByteAt(page, 0x180, "67", "raw");

    guards.assertClean();
  });

  test("gcore: Verify-Key reads the cursor's candidate in the viewer's view", async ({ page }) => {
    test.skip(!gcoreAvailable, "gcore_planted fixture missing (run its generate.py)");
    test.setTimeout(90_000);
    const meta = JSON.parse(fs.readFileSync(META_PATH, "utf8")) as { raw_offset: number; vas_offset: number };
    // Key = the 16 bytes at the secret (raw 0x1b0 == VAS 0x1100); ciphertext =
    // the backend's fixed verification plaintext under AES-128-CBC (PKCS7).
    const key = fs.readFileSync(CORE).subarray(meta.raw_offset, meta.raw_offset + 16);
    const iv = Buffer.from([...Array(16).keys()]);
    const enc = crypto.createCipheriv("aes-128-cbc", key, iv);
    const ciphertextHex = Buffer.concat([
      enc.update("AES256_MEMDIVER_VERIFICATION_OK!"), enc.final(),
    ]).toString("hex");

    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, CORE);
    const views = hexViewTabs(page);
    await expect(views).toBeVisible({ timeout: 15_000 });

    async function verifyAtCursor(): Promise<{ view: string | null }> {
      await page.locator(tab("verify-key")).first().click();
      await page.getByTestId("verify-cipher-select").selectOption("AES-128-CBC");
      await page.getByTestId("verify-length-input").fill("16");
      await page.getByTestId("verify-ciphertext-input").fill(ciphertextHex);
      const req = page.waitForRequest((r) => r.url().includes("/api/analysis/verify-key"));
      await page.getByTestId("verify-submit-btn").click();
      return { view: (JSON.parse((await req).postData() ?? "{}") as { view?: string }).view ?? null };
    }

    // VAS 0x1100 is the secret -> verified, and the request named the view.
    await views.getByRole("tab", { name: "Memory (VAS)" }).click();
    await expectByteAt(page, meta.vas_offset, "73", "vas");
    expect((await verifyAtCursor()).view).toBe("vas");
    await expect(page.getByTestId("verify-result-verified")).toBeVisible({ timeout: 15_000 });
    await page.screenshot({ path: test.info().outputPath("verify-key-gcore-vas.png") });

    // Raw 0x1100 is another candidate -> not verified (the old behaviour
    // would have verified the raw byte whatever the viewer showed).
    await views.getByRole("tab", { name: "Raw file" }).click();
    await expectByteAt(page, meta.vas_offset, "33", "raw");
    expect((await verifyAtCursor()).view).toBe("raw");
    await expect(page.getByTestId("verify-result-verified")).toHaveCount(0, { timeout: 15_000 });
    await expect(page.getByText(/No match|did not/i).first()).toBeVisible({ timeout: 15_000 });

    guards.assertClean();
  });
});
