import path from "node:path";
import { readFileSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import {
  datasetAvailable,
  syntheticMslAvailable,
  syntheticMslPath,
} from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

test.describe("Verify-key tab — basic render stub", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present on this machine.");

  test("verify-key tab mounts without crashing", async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    await enterWorkspaceWithMsl(page);

    await page.locator(tab("verify-key")).first().click();
    await expect(page.locator(tab("verify-key")).first()).toBeVisible();

    // Allow the panel a brief moment to render any network calls.
    await page.waitForTimeout(300);
    expect(pageErrors).toEqual([]);
  });
});

// --- C1: AEAD key verification on the committed synthetic MSL (CI-runnable). ---
// The synthetic sample.msl embeds a known AES-256-GCM key (0xAA*32) at VAS
// offset 0; verify-fixture.json carries the matching ciphertext/nonce/tag. The
// backend re-encrypts the 32 bytes at offset 0 and, when the tag matches, echoes
// the recovered key. This proves the whole verify-key flow end-to-end with no
// private dataset.
const VERIFY_FIXTURE = JSON.parse(
  readFileSync(
    path.resolve(__dirname, "../fixtures/verify_key/verify-fixture.json"),
    "utf8",
  ),
) as {
  offset: number;
  length: number;
  cipher: string;
  ciphertext_hex: string;
  nonce_hex: string;
  tag_hex: string;
  key_hex: string;
};

test.describe("Verify-key tab — AEAD verification (synthetic MSL)", () => {
  test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");

  test("verifies a known AES-256-GCM key at offset 0 and echoes the recovered key", async ({
    page,
  }) => {
    const guards = installErrorGuards(page);
    await enterWorkspaceWithMsl(page, syntheticMslPath, { autoAnalyze: false });

    await page.locator(tab("verify-key")).first().click();

    // The offset input parses a bare numeric string as DECIMAL (parseOffset in
    // KeyVerificationPanel); offset 0 is unambiguous either way.
    await page.getByTestId("verify-offset-input").fill(String(VERIFY_FIXTURE.offset));
    await page.getByTestId("verify-length-input").fill(String(VERIFY_FIXTURE.length));
    await page.getByTestId("verify-cipher-select").selectOption(VERIFY_FIXTURE.cipher);
    await page.getByTestId("verify-ciphertext-input").fill(VERIFY_FIXTURE.ciphertext_hex);
    await page.getByTestId("verify-nonce-input").fill(VERIFY_FIXTURE.nonce_hex);
    await page.getByTestId("verify-tag-input").fill(VERIFY_FIXTURE.tag_hex);

    const submit = page.getByTestId("verify-submit-btn");
    await expect(submit).toBeEnabled();
    await submit.click();

    // Success line + the recovered key echoed back verbatim.
    await expect(page.getByTestId("verify-result-verified")).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByTestId("verify-key-hex")).toHaveText(
      VERIFY_FIXTURE.key_hex,
      { timeout: 15_000 },
    );

    guards.assertClean();
  });
});
