import path from "node:path";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { test, expect } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

/**
 * C2 — NSS key-log composer + export, on the committed synthetic MSL (CI-runnable).
 *
 * Layer 1 drives the multi-secret composer directly from keylog/expected.json and
 * asserts the downloaded ``memdiver.keylog`` contains the exact NSS lines.
 * Layer 2 reuses the C1 verify flow → "Add to key log" prefills a composer row
 * with the recovered key; supplying the real client_random makes it exportable.
 */

const KEYLOG_FIXTURE = JSON.parse(
  readFileSync(path.resolve(__dirname, "../fixtures/keylog/expected.json"), "utf8"),
) as {
  client_random: string;
  entries: Array<{ label: string; client_random: string; secret: string }>;
  expected_lines: string[];
};

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

async function openVerifyKeyTab(page: import("@playwright/test").Page) {
  await enterWorkspaceWithMsl(page, syntheticMslPath, { autoAnalyze: false });
  await page.locator(tab("verify-key")).first().click();
}

test.describe("Key-log composer export (synthetic MSL)", () => {
  test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");

  test("Layer 1 — composer exports the exact NSS lines for multiple entries", async ({
    page,
  }) => {
    const guards = installErrorGuards(page);
    await openVerifyKeyTab(page);

    // Use the first two fixture secrets — two fully-valid entries.
    const chosen = KEYLOG_FIXTURE.entries.slice(0, 2);
    for (let i = 0; i < chosen.length; i++) {
      await page.getByTestId("keylog-add-entry").click();
    }
    const rows = page.getByTestId("keylog-entry-row");
    await expect(rows).toHaveCount(chosen.length);

    for (let i = 0; i < chosen.length; i++) {
      const row = rows.nth(i);
      await row.getByTestId("keylog-entry-secret-type").selectOption(chosen[i].label);
      await row.getByTestId("keylog-entry-client-random").fill(chosen[i].client_random);
      await row.getByTestId("keylog-entry-secret").fill(chosen[i].secret);
    }

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByTestId("keylog-export").click(),
    ]);
    expect(download.suggestedFilename()).toBe("memdiver.keylog");
    const body = await readFile((await download.path())!, "utf8");

    // Exact byte-for-byte match: the export must be PRECISELY these canonical
    // NSS lines, in composer order, with no missing/duplicate/misordered lines
    // and no stray header/trailing content. The composer preserves add order
    // (buildSecrets filters+maps in order) and the fixture lines are pre-rendered
    // in that same order, so the whole file body must equal their concatenation.
    const expectedLines = KEYLOG_FIXTURE.expected_lines.slice(0, chosen.length);
    expect(body).toBe(expectedLines.join(""));

    guards.assertClean();
  });

  test("Layer 2 — Add-to-key-log prefills the recovered key, then exports its line", async ({
    page,
  }) => {
    const guards = installErrorGuards(page);
    await openVerifyKeyTab(page);

    // Recover the key first (same flow as C1).
    await page.getByTestId("verify-offset-input").fill(String(VERIFY_FIXTURE.offset));
    await page.getByTestId("verify-length-input").fill(String(VERIFY_FIXTURE.length));
    await page.getByTestId("verify-cipher-select").selectOption(VERIFY_FIXTURE.cipher);
    await page.getByTestId("verify-ciphertext-input").fill(VERIFY_FIXTURE.ciphertext_hex);
    await page.getByTestId("verify-nonce-input").fill(VERIFY_FIXTURE.nonce_hex);
    await page.getByTestId("verify-tag-input").fill(VERIFY_FIXTURE.tag_hex);
    await page.getByTestId("verify-submit-btn").click();
    await expect(page.getByTestId("verify-result-verified")).toBeVisible({
      timeout: 15_000,
    });

    // Push the verified key into the composer: a new row appears, prefilled with
    // the recovered secret (secretType defaults to CLIENT_TRAFFIC_SECRET_0).
    await page.getByTestId("verify-add-to-keylog").click();
    const row = page.getByTestId("keylog-entry-row").first();
    await expect(row).toBeVisible();
    await expect(row.getByTestId("keylog-entry-secret")).toHaveValue(
      VERIFY_FIXTURE.key_hex,
    );

    // Memory alone yields no client_random — the analyst supplies the real one
    // (here the fixture TLS session's) to make the entry exportable.
    const clientRandom = KEYLOG_FIXTURE.client_random;
    await row.getByTestId("keylog-entry-client-random").fill(clientRandom);

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByTestId("keylog-export").click(),
    ]);
    expect(download.suggestedFilename()).toBe("memdiver.keylog");
    const body = await readFile((await download.path())!, "utf8");

    // entryFromVerifiedKey seeds secretType = CLIENT_TRAFFIC_SECRET_0. This is
    // the only composer row, so the exported body must equal exactly its single
    // canonical NSS line (no extra/duplicate lines, no stray header).
    const expectedLine = `CLIENT_TRAFFIC_SECRET_0 ${clientRandom} ${VERIFY_FIXTURE.key_hex}\n`;
    expect(body).toBe(expectedLine);

    guards.assertClean();
  });
});
