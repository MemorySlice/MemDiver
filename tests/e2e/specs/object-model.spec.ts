/**
 * E2E for the "Object model" sidebar tab on REAL data: learn a TLS 1.3 session-state
 * object layout from 8 openssl dumps (needle = CLIENT_TRAFFIC_SECRET_0), build + export
 * the model, then validate it on held-out runs.
 *
 * Corpus-gated: skipped when the experiment2_tls_local openssl runs are absent.
 * Env: MEMDIVER_TLS13_OPENSSL (corpus dir), OM_OUT_DIR (where the model/plugin are
 * written, default <e2e memdiver home>/object-model-out), OM_SHOTS (screenshot dir, optional).
 */
import { test, expect, type Page } from "@playwright/test";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

const CORPUS =
  process.env.MEMDIVER_TLS13_OPENSSL ??
  "/Users/danielbaier/research/projects/github/issues/2024 fritap issues/2026_success/mempdumps/experiment2_tls_local/data/TLS13/openssl";
// The server only WRITES inside its upload dir or MemDiver home (403 elsewhere), so the
// default is the e2e backend's own home (tests/e2e/.memdiver-home, gitignored).
const OUT_DIR =
  process.env.OM_OUT_DIR ?? path.join(__dirname, "..", ".memdiver-home", "memdiver", "object-model-out");
const SHOTS = process.env.OM_SHOTS ?? "";
const LEARN = [1, 2, 3, 4, 5, 6, 7, 8];
const HELD = [9, 10, 11, 12];

const runDir = (n: number) => path.join(CORPUS, `openssl_run_13_${n}`);
const keylogPath = (n: number) => path.join(runDir(n), "keylog.csv");
const dumpPath = (n: number) => {
  const d = path.join(runDir(n), "dumps", "msl");
  return path.join(d, readdirSync(d).find((f) => f.endsWith(".msl")) as string);
};
const corpusAvailable = [...LEARN, ...HELD].every(
  (n) => existsSync(keylogPath(n)) && existsSync(path.join(runDir(n), "dumps", "msl")),
);

/** `LABEL client_random secret` lines -> { LABEL: [client_random, secret] }. */
function keylog(n: number): Record<string, [string, string]> {
  const out: Record<string, [string, string]> = {};
  for (const line of readFileSync(keylogPath(n), "utf8").split("\n")) {
    const [label, cr, secret] = line.trim().split(/\s+/);
    if (label && cr && secret) out[label] = [cr, secret];
  }
  return out;
}

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

test.describe("Object model tab (real openssl TLS 1.3 corpus) @requires-dataset", () => {
  test.skip(!corpusAvailable, "openssl TLS13 corpus not available");
  test.setTimeout(300_000);

  test("anchor -> layout -> build -> export -> validate", async ({ page }) => {
    const guards = installErrorGuards(page);
    const stamp = Date.now();
    mkdirSync(OUT_DIR, { recursive: true });
    const modelOut = path.join(OUT_DIR, `om_${stamp}.json`);
    const pluginOut = path.join(OUT_DIR, `om_${stamp}.py`);

    const outOfRange: string[] = [];
    page.on("response", async (r) => {
      if (!r.url().includes("/api/inspect/hex-raw")) return;
      const body = await r.text().catch(() => "");
      if (body.includes("offset out of range")) outOfRange.push(r.url());
    });

    // 1. Open the 8 learning dumps: first through the wizard, the other 7 by path.
    await enterWorkspaceWithMsl(page, dumpPath(LEARN[0]));
    await page.locator(tab("dumps")).first().click();
    for (const n of LEARN.slice(1)) {
      const add = page.getByPlaceholder("Server path to dump file");
      await add.fill(dumpPath(n));
      await add.press("Enter");
      await expect(page.locator('[data-testid="dump-row"]')).toHaveCount(LEARN.indexOf(n) + 1, { timeout: 30_000 });
    }
    await expect(page.locator('[data-testid="dump-row"]')).toHaveCount(8);
    await shot(page, "01-dumps-open");

    // 2. Object model tab, per-dump needles, window, related values.
    await page.locator(tab("object")).click();
    const panel = page.getByTestId("object-model-panel");
    await expect(panel).toBeVisible();
    for (const n of LEARN) {
      const base = path.basename(dumpPath(n));
      await panel.getByLabel(`Needle for ${base}`, { exact: true }).fill(keylog(n).CLIENT_TRAFFIC_SECRET_0[1]);
    }
    await panel.getByLabel("Delta start").fill("-2048");
    await panel.getByLabel("Window length").fill("5632");
    for (const [name, label] of [["client_random", null], ["server_traffic_secret_0", "SERVER_TRAFFIC_SECRET_0"]] as const) {
      await panel.getByRole("button", { name: "Add related value" }).click();
      await panel.getByLabel("Related value name").last().fill(name);
      for (const n of LEARN) {
        const base = path.basename(dumpPath(n));
        const val = label ? keylog(n)[label][1] : keylog(n).CLIENT_TRAFFIC_SECRET_0[0];
        await panel.getByLabel(`${name} hex for ${base}`, { exact: true }).fill(val);
      }
    }
    await shot(page, "02-inputs");

    // 3. Anchor consensus.
    const anchorResp = page.waitForResponse((r) => r.url().includes("/consensus/anchor") && r.request().method() === "POST");
    await panel.getByRole("button", { name: "Anchor consensus" }).click();
    const anchor = await (await anchorResp).json();
    await expect(page.getByTestId("anchor-results")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByTestId("instances").locator("tbody tr")).toHaveCount(8);
    await expect(page.getByTestId("unanchored")).toHaveCount(0);
    console.log("ANCHOR instances/unanchored:", JSON.stringify(anchor).slice(0, 300));
    await shot(page, "03-anchor");

    // 4. Propose layout.
    const proposeRequest = page.waitForRequest((r) => r.url().includes("/api/semantic/propose-layout"));
    await panel.getByRole("button", { name: "Propose layout" }).click();
    // The panel shows per-field evidence, so the client must ask for the full payload
    // (the server default is "summary").
    expect(JSON.parse((await proposeRequest).postData() ?? "{}").detail).toBe("full");
    await expect(page.getByTestId("layout-results")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByTestId("field-row").first().locator("td").last()).not.toBeEmpty();
    await expect(page.getByTestId("bounds")).toContainText("-0x6fc");
    await expect(page.getByTestId("bounds")).toContainText("5392"); // 0x1510
    const rows = page.getByTestId("field-row");
    const crRow = rows.filter({ hasText: "client_random" });
    const stsRow = rows.filter({ hasText: "server_traffic_secret_0" });
    await expect(crRow.first()).toContainText("-0x5bc");
    await expect(stsRow.first()).toContainText("+0x40");
    await crRow.first().click();
    // The hex view must show THIS run's client_random at anchor.offset + delta (in the instance's view).
    const inst = anchor.instances[0];
    expect(inst.dump_path).toBe(dumpPath(LEARN[0]));
    const target = inst.offset + -0x5bc;
    const expectedHex = keylog(LEARN[0]).CLIENT_TRAFFIC_SECRET_0[0];
    const cells = page.locator(`.hex-byte[data-col="hex"]`);
    await expect(page.locator(`.hex-byte[data-col="hex"][data-offset="${target + 31}"]`)).toBeVisible({ timeout: 30_000 });
    const shown: string[] = [];
    for (let i = 0; i < 32; i++) {
      shown.push((await page.locator(`.hex-byte[data-col="hex"][data-offset="${target + i}"]`).first().innerText()).trim());
    }
    console.log(`HEX view=${inst.view} address=0x${target.toString(16)} bytes=${shown.join("")}`);
    expect(shown.join("")).toBe(expectedHex);
    expect(cells.first()).toBeTruthy();
    expect(outOfRange).toEqual([]);
    await shot(page, "04-layout");

    // 5. Build model + export plugin.
    const build = page.getByTestId("build-model");
    await build.getByLabel("Model name").fill("openssl_tls13_session");
    await build.getByLabel("Meaning for anchor").fill("CLIENT_TRAFFIC_SECRET_0");
    await build.getByLabel("Meaning for server_traffic_secret_0").fill("SERVER_TRAFFIC_SECRET_0");
    await build.getByLabel("Meaning for client_random").fill("tls.client_random");
    // Validation scores against keylog LABELS: without an output label the server refuses
    // ("no labels: the model has no labelled assertions") and the UI has no other way to pass them.
    await build.getByLabel("Output label for anchor").fill("CLIENT_TRAFFIC_SECRET_0");
    await build.getByLabel("Output label for server_traffic_secret_0").fill("SERVER_TRAFFIC_SECRET_0");
    for (const src of ["anchor", "server_traffic_secret_0"]) {
      await build.getByRole("button", { name: "Add relationship" }).click();
      const n = await build.getByLabel("Source field").count();
      await build.getByLabel("Source field").nth(n - 1).selectOption(src);
      await build.getByLabel("Target field").nth(n - 1).selectOption("client_random");
    }
    await build.getByLabel("Model JSON output path (new .json file)").fill(modelOut);
    await build.getByRole("button", { name: "Build model", exact: true }).click();
    await expect(page.getByTestId("build-result")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("build-error")).toHaveCount(0);
    await build.getByLabel("Plugin output path (new .py file)").fill(pluginOut);
    await page.getByTestId("export-plugin").getByRole("button", { name: "Export plugin" }).click();
    await expect(page.getByTestId("export-result")).toBeVisible({ timeout: 60_000 });
    expect(existsSync(modelOut) && existsSync(pluginOut)).toBe(true);
    await shot(page, "05-built-exported");

    // 6. Validate on the 4 held-out runs, plus a learning dump (leak).
    const val = page.getByTestId("validate-model");
    for (const n of HELD) {
      await val.getByRole("button", { name: "Add held-out dump" }).click();
      await val.getByLabel("Held-out dump path").last().fill(dumpPath(n));
      await val.getByLabel("Keylog path").last().fill(keylogPath(n));
    }
    await val.getByRole("button", { name: "Validate", exact: true }).click();
    await expect(page.getByTestId("validate-result")).toBeVisible({ timeout: 180_000 });
    // First badge = the overall verdict (per-capture rows carry their own badges).
    await expect(page.getByTestId("verdict-badge").first()).toHaveAttribute("data-verdict", "pass");
    const totals = (await page.getByTestId("validate-totals").locator("td").allInnerTexts()).join("|");
    console.log("VALIDATE totals:", totals);
    expect(totals).toMatch(/\|8\|8\|0\|0\|8\/8\|/);
    await shot(page, "06-validate-pass");
    guards.assertClean(); // the happy path is clean; the deliberate refusal below is a 400

    await val.getByRole("button", { name: "Add held-out dump" }).click();
    await val.getByLabel("Held-out dump path").last().fill(dumpPath(LEARN[0]));
    await val.getByLabel("Keylog path").last().fill(keylogPath(LEARN[0]));
    await expect(page.getByTestId("leak-warning")).toBeVisible();
    await val.getByRole("button", { name: "Validate", exact: true }).click();
    await expect(page.getByTestId("validate-error")).toBeVisible({ timeout: 60_000 });
    console.log("LEAK refusal:", await page.getByTestId("validate-error").innerText());
    await shot(page, "07-leak");

    // The ONLY console error allowed is the leak refusal's own 400 (no 5xx, nothing else).
    expect(guards.consoleErrors.filter((e) => !/status of 400/.test(e))).toEqual([]);
    expect(guards.serverErrors).toEqual([]);
  });
});
