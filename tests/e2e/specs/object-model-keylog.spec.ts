/**
 * E2E for the Object model panel's KEY LOG input on the REAL openssl TLS 1.3 corpus: one
 * shared NSS key log (a concatenation of 16 runs' keylog.csv) uploaded through the browser
 * file picker anchors 8 learning dumps with nothing typed, builds a pre-filled model, and
 * validates 8 held-out dumps against the SAME file. Corpus-gated.
 * Env: MEMDIVER_TLS13_OPENSSL, OM_OUT_DIR (server-allowed write dir), OM_SHOTS, OM_DENIED_DIR.
 */
import { test, expect, type Page } from "@playwright/test";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";
import { tab } from "../fixtures/selectors";

const CORPUS =
  process.env.MEMDIVER_TLS13_OPENSSL ??
  "/Users/danielbaier/research/projects/github/issues/2024 fritap issues/2026_success/mempdumps/experiment2_tls_local/data/TLS13/openssl";
const OUT_DIR =
  process.env.OM_OUT_DIR ?? path.join(__dirname, "..", ".memdiver-home", "memdiver", "object-model-out");
const SHOTS = process.env.OM_SHOTS ?? "";
const DENIED_DIR = process.env.OM_DENIED_DIR ?? "/private/tmp/om-denied-dir";
const LEARN = [1, 2, 3, 4, 5, 6, 7, 8];
const HELD = [9, 10, 11, 12, 13, 14, 15, 16];
const ALL = [...LEARN, ...HELD];

const runDir = (n: number) => path.join(CORPUS, `openssl_run_13_${n}`);
const keylogPath = (n: number) => path.join(runDir(n), "keylog.csv");
const dumpPath = (n: number) => {
  const d = path.join(runDir(n), "dumps", "msl");
  return path.join(d, readdirSync(d).find((f) => f.endsWith(".msl")) as string);
};
const corpusAvailable = ALL.every((n) => existsSync(keylogPath(n)) && existsSync(path.join(runDir(n), "dumps", "msl")));
const clientRandom = (n: number) =>
  readFileSync(keylogPath(n), "utf8").split("\n").find((l) => l.startsWith("CLIENT_TRAFFIC_SECRET_0"))!.split(" ")[1];

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

/** A real concatenation of the runs' key logs (each keeps its own `line` header). */
function writeSharedKeylog(file: string, truncateRun?: number) {
  mkdirSync(path.dirname(file), { recursive: true });
  const parts = ALL.map((n) => {
    let text = readFileSync(keylogPath(n), "utf8");
    if (n === truncateRun) {
      text = text.split("\n").map((l) => {
        if (!l.startsWith("CLIENT_TRAFFIC_SECRET_0")) return l;
        const [a, b] = l.split(" ");
        return `${a} ${b} ${l.split(" ")[2].slice(0, 4)}`;
      }).join("\n");
    }
    return text.endsWith("\n") ? text : text + "\n";
  });
  writeFileSync(file, parts.join(""));
}

const crs0 = (t: string | null) => (t ?? "").replace(/\s+/g, " ");

async function openLearningDumps(page: Page) {
  await enterWorkspaceWithMsl(page, dumpPath(LEARN[0]));
  await page.locator(tab("dumps")).first().click();
  for (const n of LEARN.slice(1)) {
    const add = page.getByPlaceholder("Server path to dump file");
    await add.fill(dumpPath(n));
    await add.press("Enter");
    await expect(page.locator('[data-testid="dump-row"]')).toHaveCount(LEARN.indexOf(n) + 1, { timeout: 30_000 });
  }
  await page.locator(tab("object")).click();
}

async function uploadKeylog(page: Page, file: string) {
  const panel = page.getByTestId("object-model-panel");
  await panel.getByLabel("Anchor input").selectOption({ label: "Key log" });
  await panel.getByTestId("keylog-input").getByLabel("Key log file").setInputFiles(file);
  await expect(page.getByTestId("keylog-file-summary")).toBeVisible();
  return panel;
}

test.describe("Object model key log input (real openssl TLS 1.3 corpus) @requires-dataset", () => {
  test.skip(!corpusAvailable, "openssl TLS13 corpus not available");
  test.setTimeout(300_000);

  test("shared key log: anchor -> layout -> build (nothing typed) -> export -> validate", async ({ page }) => {
    const guards = installErrorGuards(page);
    const stamp = Date.now();
    mkdirSync(OUT_DIR, { recursive: true });
    const shared = path.join(OUT_DIR, `shared_${stamp}.keylog`);
    writeSharedKeylog(shared);
    const modelOut = path.join(OUT_DIR, `omk_${stamp}.json`);
    const pluginOut = path.join(OUT_DIR, `omk_${stamp}.py`);

    await openLearningDumps(page);
    const panel = await uploadKeylog(page, shared);
    console.log("KEYLOG file summary:", await page.getByTestId("keylog-file-summary").innerText());
    await expect(panel.getByLabel("Anchor label")).toHaveValue("");
    await shot(page, "k01-keylog-input");

    // Anchor consensus: 8 anchored via key log, each with its own client_random.
    await panel.getByRole("button", { name: "Anchor consensus" }).click();
    await expect(page.getByTestId("anchor-results")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByTestId("instances").locator("tbody tr")).toHaveCount(8);
    const resRows = page.getByTestId("keylog-resolution-row");
    await expect(resRows).toHaveCount(8);
    await expect(page.getByTestId("keylog-unanchored")).toHaveCount(0);
    for (let i = 0; i < 8; i++) {
      await expect(resRows.nth(i)).toHaveAttribute("data-status", "anchored");
      await expect(resRows.nth(i)).toContainText(clientRandom(LEARN[i]));
    }
    console.log("RESOLUTION title:", await page.getByTestId("keylog-resolution").locator("caption").innerText());
    await shot(page, "k02-anchor-resolution");

    // Layout.
    await panel.getByRole("button", { name: "Propose layout" }).click();
    await expect(page.getByTestId("layout-results")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByTestId("bounds")).toContainText("-0x6fc");
    await expect(page.getByTestId("bounds")).toContainText("5392");
    await expect(page.getByTestId("field-row").filter({ hasText: "client_random" }).first()).toContainText("-0x5bc");
    await expect(page.getByTestId("field-row").filter({ hasText: "server_traffic_secret_0" }).first()).toContainText("+0x40");
    await shot(page, "k03-layout");

    // Build with ONLY name + out path; first an out path outside the allowed locations.
    const build = page.getByTestId("build-model");
    await build.getByLabel("Model name").fill("openssl_tls13_keylog");
    await build.getByLabel("Model JSON output path (new .json file)").fill(path.join(DENIED_DIR, "denied.json"));
    await build.getByRole("button", { name: "Build model", exact: true }).click();
    await expect(page.getByTestId("build-error")).toBeVisible({ timeout: 30_000 });
    const denied = await page.getByTestId("build-error").innerText();
    console.log("DENIED 403 text:", denied.replace(/\n/g, " "));
    expect(denied).toMatch(/memdiver\. Example/);
    await shot(page, "k04-denied");
    await build.getByLabel("Model JSON output path (new .json file)").fill(modelOut);
    await build.getByRole("button", { name: "Build model", exact: true }).click();
    await expect(page.getByTestId("build-result")).toBeVisible({ timeout: 60_000 });
    console.log("PREFILL notice visible:", await build.getByText(/pre-filled from the key log/).count());
    await build.getByLabel("Plugin output path (new .py file)").fill(pluginOut);
    await page.getByTestId("export-plugin").getByRole("button", { name: "Export plugin" }).click();
    await expect(page.getByTestId("export-result")).toBeVisible({ timeout: 60_000 });
    await shot(page, "k05-built-exported");

    // Validate the 8 held-out dumps with the SAME shared key log file.
    const val = page.getByTestId("validate-model");
    await val.getByLabel("Key log for the held-out dumps").selectOption({ label: "One key log file (from this browser) for all held-out dumps" });
    await val.getByLabel("Key log file").setInputFiles(shared);
    for (const n of HELD) {
      await val.getByRole("button", { name: "Add held-out dump" }).click();
      await val.getByLabel("Held-out dump path").last().fill(dumpPath(n));
    }
    await val.getByRole("button", { name: "Validate", exact: true }).click();
    await expect(page.getByTestId("validate-result")).toBeVisible({ timeout: 240_000 });
    console.log("VERDICT:", await page.getByTestId("verdict-badge").first().getAttribute("data-verdict"));
    console.log("CAPTURE rows:", await page.getByTestId("validate-row").count());
    console.log("TOTALS:", (await page.getByTestId("validate-totals").locator("td").allInnerTexts()).join("|"));
    await shot(page, "k06-validate");
    await expect(page.getByTestId("verdict-badge").first()).toHaveAttribute("data-verdict", "pass");
    await expect(page.getByTestId("validate-row")).toHaveCount(8);
    const rowVerdicts = await page.getByTestId("validate-row").evaluateAll((r) => r.map((x) => x.getAttribute("data-verdict")));
    console.log("ROW verdicts:", rowVerdicts.join(","));

    // Same held-out validation with a shared key log holding ONE truncated line: the parse
    // report must appear next to the verdict.
    const badHeld = path.join(OUT_DIR, `shared_bad_held_${stamp}.keylog`);
    writeSharedKeylog(badHeld, HELD[0]);
    await val.getByLabel("Key log file").setInputFiles(badHeld);
    await val.getByRole("button", { name: "Validate", exact: true }).click();
    const vReport = val.getByTestId("keylog-parse-report");
    await expect(vReport).toBeVisible({ timeout: 240_000 });
    await expect(val.getByTestId("validate-result")).toBeVisible();
    console.log("VALIDATE parse report:", (await vReport.innerText()).replace(/\n/g, " | "));
    console.log("VALIDATE verdict with bad log:", await page.getByTestId("verdict-badge").first().getAttribute("data-verdict"));
    await expect(vReport).toContainText(/Line \d+/);
    await shot(page, "k08-validate-parse-report");

    // Only the deliberate 403 is allowed.
    expect(guards.consoleErrors.filter((e) => !/status of 403/.test(e))).toEqual([]);
    expect(guards.serverErrors).toEqual([]);
  });

  test("a truncated secret is reported and never anchors a dump to a wrong session", async ({ page }) => {
    const guards = installErrorGuards(page);
    const bad = path.join(OUT_DIR, `shared_bad_${Date.now()}.keylog`);
    writeSharedKeylog(bad, LEARN[2]);
    await openLearningDumps(page);
    const panel = await uploadKeylog(page, bad);
    await panel.getByRole("button", { name: "Anchor consensus" }).click();
    await expect(page.getByTestId("keylog-resolution")).toBeVisible({ timeout: 120_000 });
    const statuses = await page.getByTestId("keylog-resolution-row").evaluateAll((rows) =>
      rows.map((r) => `${(r.querySelector("td") as HTMLElement).title.split("openssl_run_")[1].slice(0, 5)}:${r.getAttribute("data-status")}`));
    console.log("NEG statuses:", statuses.join(" "));
    console.log("NEG warnings:", await page.getByTestId("warnings").allInnerTexts().catch(() => []));
    console.log("NEG alerts:", await page.getByRole("alert").allInnerTexts());
    console.log("NEG instances:", await page.getByTestId("instances").locator("tbody tr").count());
    console.log("NEG run3 row:", crs0(await page.getByTestId("keylog-resolution-row").nth(2).textContent()));
    console.log("NEG malformed mentions in panel:", JSON.stringify(((await panel.innerText()).match(/[^\n]*(malformed|invalid|skipped|truncat|ignored)[^\n]*/gi)) ?? []));
    const report = page.getByTestId("keylog-parse-report");
    await expect(report).toBeVisible();
    const reportText = (await report.innerText()).replace(/\n/g, " | ");
    console.log("NEG parse report:", reportText);
    await expect(report).toContainText(/Line \d+/);
    await expect(report).toContainText(/secret is 2 bytes/);
    await shot(page, "k07-negative");
    const run3 = page.getByTestId("keylog-resolution-row").nth(2);
    await expect(run3).not.toHaveAttribute("data-status", "anchored");
    const crs = await page.getByTestId("keylog-resolution-row").evaluateAll((rows) => rows.map((r) => r.textContent ?? ""));
    expect(crs[2]).not.toContain(clientRandom(LEARN[2])); // never anchored on its own run's (broken) line
    for (let i = 0; i < 8; i++) {
      if (i === 2) continue;
      expect(crs[i]).toContain(clientRandom(LEARN[i])); // every other dump keeps its OWN session
    }
    expect(guards.serverErrors).toEqual([]);
  });
});
