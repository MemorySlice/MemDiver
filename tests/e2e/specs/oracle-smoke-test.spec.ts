/**
 * Oracle smoke test — the server-composed control/decoy run.
 *
 * WHAT REGRESSED BEFORE, AND WHY THIS FILE EXISTS
 * ------------------------------------------------
 * The bar this replaced built its own 16 samples in the browser as an
 * arithmetic ramp. Those bytes were not key material and had never touched a
 * dump, so a CORRECT oracle scored 0 pass / 16 fail — and so did a completely
 * broken one. The widget was decorative: no arrangement of its dots could tell
 * the two apart, which is the only question a smoke test exists to answer.
 *
 * ``POST /api/oracles/{id}/smoke-test`` now composes the samples server-side:
 * one POSITIVE CONTROL (the run's ``master_key_hex`` out of ``meta.json``,
 * which the oracle must accept) plus 15 DECOYS read at random offsets from the
 * user's own dump (which it must reject). Only the pair is diagnostic, so the
 * server returns a ``verdict`` and the UI leads with it.
 *
 * The load-bearing test in this file is therefore NOT the green one. A smoke
 * test that is green for everything is exactly the bug that was just fixed, so
 * the second test re-runs the identical flow with ``sample_ciphertext`` aimed
 * at the vault's ``gocryptfs.conf`` — metadata, not content, which the oracle
 * can never decrypt — and asserts the verdict flips to "never accepts" and the
 * Continue button is withheld. Green-path assertions alone would still pass
 * against the broken widget this replaced; that pair cannot.
 *
 * The third test guards a separate reported bug: the Back/Next row used to be
 * the last child of a stage several screens tall, below the entire pcap block,
 * so users reported the oracle stage as having no way forward at all.
 *
 * Gated on the private corpus (`datasetAvailable`): the positive control IS
 * the dataset's recorded answer key, so there is nothing to control against
 * without it.
 */

import path from "node:path";

import { test, expect, type Page } from "@playwright/test";

import { MSL, RUN_0001, datasetAvailable } from "../fixtures/dataset";
import { tab } from "../fixtures/selectors";
import { dismissFtueIfPresent, enterWorkspaceWithMsl } from "../fixtures/workspace";

/** The bundled Shape 2 example the flow arms. */
const EXAMPLE = "gocryptfs.py";

/**
 * Vault METADATA, deliberately — the one path in the vault that is not
 * encrypted content. ``gocryptfs.py`` AES-GCM-decrypts block 0 of whatever it
 * is pointed at, so this file makes a well-formed, loadable, armable oracle
 * that answers "no" to every candidate including the real master key. That is
 * the shape of a broken oracle the old bar could not distinguish from a
 * working one.
 */
const BROKEN_SAMPLE_CIPHERTEXT = path.join(RUN_0001, "cipher", "gocryptfs.conf");

/**
 * Walk landing → workspace → pipeline → blank recipe → dumps → oracle.
 *
 * Deliberately the real wizard route rather than a seeded ``memdiver-pipeline``
 * localStorage blob: the smoke test reads its decoys out of
 * ``form.sourcePaths[0]``, and a seeded store would prove the bar works given a
 * state no user can reach.
 */
async function reachOracleStage(page: Page): Promise<void> {
  await enterWorkspaceWithMsl(page);

  await page.locator(tab("pipeline")).first().click();
  // PipelinePanel's mount effect starts the `pipeline-101` tour, whose
  // driver.js overlay intercepts every pointer event below. The workspace
  // fixture's seeded "seen" payload does not list that tour, so the sweep is
  // the fixture's own documented fallback rather than a new mechanism.
  await dismissFtueIfPresent(page);

  await page.getByRole("button", { name: /Start blank/i }).click();

  await page.locator('textarea[placeholder*="gdb_raw.bin"]').fill(MSL);
  await page.getByRole("button", { name: "Add paths" }).click();

  // StageDumps keeps Next disabled until >= 1 dump is accepted, so "enabled"
  // is the wire-accurate signal that the path landed in `form.sourcePaths`.
  const toOracle = page.getByRole("button", { name: /Next: Oracle/i });
  await expect(toOracle).toBeEnabled({ timeout: 30_000 });
  await toOracle.click();

  await expect(page.getByRole("tab", { name: "Examples" })).toBeVisible({
    timeout: 15_000,
  });
}

/**
 * Give consent to run user-supplied Python, if this backend has not already.
 *
 * The e2e backend deletes its preferences file on every spawn (see
 * playwright.config.ts), so `oracle_dir` starts unconfigured and every write
 * endpoint answers 503. The consent panel lives on the Upload tab — which is
 * the default tab — so this is the first thing a real first-time user does on
 * this stage. A REUSED server may already be enabled; both states are normal.
 */
async function enableOracleExecutionIfNeeded(page: Page): Promise<void> {
  const consent = page.getByTestId("oracle-consent-panel");
  const dropzone = page.getByText(/Drop an oracle \.py file here/i);
  await expect(consent.or(dropzone).first()).toBeVisible({ timeout: 20_000 });

  const enableBtn = page.getByTestId("oracle-enable-btn");
  if (await enableBtn.isVisible().catch(() => false)) {
    await enableBtn.click();
    await expect(enableBtn).toHaveCount(0, { timeout: 20_000 });
  }
}

/**
 * Examples tab → gocryptfs.py card → Use this example → Load + arm.
 *
 * @param sampleCiphertext - when given, replaces the server-derived
 * ``sample_ciphertext`` before arming. Used to build the deliberately broken
 * oracle the second test needs.
 */
async function armGocryptfsExample(
  page: Page,
  sampleCiphertext?: string,
): Promise<void> {
  await enableOracleExecutionIfNeeded(page);

  await page.getByRole("tab", { name: "Examples" }).click();

  const card = page.getByTestId(`oracle-example-${EXAMPLE}`);
  await expect(card).toBeVisible({ timeout: 20_000 });
  // The card body and "Use this example" are SIBLING buttons; the card body is
  // the one whose accessible name carries the filename.
  await card.getByRole("button", { name: /gocryptfs\.py/ }).click();
  await card.getByTestId(`oracle-example-use-${EXAMPLE}`).click();

  const config = card.getByTestId(`oracle-example-config-${EXAMPLE}`);
  await expect(config).toBeVisible({ timeout: 15_000 });

  // The server auto-fills sample_ciphertext from the selected dump's own vault
  // (POST /api/oracles/examples/{f}/suggest-config). The provenance caption is
  // what says that answer arrived, so it is what we wait for — the input's
  // value alone cannot distinguish "derived" from "still the template".
  await expect(card.getByTestId("oracle-cfg-provenance-sample_ciphertext")).toBeVisible(
    { timeout: 30_000 },
  );

  const valueInput = config.getByLabel("Value for sample_ciphertext");
  if (sampleCiphertext === undefined) {
    // The derived answer must name this run's vault, not some other run's:
    // each run has its own master key, so a cross-run ciphertext would fail
    // for every candidate and look exactly like a broken oracle.
    await expect(valueInput).toHaveValue(
      new RegExp(`${path.join("run_0001", "cipher")}`.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  } else {
    await valueInput.fill(sampleCiphertext);
    await expect(valueInput).toHaveValue(sampleCiphertext);
  }

  const armBtn = card.getByTestId(`oracle-example-arm-${EXAMPLE}`);
  await expect(armBtn).toBeEnabled();
  await armBtn.click();

  // "Loaded and armed <file> — you can continue." Anything less than armed
  // leaves the smoke test testing an oracle the sweep would never run.
  await expect(card.getByTestId("oracle-example-notice")).toContainText(
    /Loaded and armed/i,
    { timeout: 60_000 },
  );
}

/** Click "Test on 16 samples" and wait for the verdict banner to land. */
async function runSmokeTest(page: Page) {
  const verdict = page.getByTestId("oracle-smoke-verdict");
  await page.getByRole("button", { name: /Test on 16 samples/i }).click();
  await expect(verdict).toBeVisible({ timeout: 120_000 });
  return verdict;
}

test.describe("Oracle smoke test", { tag: "@requires-dataset" }, () => {
  test.skip(!datasetAvailable, "Dataset not present.");

  /**
   * Protects: the smoke test must be able to say YES.
   *
   * A correctly configured oracle has to accept the run's recorded master key
   * and reject 15 real dump windows, report where both halves came from, and
   * only then offer the way forward. The old client-composed bar could not
   * produce this state at all — it had no positive control to pass.
   */
  test("a correct oracle scores discriminates and offers the way forward", async ({
    page,
  }) => {
    test.setTimeout(300_000);

    await reachOracleStage(page);
    await armGocryptfsExample(page);

    const verdict = await runSmokeTest(page);
    await expect(verdict).toHaveAttribute("data-verdict", "discriminates");
    await expect(verdict).toContainText(/discriminates/i);

    // Provenance, not decoration: a green control dot with no caption claims a
    // discovery the pipeline did not make. It must name the run's answer key.
    await expect(page.getByTestId("oracle-smoke-positive-provenance")).toContainText(
      "run_0001/meta.json",
    );
    await expect(page.getByTestId("oracle-smoke-positive-absent")).toHaveCount(0);

    // The decoys are real bytes from the user's own dump, read in the `vas`
    // (flattened captured-memory) view — never `va`, which pads unmapped space
    // with synthesized zeroes the dump never captured.
    const dumpLine = page.getByTestId("oracle-smoke-dump");
    await expect(dumpLine).toContainText("memslicer.msl");
    await expect(dumpLine).toContainText("vas");

    /*
      The control is rendered in its own group, separated from the decoy row.
      This is a correctness requirement and not styling: a green dot meaning
      "the oracle recognises a key we already knew" must not be mistakable for
      one of the search results beside it.
    */
    const positiveGroup = page.getByTestId("oracle-smoke-positive");
    await expect(positiveGroup.getByTestId("oracle-smoke-positive-dot")).toHaveAttribute(
      "data-state",
      "pass",
    );
    await expect(positiveGroup.locator("span")).toHaveCount(1);
    const decoyDots = positiveGroup
      .locator("xpath=following-sibling::div[1]")
      .locator("span");
    await expect(decoyDots).toHaveCount(15);

    // Continue is offered ONLY on `discriminates`, and it is a real wizard
    // advance rather than a banner.
    const continueBtn = page.getByTestId("oracle-smoke-continue");
    await expect(continueBtn).toBeVisible();
    await continueBtn.click();
    await expect(
      page.getByRole("heading", { name: "Configure thresholds" }),
    ).toBeVisible({ timeout: 15_000 });
  });

  /**
   * Protects: the smoke test must also be able to say NO.
   *
   * THE regression this file exists for. The replaced bar reported the same 0
   * pass / 16 fail for a working oracle and a broken one, so "the dots are
   * red" proved nothing. Here the oracle is broken in the way that is hardest
   * to see — it loads, it arms, it runs, and it answers false to everything
   * including the real key — and the verdict has to call it out AND withhold
   * the way forward. If this test ever goes green on `discriminates`, the
   * smoke test has stopped being diagnostic again.
   */
  test("a broken oracle scores never accepts and is NOT allowed to continue", async ({
    page,
  }) => {
    test.setTimeout(300_000);

    await reachOracleStage(page);
    await armGocryptfsExample(page, BROKEN_SAMPLE_CIPHERTEXT);

    const verdict = await runSmokeTest(page);
    await expect(verdict).toHaveAttribute("data-verdict", "never_accepts");
    await expect(verdict).toContainText(/never accepts/i);

    // The control ran and was REJECTED — that is the whole finding, and it is
    // a different state from "no control was available".
    await expect(page.getByTestId("oracle-smoke-positive-dot")).toHaveAttribute(
      "data-state",
      "fail",
    );
    await expect(page.getByTestId("oracle-smoke-positive-absent")).toHaveCount(0);

    // No way forward: the next stage would be configured around an oracle that
    // cannot answer the question the sweep is about to ask it.
    await expect(page.getByTestId("oracle-smoke-continue")).toHaveCount(0);
  });

  /**
   * Protects: the reported "this stage has no way forward" bug.
   *
   * The Back/Next row used to be the last child of a stage several screens
   * tall, below the fully-expanded pcap block, so on any normal window a user
   * saw the pcap upload box and concluded the wizard was stuck. The fix has
   * three parts and all three are asserted: the pcap block is a <details> that
   * starts closed, the row is sticky, and the disabled Next states its reason
   * in TEXT rather than only in a `title` nobody can hover on touch.
   */
  test("with no oracle armed, Next is on screen and says why it is blocked", async ({
    page,
  }) => {
    test.setTimeout(180_000);

    await reachOracleStage(page);

    const blocked = page.getByTestId("oracle-next-blocked");
    await expect(blocked).toBeVisible();
    await expect(blocked).toContainText(/arm an oracle/i);

    // The pcap block is the ALTERNATIVE route, and expanded it is what pushed
    // the exits off screen. It must start collapsed.
    const pcap = page.locator('details[data-tour-id="pipeline-oracle-pcap"]');
    await expect(pcap).toBeVisible();
    expect(
      await pcap.evaluate((el) => (el as HTMLDetailsElement).open),
      "the pcap disclosure starts closed",
    ).toBe(false);

    // No scrolling happens in this test, so "in viewport" is the literal claim
    // the bug report made: the user can see the way out on arrival.
    const nextBtn = page.getByRole("button", { name: "Next: Thresholds →" });
    await expect(nextBtn).toBeInViewport();
    await expect(nextBtn).toBeDisabled();

    // …and it stays on screen while the stage is scrolled, which is what
    // `position: sticky` on the row buys and what a plain last-child does not.
    expect(
      await nextBtn.evaluate((el) => {
        let node: HTMLElement | null = el.parentElement;
        while (node) {
          if (getComputedStyle(node).position === "sticky") return true;
          node = node.parentElement;
        }
        return false;
      }),
      "the Back/Next row sits in a sticky container",
    ).toBe(true);
  });
});
