/**
 * The smoke-test bar: its failure surface, and its diagnostic honesty.
 *
 * The first regression pinned here predates the smoke test: "Test on N
 * samples" answered HTTP 400 with a perfectly readable message and the bar
 * said nothing at all — the dots stayed grey, and the sentence only became
 * visible after switching to the Upload tab, which renders the SHARED store
 * error. A refused run is not an all-red run, and the dots cannot express the
 * difference.
 *
 * The shape of that fix is pinned too: the message must be read imperatively
 * at the moment the run resolves, never through a reactive selector on
 * ``useOracleStore.error``. That field is shared by upload, arm, load-example
 * and delete, and StageOracle mounts those panels alongside this bar — a
 * selector would paint a failed upload under the smoke-test dots.
 *
 * The rest of the file pins what the bar was rebuilt FOR. The old client-side
 * samples were an arithmetic ramp, so a correct oracle and a broken one both
 * scored zero passes; the server now composes a positive control plus decoys
 * and returns a verdict. What must hold:
 *
 *  - every verdict states its outcome in words, not just in colour;
 *  - the positive control renders apart from the decoys, WITH its provenance,
 *    because it is a self-test against a recorded answer key and not a find;
 *  - ``positive.ok === null`` (no ground truth) never renders as a failure;
 *  - per-sample ``error`` strings are actually shown — the old bar had them
 *    all along and used them only to pick a grey fill;
 *  - a failed run clears the previous verdict, so a stale "discriminates"
 *    cannot sit above a fresh error.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

import type { SmokeTestResult, SmokeTestVerdict } from "@/api/oracles";

// The store's whole network surface. `smokeTestOracle` is the one under test;
// the rest exist so importing the store does not pull in real fetches.
const enableOracles = vi.fn();
const getOracleStatus = vi.fn();
const listOracleExamples = vi.fn();
const listOracles = vi.fn();
const uploadOracle = vi.fn();
const loadOracleExample = vi.fn();
const armOracle = vi.fn();
const dryRunOracle = vi.fn();
const smokeTestOracle = vi.fn();
const deleteOracle = vi.fn();
vi.mock("@/api/oracles", () => ({
  enableOracles: (...a: unknown[]) => enableOracles(...a),
  getOracleStatus: (...a: unknown[]) => getOracleStatus(...a),
  listOracleExamples: (...a: unknown[]) => listOracleExamples(...a),
  listOracles: (...a: unknown[]) => listOracles(...a),
  uploadOracle: (...a: unknown[]) => uploadOracle(...a),
  loadOracleExample: (...a: unknown[]) => loadOracleExample(...a),
  armOracle: (...a: unknown[]) => armOracle(...a),
  dryRunOracle: (...a: unknown[]) => dryRunOracle(...a),
  smokeTestOracle: (...a: unknown[]) => smokeTestOracle(...a),
  deleteOracle: (...a: unknown[]) => deleteOracle(...a),
  ORACLE_EXAMPLES_DIR: "docs/oracle/examples/",
}));

import { OracleDryRunBar } from "@/components/pipeline/oracle/OracleDryRunBar";
import { useOracleStore } from "@/stores/oracle-store";

const ORACLE_ID = "orc-1";
const SOURCE_PATHS = ["/data/run-01/dump-a.msl"];
/** Two decoys + one control = the "Test on 3 samples" button label. */
const NEGATIVES = 2;

/** A graded run: control passes, one decoy rejected, one decoy errored. */
function makeSmoke(overrides: Partial<SmokeTestResult> = {}): SmokeTestResult {
  return {
    oracle_id: ORACLE_ID,
    samples: 3,
    passes: 1,
    fails: 1,
    errors: 1,
    per_call_us_avg: 12.5,
    results: [
      { index: 0, ok: true, duration_us: 10 },
      { index: 1, ok: false, duration_us: 15 },
      { index: 2, ok: false, error: "boom" },
    ],
    positive: {
      present: true,
      index: 0,
      ok: true,
      error: null,
      source: "/data/run-01/meta.json",
      provenance_label: "run-01 meta.json",
      reason: null,
    },
    negatives: {
      count: 2,
      accepted: 0,
      rejected: 1,
      errors: 1,
      key_size: 32,
      low_entropy_included: 0,
      offsets: [4096, 8192],
    },
    dump: {
      path: "/data/run-01/dump-a.msl",
      format: "msl",
      view: "raw",
      size: 192_000_000,
    },
    verdict: "discriminates",
    caveats: [],
    ...overrides,
  };
}

function renderBar(onContinue?: () => void) {
  return render(
    <OracleDryRunBar
      oracleId={ORACLE_ID}
      sourcePaths={SOURCE_PATHS}
      keySize={32}
      negativeCount={NEGATIVES}
      onContinue={onContinue}
    />,
  );
}

function runButton(): HTMLElement {
  return screen.getByRole("button", { name: /Test on 3 samples/ });
}

/** The decoy dots only — the control is deliberately not in this row. */
function negativeDots(): HTMLElement[] {
  return [1, 2].map((i) => screen.getByTitle(new RegExp(`^sample ${i}: `)));
}

beforeEach(() => {
  smokeTestOracle.mockReset();
  useOracleStore.setState({
    status: null,
    uploaded: [],
    examples: [],
    selectedOracleId: null,
    dryRun: null,
    smokeTest: null,
    loading: false,
    error: null,
  });
});

describe("OracleDryRunBar failure surface", () => {
  it("shows the server's sentence when the run is refused, not a JSON blob", async () => {
    smokeTestOracle.mockRejectedValue(
      new Error('{"detail":"oracle gocryptfs.py could not be loaded"}'),
    );
    renderBar();

    fireEvent.click(runButton());

    const failure = await screen.findByTestId("oracle-dry-run-error");
    expect(failure).toHaveTextContent(
      "Smoke test failed: oracle gocryptfs.py could not be loaded",
    );
    expect(failure.textContent).not.toContain("detail");
  });

  it("falls back to a stated reason when the store has none", async () => {
    // A rejection with an empty message leaves `error` as "" -- the bar must
    // still say the run failed rather than rendering an empty red line.
    smokeTestOracle.mockRejectedValue(new Error(""));
    renderBar();

    fireEvent.click(runButton());

    await waitFor(() => {
      expect(screen.getByTestId("oracle-dry-run-error")).toBeInTheDocument();
    });
    expect(screen.getByTestId("oracle-dry-run-error")).toHaveTextContent(
      /Smoke test failed:/,
    );
  });

  it("clears the previous failure when the next run starts", async () => {
    smokeTestOracle.mockRejectedValueOnce(new Error('{"detail":"refused"}'));
    renderBar();

    fireEvent.click(runButton());
    await screen.findByTestId("oracle-dry-run-error");

    // Second run: hold it in flight so the assertion is about the START of the
    // run, not about its (successful) outcome.
    let release: (result: SmokeTestResult) => void = () => {};
    smokeTestOracle.mockReturnValueOnce(
      new Promise<SmokeTestResult>((resolve) => {
        release = resolve;
      }),
    );
    fireEvent.click(runButton());

    await waitFor(() => {
      expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
    });

    release(makeSmoke());
    await waitFor(() => {
      expect(screen.getByText(/1 pass/)).toBeInTheDocument();
    });
    expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
  });

  it("does not render an unrelated store error that predates the mount", () => {
    // The reactive-selector trap: `error` is shared by every oracle action, and
    // StageOracle mounts OracleUpload/OracleExamplePicker beside this bar. A
    // failed UPLOAD must never appear under the smoke-test dots.
    useOracleStore.setState({ error: "upload rejected: file too large" });
    renderBar();

    expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
    expect(screen.queryByText(/upload rejected/)).toBeNull();
  });

  it("drops the stale verdict when a later run is refused", async () => {
    // The bar asserts a conclusion about the oracle, so a stale banner is not
    // merely redundant -- "This oracle discriminates" above "the server
    // refused the request" is a claim the server just declined to make.
    useOracleStore.setState({ smokeTest: makeSmoke() });
    renderBar();
    expect(screen.getByTestId("oracle-smoke-verdict")).toBeInTheDocument();

    smokeTestOracle.mockRejectedValue(new Error('{"detail":"refused"}'));
    fireEvent.click(runButton());

    await screen.findByTestId("oracle-dry-run-error");
    expect(screen.queryByTestId("oracle-smoke-verdict")).toBeNull();
    expect(useOracleStore.getState().smokeTest).toBeNull();
  });
});

describe("OracleDryRunBar verdict banner", () => {
  const cases: Array<[SmokeTestVerdict, RegExp]> = [
    ["discriminates", /accepted the known-good key and rejected the decoys/],
    ["never_accepts", /rejected the known-good key/],
    ["accepts_noise", /said yes to arbitrary dump bytes/],
    ["no_positive_control", /nothing proved this oracle can ever say yes/],
    ["inconclusive", /not produce enough clean signal/],
  ];

  for (const [verdict, sentence] of cases) {
    it(`states the outcome in words for "${verdict}"`, () => {
      useOracleStore.setState({ smokeTest: makeSmoke({ verdict }) });
      renderBar();

      const banner = screen.getByTestId("oracle-smoke-verdict");
      expect(banner).toHaveAttribute("data-verdict", verdict);
      expect(banner).toHaveTextContent(sentence);
    });
  }

  it("offers Continue only once the oracle is shown to discriminate", () => {
    const onContinue = vi.fn();
    useOracleStore.setState({ smokeTest: makeSmoke() });
    const { unmount } = renderBar(onContinue);

    fireEvent.click(screen.getByTestId("oracle-smoke-continue"));
    expect(onContinue).toHaveBeenCalledTimes(1);
    unmount();

    useOracleStore.setState({
      smokeTest: makeSmoke({ verdict: "never_accepts" }),
    });
    renderBar(onContinue);
    expect(screen.queryByTestId("oracle-smoke-continue")).toBeNull();
  });
});

describe("OracleDryRunBar positive control", () => {
  it("renders the control apart from the decoys, with its provenance", () => {
    useOracleStore.setState({ smokeTest: makeSmoke() });
    renderBar();

    const control = screen.getByTestId("oracle-smoke-positive-dot");
    expect(control).toHaveAttribute("data-state", "pass");
    expect(control).toHaveStyle({ background: "var(--md-accent-green)" });
    // Not one of the decoy dots: the decoy row holds exactly the negatives.
    expect(
      screen.getByTestId("oracle-smoke-positive").contains(control),
    ).toBe(true);
    expect(negativeDots()).toHaveLength(2);
    expect(negativeDots()).not.toContain(control);

    // The honesty copy: a recorded answer key, not a pipeline finding.
    expect(
      screen.getByTestId("oracle-smoke-positive-provenance"),
    ).toHaveTextContent("Control key from run-01 meta.json.");
    expect(
      screen.getByText(/self-test of the oracle, not a pipeline finding/),
    ).toBeInTheDocument();
  });

  it("treats a missing control as neutral, never as a failure", () => {
    // `ok: null` means the control was never RUN -- there was no ground truth
    // to run it with. Painting that red would accuse a working oracle.
    useOracleStore.setState({
      smokeTest: makeSmoke({
        verdict: "no_positive_control",
        positive: {
          present: false,
          index: null,
          ok: null,
          error: null,
          source: null,
          provenance_label: null,
          reason: "no meta.json beside this dump, so no answer key is known",
        },
        results: [
          { index: 0, ok: false, duration_us: 15 },
          { index: 1, ok: false, duration_us: 15 },
        ],
      }),
    });
    renderBar();

    const control = screen.getByTestId("oracle-smoke-positive-dot");
    expect(control).toHaveAttribute("data-state", "absent");
    expect(control).not.toHaveStyle({ background: "var(--md-accent-red)" });
    expect(screen.getByTestId("oracle-smoke-positive-absent")).toHaveTextContent(
      "no meta.json beside this dump",
    );
    expect(screen.queryByTestId("oracle-smoke-positive-provenance")).toBeNull();
  });
});

describe("OracleDryRunBar dots and disclosures", () => {
  it("colours pass, fail and error dots once a run is graded", async () => {
    smokeTestOracle.mockResolvedValue(makeSmoke());
    renderBar();

    fireEvent.click(runButton());

    await waitFor(() => {
      expect(screen.getByTitle("sample 1: fail")).toBeInTheDocument();
    });
    const [fail, errored] = negativeDots();
    expect(fail).toHaveStyle({ background: "var(--md-accent-red)" });
    // A per-sample `error` outranks `ok`, so the errored decoy is grey, not red.
    expect(errored).toHaveStyle({ background: "var(--md-text-muted)" });
    // ...and the message rides along in the title, which it never used to.
    expect(errored).toHaveAttribute("title", "sample 2: error — boom");
    expect(screen.getByText(/1 pass · 1 fail · 1 error/)).toBeInTheDocument();
  });

  it("lists every per-sample error message", () => {
    // The missing surface: the server always sent these strings and the bar
    // used them only as a boolean to pick a grey fill.
    useOracleStore.setState({
      smokeTest: makeSmoke({
        verdict: "inconclusive",
        results: [
          { index: 0, ok: false, error: "TypeError: verify() takes 2 args" },
          { index: 1, ok: false, error: "boom" },
          { index: 2, ok: false, duration_us: 9 },
        ],
      }),
    });
    renderBar();

    const details = screen.getByTestId("oracle-smoke-errors");
    expect(details).toHaveTextContent("2 samples raised an error");
    expect(details).toHaveTextContent(
      "sample 0 — TypeError: verify() takes 2 args",
    );
    expect(details).toHaveTextContent("sample 1 — boom");
  });

  it("names the dump the decoys came from and discloses low-entropy ones", () => {
    useOracleStore.setState({
      smokeTest: makeSmoke({
        negatives: {
          count: 2,
          accepted: 0,
          rejected: 2,
          errors: 0,
          key_size: 32,
          low_entropy_included: 1,
          offsets: [4096, 8192],
        },
      }),
    });
    renderBar();

    const dumpLine = screen.getByTestId("oracle-smoke-dump");
    expect(dumpLine).toHaveTextContent("dump-a.msl");
    expect(dumpLine).toHaveTextContent("raw");
    // Full path stays reachable without widening the panel.
    expect(dumpLine).toHaveAttribute("title", "/data/run-01/dump-a.msl");
    expect(screen.getByTestId("oracle-smoke-low-entropy")).toHaveTextContent(
      /1 decoy came from a low-entropy region/,
    );
  });

  it("renders the server's caveats", () => {
    useOracleStore.setState({
      smokeTest: makeSmoke({ caveats: ["Only one dump was sampled."] }),
    });
    renderBar();

    expect(screen.getByTestId("oracle-smoke-caveats")).toHaveTextContent(
      "Only one dump was sampled.",
    );
  });

  it("keeps every dot idle while no run has been graded for this oracle", () => {
    // A result belonging to a DIFFERENT oracle must not colour this bar.
    useOracleStore.setState({ smokeTest: makeSmoke({ oracle_id: "other" }) });
    renderBar();

    for (const dot of negativeDots()) {
      expect(dot).toHaveStyle({ background: "var(--md-bg-hover)" });
    }
    expect(screen.getByTestId("oracle-smoke-positive-dot")).toHaveAttribute(
      "data-state",
      "idle",
    );
    expect(screen.queryByTestId("oracle-smoke-verdict")).toBeNull();
  });

  it("refuses to run without a dump to sample from", () => {
    render(
      <OracleDryRunBar
        oracleId={ORACLE_ID}
        sourcePaths={[]}
        keySize={32}
        negativeCount={NEGATIVES}
      />,
    );

    expect(runButton()).toBeDisabled();
    expect(screen.getByTestId("oracle-smoke-no-dumps")).toBeInTheDocument();
  });
});
