/**
 * The dry-run bar's own failure surface.
 *
 * The regression this pins: "Test on 16 samples" answered HTTP 400 with a
 * perfectly readable message and the bar said nothing at all — the 16 dots
 * stayed grey, and the sentence only became visible after switching to the
 * Upload tab, which renders the SHARED store error. A refused run is not an
 * all-red run, and the dots cannot express the difference.
 *
 * The second thing pinned here is the shape of the fix: the message must be
 * read imperatively at the moment the run resolves, never through a reactive
 * selector on ``useOracleStore.error``. That field is shared by upload, arm,
 * load-example and delete, and StageOracle mounts those panels alongside this
 * bar — a selector would paint a failed upload under the dry-run dots.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

import type { DryRunResult } from "@/api/oracles";

// The store's whole network surface. `dryRunOracle` is the one under test;
// the rest exist so importing the store does not pull in real fetches.
const enableOracles = vi.fn();
const getOracleStatus = vi.fn();
const listOracleExamples = vi.fn();
const listOracles = vi.fn();
const uploadOracle = vi.fn();
const loadOracleExample = vi.fn();
const armOracle = vi.fn();
const dryRunOracle = vi.fn();
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
  deleteOracle: (...a: unknown[]) => deleteOracle(...a),
  ORACLE_EXAMPLES_DIR: "docs/oracle/examples/",
}));

import { OracleDryRunBar } from "@/components/pipeline/oracle/OracleDryRunBar";
import { useOracleStore } from "@/stores/oracle-store";

const ORACLE_ID = "orc-1";
const SAMPLES = ["AAAA", "BBBB", "CCCC"];

/** A graded run: one pass, one fail, one per-sample error. */
function makeDryRun(overrides: Partial<DryRunResult> = {}): DryRunResult {
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
    ...overrides,
  };
}

function dots(): HTMLElement[] {
  return SAMPLES.map((_, i) =>
    screen.getByTitle(new RegExp(`^sample ${i}: `)),
  );
}

beforeEach(() => {
  dryRunOracle.mockReset();
  useOracleStore.setState({
    status: null,
    uploaded: [],
    examples: [],
    selectedOracleId: null,
    dryRun: null,
    loading: false,
    error: null,
  });
});

describe("OracleDryRunBar failure surface", () => {
  it("shows the server's sentence when the run is refused, not a JSON blob", async () => {
    dryRunOracle.mockRejectedValue(
      new Error('{"detail":"oracle gocryptfs.py could not be loaded"}'),
    );
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    fireEvent.click(screen.getByRole("button", { name: /Test on 3 samples/ }));

    const failure = await screen.findByTestId("oracle-dry-run-error");
    expect(failure).toHaveTextContent(
      "Smoke test failed: oracle gocryptfs.py could not be loaded",
    );
    expect(failure.textContent).not.toContain("detail");
  });

  it("falls back to a stated reason when the store has none", async () => {
    // A rejection with an empty message leaves `error` as "" -- the bar must
    // still say the run failed rather than rendering an empty red line.
    dryRunOracle.mockRejectedValue(new Error(""));
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    fireEvent.click(screen.getByRole("button", { name: /Test on 3 samples/ }));

    await waitFor(() => {
      expect(screen.getByTestId("oracle-dry-run-error")).toBeInTheDocument();
    });
    expect(screen.getByTestId("oracle-dry-run-error")).toHaveTextContent(
      /Smoke test failed:/,
    );
  });

  it("clears the previous failure when the next run starts", async () => {
    dryRunOracle.mockRejectedValueOnce(new Error('{"detail":"refused"}'));
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    const button = screen.getByRole("button", { name: /Test on 3 samples/ });
    fireEvent.click(button);
    await screen.findByTestId("oracle-dry-run-error");

    // Second run: hold it in flight so the assertion is about the START of the
    // run, not about its (successful) outcome.
    let release: (result: DryRunResult) => void = () => {};
    dryRunOracle.mockReturnValueOnce(
      new Promise<DryRunResult>((resolve) => {
        release = resolve;
      }),
    );
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
    });

    release(makeDryRun());
    await waitFor(() => {
      expect(screen.getByText(/1 pass/)).toBeInTheDocument();
    });
    expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
  });

  it("does not render an unrelated store error that predates the mount", () => {
    // The reactive-selector trap: `error` is shared by every oracle action, and
    // StageOracle mounts OracleUpload/OracleExamplePicker beside this bar. A
    // failed UPLOAD must never appear under the dry-run dots.
    useOracleStore.setState({ error: "upload rejected: file too large" });
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    expect(screen.queryByTestId("oracle-dry-run-error")).toBeNull();
    expect(screen.queryByText(/upload rejected/)).toBeNull();
  });
});

describe("OracleDryRunBar dots", () => {
  it("colours pass, fail and error dots once a run is graded", async () => {
    dryRunOracle.mockResolvedValue(makeDryRun());
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    fireEvent.click(screen.getByRole("button", { name: /Test on 3 samples/ }));

    await waitFor(() => {
      expect(screen.getByTitle("sample 0: pass")).toBeInTheDocument();
    });
    const [pass, fail, error] = dots();
    expect(pass).toHaveStyle({ background: "var(--md-accent-green)" });
    expect(fail).toHaveStyle({ background: "var(--md-accent-red)" });
    // A per-sample `error` outranks `ok`, so sample 2 is grey and not red.
    expect(error).toHaveStyle({ background: "var(--md-text-muted)" });
    expect(screen.getByText(/1 pass · 1 fail · 1 error/)).toBeInTheDocument();
  });

  it("keeps every dot idle while no run has been graded for this oracle", () => {
    // A result belonging to a DIFFERENT oracle must not colour this bar.
    useOracleStore.setState({ dryRun: makeDryRun({ oracle_id: "other" }) });
    render(<OracleDryRunBar oracleId={ORACLE_ID} samplesB64={SAMPLES} />);

    for (const dot of dots()) {
      expect(dot).toHaveStyle({ background: "var(--md-bg-hover)" });
    }
  });
});
