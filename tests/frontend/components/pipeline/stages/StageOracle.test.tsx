/**
 * The oracle tabs must not inherit each other's failures.
 *
 * ``useOracleStore.error`` is a single field written by upload, arm,
 * load-example, dry-run and delete, and BOTH sub-tabs render it. Before this
 * guard, a refused "Use this example" was still on screen after switching to
 * Upload, where it read as a failed upload the user never attempted — and the
 * reverse held too. Switching tabs clears it.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

// The store's whole network surface, so mounting the stage performs no fetch.
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

import type { OracleExample, OracleStatus } from "@/api/oracles";

import { StageOracle } from "@/components/pipeline/stages/StageOracle";
import { useOracleStore } from "@/stores/oracle-store";

/**
 * One bundled example, so OracleExamplePicker has nothing to fetch.
 *
 * This matters for what the test can prove: both sub-panels call ``refresh``
 * on mount when their slice of the store is still empty, and ``refresh``
 * blanks ``error`` on its way out. A seeded store means the ONLY thing that
 * can clear the error here is the tab switch itself.
 */
const EXAMPLE: OracleExample = {
  filename: "gocryptfs.py",
  path: "docs/oracle/examples/gocryptfs.py",
  sha256: "a".repeat(64),
  size: 1024,
  shape: 2,
  summary: "gocryptfs master-key oracle",
  head_lines: ["def build_oracle(cfg):"],
  config_template: null,
};

const STATUS: OracleStatus = {
  enabled: true,
  path: "/home/analyst/.memdiver/oracles",
  source: "user_config",
  env_pinned: false,
  default_path: "/home/analyst/.memdiver/oracles",
};

beforeEach(() => {
  getOracleStatus.mockResolvedValue(STATUS);
  listOracleExamples.mockResolvedValue({ examples: [EXAMPLE] });
  listOracles.mockResolvedValue({ oracles: [] });
  useOracleStore.setState({
    status: STATUS,
    uploaded: [],
    examples: [EXAMPLE],
    selectedOracleId: null,
    dryRun: null,
    loading: false,
    error: null,
  });
});

describe("StageOracle tab switching", () => {
  it("drops the shared oracle error when the tab changes", async () => {
    render(<StageOracle onAdvance={() => {}} />);
    // A failure produced on the Upload tab -- the panel shows it, attributed.
    useOracleStore.setState({ error: "oracle execution disabled" });
    expect(
      await screen.findByText(/Could not upload this oracle: oracle execution disabled/),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Examples" }));

    await waitFor(() => {
      expect(useOracleStore.getState().error).toBeNull();
    });
    expect(screen.queryByText(/oracle execution disabled/)).toBeNull();
    // Nothing refetched: the clear came from the switch, not from a refresh.
    expect(listOracleExamples).not.toHaveBeenCalled();
    expect(getOracleStatus).not.toHaveBeenCalled();
  });
});

/**
 * The reported navigation bug: the Back/Next row was the last child of a stage
 * several screens tall, so it sat below the entire pcap block and users
 * concluded the wizard had no way forward. Two things fix it, and both are
 * pinned here: the row is sticky, and the pcap block is collapsed by default.
 */
describe("StageOracle navigation affordances", () => {
  it("pins the Back/Next row and states why Next is blocked", () => {
    render(<StageOracle onAdvance={() => {}} />);

    const next = screen.getByRole("button", { name: /Next: Thresholds/ });
    expect(next).toBeDisabled();
    // The reason is on screen, not only in the disabled button's `title`.
    expect(screen.getByTestId("oracle-next-blocked")).toHaveTextContent(
      /Upload and arm an oracle/,
    );
    expect(next.closest("div")?.parentElement?.className).toMatch(/sticky/);
  });

  it("keeps the pcap alternative collapsed until asked for", () => {
    render(<StageOracle onAdvance={() => {}} />);

    const summary = screen.getByText(/verify against a pcap instead/);
    const details = summary.closest("details");
    expect(details).not.toBeNull();
    expect(details).not.toHaveAttribute("open");
  });
});
