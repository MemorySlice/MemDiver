/**
 * The consent gate in front of the oracle dropzone.
 *
 * The regression this pins: the dropzone used to render unconditionally even
 * though the server refuses uploads until an oracle directory is configured,
 * so every drop answered 503 and the UI never said why. Disabled must show the
 * consent panel instead, enabling must reveal the dropzone in place (no
 * reload), and an env-pinned directory must not offer a button at all — the
 * backend answers 409 for that case.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

import type { OracleStatus } from "@/api/oracles";

// The store's whole network surface. `enableOracles` is the one under test;
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

import { OracleUpload } from "@/components/pipeline/oracle/OracleUpload";
import { useOracleStore } from "@/stores/oracle-store";

/** The dropzone has no test id; its accessible name is the contract. */
const DROPZONE_NAME = "Drop an oracle .py file here";

function makeStatus(overrides: Partial<OracleStatus> = {}): OracleStatus {
  return {
    enabled: false,
    path: null,
    source: null,
    env_pinned: false,
    default_path: "/home/analyst/.memdiver/oracles",
    ...overrides,
  };
}

function setStatus(status: OracleStatus | null): void {
  useOracleStore.setState({ status });
}

beforeEach(() => {
  enableOracles.mockReset();
  getOracleStatus.mockReset();
  listOracleExamples.mockReset();
  listOracles.mockReset();
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

describe("OracleUpload consent gate", () => {
  it("renders the consent panel instead of the dropzone while disabled", () => {
    setStatus(makeStatus());
    render(<OracleUpload />);

    expect(screen.getByTestId("oracle-consent-panel")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: DROPZONE_NAME })).toBeNull();
  });

  it("names what is being allowed and where the files land", () => {
    setStatus(makeStatus());
    render(<OracleUpload />);

    const panel = screen.getByTestId("oracle-consent-panel");
    expect(panel).toHaveTextContent(/MemDiver runs it in this server's process/);
    expect(panel).toHaveTextContent("/home/analyst/.memdiver/oracles");
    expect(panel).toHaveTextContent(/0700/);
  });

  it("keeps today's dropzone while the status is still unknown", () => {
    setStatus(null);
    render(<OracleUpload />);

    expect(screen.getByRole("button", { name: DROPZONE_NAME })).toBeInTheDocument();
    expect(screen.queryByTestId("oracle-consent-panel")).toBeNull();
  });

  it("fetches the status it branches on instead of waiting for a sibling", async () => {
    // The regression: `refresh` used to be called only by OracleExamplePicker,
    // which mounts on the *Examples* tab. Upload is the DEFAULT tab, so a
    // first-time user never triggered it: `status` stayed null forever, the
    // consent panel never rendered, and the drop they made answered 503 --
    // exactly the dead end that panel exists to prevent.
    getOracleStatus.mockResolvedValue(makeStatus());
    listOracleExamples.mockResolvedValue({ examples: [] });
    listOracles.mockResolvedValue({ oracles: [] });
    setStatus(null);

    render(<OracleUpload />);

    await waitFor(() => expect(getOracleStatus).toHaveBeenCalled());
    expect(await screen.findByTestId("oracle-consent-panel")).toBeInTheDocument();
  });

  it("enables uploads and reveals the dropzone without a reload", async () => {
    const enabled = makeStatus({
      enabled: true,
      path: "/home/analyst/.memdiver/oracles",
      source: "user_config",
    });
    enableOracles.mockResolvedValue(enabled);
    setStatus(makeStatus());
    render(<OracleUpload />);

    fireEvent.click(screen.getByTestId("oracle-enable-btn"));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: DROPZONE_NAME })).toBeInTheDocument();
    });
    // The default path is the server's business: the UI sends no path at all.
    expect(enableOracles).toHaveBeenCalledWith(undefined);
    expect(screen.queryByTestId("oracle-consent-panel")).toBeNull();
    expect(useOracleStore.getState().status).toEqual(enabled);
  });

  it("marks the button busy while the request is in flight", async () => {
    let release: (status: OracleStatus) => void = () => {};
    enableOracles.mockReturnValue(
      new Promise<OracleStatus>((resolve) => {
        release = resolve;
      }),
    );
    setStatus(makeStatus());
    render(<OracleUpload />);

    const button = screen.getByTestId("oracle-enable-btn");
    fireEvent.click(button);
    await waitFor(() => {
      expect(screen.getByTestId("oracle-enable-btn")).toHaveAttribute(
        "aria-busy",
        "true",
      );
    });

    release(makeStatus({ enabled: true, path: "/p", source: "user_config" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: DROPZONE_NAME })).toBeInTheDocument();
    });
  });

  it("surfaces a rejected enable instead of silently doing nothing", async () => {
    enableOracles.mockRejectedValue(new Error('{"detail":"refused: /etc"}'));
    setStatus(makeStatus());
    render(<OracleUpload />);

    fireEvent.click(screen.getByTestId("oracle-enable-btn"));

    // readableFailure unwraps the envelope -- no raw JSON blob in the panel --
    // and the sentence is attributed, because `error` is a field shared by
    // every oracle action (dry-run and the Examples tab write to it too).
    await waitFor(() => {
      expect(
        screen.getByText("Could not upload this oracle: refused: /etc"),
      ).toBeInTheDocument();
    });
    expect(screen.getByTestId("oracle-consent-panel")).toBeInTheDocument();
  });

  it("offers no button when the directory is pinned by the environment", () => {
    setStatus(
      makeStatus({
        enabled: false,
        env_pinned: true,
        path: "/opt/pinned/oracles",
      }),
    );
    render(<OracleUpload />);

    const panel = screen.getByTestId("oracle-consent-panel");
    expect(screen.queryByTestId("oracle-enable-btn")).toBeNull();
    expect(panel).toHaveTextContent("MEMDIVER_ORACLE_DIR");
    expect(panel).toHaveTextContent("/opt/pinned/oracles");
  });
});
