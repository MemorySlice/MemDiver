/**
 * "Use this example" — the Examples tab's load + arm flow.
 *
 * The regression this pins: clicking a bundled example used to do nothing but
 * print directions to a file on disk, even though
 * ``POST /api/oracles/examples/{filename}/load`` has always been able to
 * register it server-side. So the assertions below are about the example
 * actually BECOMING an oracle: a Shape 2 card reveals the config its
 * ``build_oracle(cfg)`` needs, seeded from the bundled template; "Load + arm"
 * sends that config to both endpoints; a refused config surfaces the server's
 * own sentence rather than a JSON envelope; and a Shape 1 card, which takes no
 * config at all, is registered on the spot.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English the user actually sees.
import "@/i18n";

import type { OracleEntry, OracleExample } from "@/api/oracles";

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

// The real dialog talks to /api/path/browse; what matters here is only THAT it
// is opened for every file (a gocryptfs sample has no extension) and that the
// picked path lands in the field.
const fileBrowserProps = vi.fn();
vi.mock("@/components/wizard/FileBrowser", () => ({
  FileBrowser: (props: {
    onSelect: (path: string) => void;
    onClose: () => void;
    allFiles?: boolean;
  }) => {
    fileBrowserProps(props);
    return (
      <button type="button" onClick={() => props.onSelect("/real/cipher/file")}>
        pick a file
      </button>
    );
  },
}));

import { OracleExamplePicker } from "@/components/pipeline/oracle/OracleExamplePicker";
import { useOracleStore } from "@/stores/oracle-store";

const TEMPLATE = {
  sample_ciphertext:
    "${MEMDIVER_FIXTURE_ROOT}/gocryptfs/dataset_gocryptfs/run_0001/cipher/jxSMOg-V7hYDb5UsGpxWxg",
};

function makeExample(overrides: Partial<OracleExample> = {}): OracleExample {
  return {
    filename: "gocryptfs.py",
    path: "docs/oracle/examples/gocryptfs.py",
    sha256: "a".repeat(64),
    size: 2048,
    shape: 2,
    summary: "gocryptfs AES-GCM file oracle",
    head_lines: ["def build_oracle(cfg):"],
    config_template: TEMPLATE,
    ...overrides,
  };
}

function makeEntry(overrides: Partial<OracleEntry> = {}): OracleEntry {
  return {
    id: "orc-1",
    filename: "gocryptfs.py",
    sha256: "a".repeat(64),
    size: 2048,
    shape: 2,
    head_lines: ["def build_oracle(cfg):"],
    uploaded_at: 0,
    armed: false,
    description: null,
    ...overrides,
  };
}

function mount(examples: OracleExample[], onLoaded = vi.fn()) {
  useOracleStore.setState({ examples });
  render(
    <OracleExamplePicker selected={null} onSelect={vi.fn()} onLoaded={onLoaded} />,
  );
  return onLoaded;
}

beforeEach(() => {
  loadOracleExample.mockReset();
  armOracle.mockReset();
  fileBrowserProps.mockReset();
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

describe("OracleExamplePicker — use this example", () => {
  it("reveals a config form seeded from the example's template", () => {
    mount([makeExample()]);

    // Nothing is sent until the user has seen the placeholder for what it is.
    expect(screen.queryByTestId("oracle-example-config-gocryptfs.py")).toBeNull();
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    expect(screen.getByTestId("oracle-example-config-gocryptfs.py")).toBeInTheDocument();
    expect(screen.getByLabelText("Config key")).toHaveValue("sample_ciphertext");
    expect(screen.getByLabelText("Value for sample_ciphertext")).toHaveValue(
      TEMPLATE.sample_ciphertext,
    );
    expect(loadOracleExample).not.toHaveBeenCalled();
  });

  it("loads and arms with the typed config, in that order", async () => {
    const entry = makeEntry();
    loadOracleExample.mockResolvedValue(entry);
    armOracle.mockResolvedValue({ ...entry, armed: true });
    const onLoaded = mount([makeExample()]);

    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));
    fireEvent.change(screen.getByLabelText("Value for sample_ciphertext"), {
      target: { value: "/real/cipher/file" },
    });
    fireEvent.click(screen.getByTestId("oracle-example-arm-gocryptfs.py"));

    await waitFor(() => expect(armOracle).toHaveBeenCalled());
    const config = { sample_ciphertext: "/real/cipher/file" };
    // Third argument is the optional description the store always forwards.
    expect(loadOracleExample).toHaveBeenCalledWith("gocryptfs.py", config, undefined);
    // Arming REPLAYS build_oracle(cfg), so the same config has to go with it.
    expect(armOracle).toHaveBeenCalledWith(entry.id, entry.sha256, config);
    // The wizard form is driven from this: an armed entry is what makes Next
    // reachable in StageOracle.
    expect(onLoaded).toHaveBeenLastCalledWith(
      expect.objectContaining({ id: "orc-1", armed: true }),
    );
    expect(screen.getByTestId("oracle-example-notice")).toHaveTextContent(
      "Loaded and armed gocryptfs.py",
    );
  });

  it("surfaces a refused config as the server's own sentence, not a JSON blob", async () => {
    const entry = makeEntry();
    const detail =
      "oracle gocryptfs.py could not be loaded with the supplied configuration " +
      "(sample_ciphertext): oracle failed to load: FileNotFoundError";
    loadOracleExample.mockResolvedValue(entry);
    armOracle.mockRejectedValue(new Error(JSON.stringify({ detail })));
    mount([makeExample()]);

    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));
    fireEvent.click(screen.getByTestId("oracle-example-arm-gocryptfs.py"));

    const error = await screen.findByTestId("oracle-example-error");
    expect(error).toHaveTextContent(detail);
    expect(error.textContent).not.toContain('{"detail"');
    // The values that failed stay on screen so they can be corrected.
    expect(screen.getByTestId("oracle-example-config-gocryptfs.py")).toBeInTheDocument();
  });

  it("registers a Shape 1 example immediately, with no config form", async () => {
    const entry = makeEntry({ id: "orc-2", filename: "aes_gcm.py", shape: 1 });
    loadOracleExample.mockResolvedValue(entry);
    const onLoaded = mount([
      makeExample({
        filename: "aes_gcm.py",
        shape: 1,
        config_template: null,
        head_lines: ["def verify(candidate):"],
      }),
    ]);

    fireEvent.click(screen.getByTestId("oracle-example-use-aes_gcm.py"));

    await waitFor(() =>
      expect(loadOracleExample).toHaveBeenCalledWith("aes_gcm.py", undefined, undefined),
    );
    expect(screen.queryByTestId("oracle-example-config-aes_gcm.py")).toBeNull();
    expect(armOracle).not.toHaveBeenCalled();
    expect(onLoaded).toHaveBeenCalledWith(entry);
    expect(useOracleStore.getState().uploaded).toEqual([entry]);
  });

  it("still lets a Shape 2 example with no template be loaded unarmed", async () => {
    const entry = makeEntry({ filename: "custom.py" });
    loadOracleExample.mockResolvedValue(entry);
    mount([makeExample({ filename: "custom.py", config_template: null })]);

    fireEvent.click(screen.getByTestId("oracle-example-use-custom.py"));
    const form = screen.getByTestId("oracle-example-config-custom.py");
    expect(form).toHaveTextContent("ships no config template");

    fireEvent.click(screen.getByTestId("oracle-example-load-custom.py"));

    await waitFor(() =>
      expect(loadOracleExample).toHaveBeenCalledWith("custom.py", {}, undefined),
    );
    expect(armOracle).not.toHaveBeenCalled();
  });

  it("browses for a sample file with the extension filter lifted", async () => {
    mount([makeExample()]);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    fireEvent.click(
      screen.getByRole("button", { name: "Browse for the sample_ciphertext file" }),
    );
    // Without all_files the endpoint lists only .dump/.msl and the ciphertext
    // sample -- which has no extension at all -- is invisible.
    expect(fileBrowserProps).toHaveBeenCalledWith(
      expect.objectContaining({ allFiles: true }),
    );

    fireEvent.click(screen.getByRole("button", { name: "pick a file" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Value for sample_ciphertext")).toHaveValue(
        "/real/cipher/file",
      ),
    );
  });
});
