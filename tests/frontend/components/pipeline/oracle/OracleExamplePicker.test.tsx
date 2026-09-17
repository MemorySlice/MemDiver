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
 *
 * The second regression it pins: that seeded config used to arrive in the
 * input's VALUE, so the bundled template's stand-in path read as a real answer
 * and was submitted verbatim — a guaranteed server error on a fresh install.
 * A placeholder is now empty-and-required, and what the server can derive from
 * the already-picked dumps is prefilled with its provenance beside it.
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
const smokeTestOracle = vi.fn();
const deleteOracle = vi.fn();
const suggestExampleConfig = vi.fn();
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
  suggestExampleConfig: (...a: unknown[]) => suggestExampleConfig(...a),
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

/**
 * A template value that is every bit as fake but matches no ``${VAR}``.
 *
 * The bundled .toml says exactly this now, which is why the server has to name
 * its placeholder keys: a regex over the value would wave this one through.
 */
const PLAIN_TEMPLATE = {
  sample_ciphertext: "/absolute/path/to/your/gocryptfs/vault/cipher/<any-encrypted-file>",
  cipher: "aes",
};

/** Stable identities: the picker re-derives whenever the first dump changes. */
const NO_DUMPS: string[] = [];
const RUN_1_DUMPS = ["/dumps/run_0001/pre.msl"];
const RUN_2_DUMPS = ["/dumps/run_0002/pre.msl"];

/** What the server answers when it could derive the config from the dumps. */
function makeSuggestion(overrides: Record<string, unknown> = {}) {
  return {
    config: { sample_ciphertext: "/vault/run_0001/cipher/aaa" },
    provenance: "the vault beside run_0001",
    blocked_reason: null,
    warnings: [],
    reference_run: "run_0001",
    reference_dump: RUN_1_DUMPS[0],
    ...overrides,
  };
}

/** The 200 that means "nothing derivable" — a result, not a failure. */
const NO_SUGGESTION = makeSuggestion({
  config: {},
  provenance: null,
  reference_run: null,
  reference_dump: null,
});

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
    // The server, not the value's shape, decides what is a question.
    config_placeholders: ["sample_ciphertext"],
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

function mount(
  examples: OracleExample[],
  onLoaded = vi.fn(),
  sourcePaths: string[] = NO_DUMPS,
) {
  useOracleStore.setState({ examples });
  render(
    <OracleExamplePicker
      selected={null}
      onSelect={vi.fn()}
      onLoaded={onLoaded}
      sourcePaths={sourcePaths}
    />,
  );
  return onLoaded;
}

beforeEach(() => {
  loadOracleExample.mockReset();
  armOracle.mockReset();
  fileBrowserProps.mockReset();
  suggestExampleConfig.mockReset();
  // Most cases mount with no dumps picked, so the picker never asks; this is
  // the answer for the ones that do and do not care what comes back.
  suggestExampleConfig.mockResolvedValue(NO_SUGGESTION);
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
  it("offers the template as a placeholder, never as the value, and blocks on it", () => {
    mount([makeExample()]);

    expect(screen.queryByTestId("oracle-example-config-gocryptfs.py")).toBeNull();
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    expect(screen.getByTestId("oracle-example-config-gocryptfs.py")).toBeInTheDocument();
    expect(screen.getByLabelText("Config key")).toHaveValue("sample_ciphertext");
    // The bug: seeded into the value, ${MEMDIVER_FIXTURE_ROOT}/... reads as an
    // answer and is submitted verbatim. Nothing in the product expands it and
    // the file it names is on nobody's machine, so the load always failed.
    const input = screen.getByLabelText("Value for sample_ciphertext");
    expect(input).toHaveValue("");
    expect(input).toHaveAttribute("placeholder", TEMPLATE.sample_ciphertext);
    // ...and the form says why it will not go anywhere yet, in text, on the
    // page -- a title on a disabled button is announced to nobody.
    const blocked = screen.getByTestId("oracle-example-unfilled");
    expect(blocked).toHaveTextContent("sample_ciphertext");
    const armBtn = screen.getByTestId("oracle-example-arm-gocryptfs.py");
    const loadBtn = screen.getByTestId("oracle-example-load-gocryptfs.py");
    expect(armBtn).toBeDisabled();
    expect(loadBtn).toBeDisabled();
    expect(armBtn.getAttribute("aria-describedby")).toBe(blocked.id);
    expect(loadBtn.getAttribute("aria-describedby")).toBe(blocked.id);
    // The row that most needs the browser is the one with nothing in it.
    expect(
      screen.getByRole("button", { name: "Browse for the sample_ciphertext file" }),
    ).toBeInTheDocument();
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
    const notice = screen.getByTestId("oracle-example-notice");
    expect(notice).toHaveTextContent("Loaded and armed gocryptfs.py");
    // "Armed" is the state this whole stage exists to reach and this notice is
    // the only signal of it, so it is weighted like a result: the success token
    // rather than the 10px muted grey it used to share with the fine print.
    expect(notice).toHaveClass("md-text-success");
    expect(notice.className).not.toContain("md-text-muted");
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
    // A real value, because an unanswered placeholder never reaches the server
    // any more; what this case is about is how a REFUSAL is rendered.
    fireEvent.change(screen.getByLabelText("Value for sample_ciphertext"), {
      target: { value: "/real/cipher/file" },
    });
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

  it("does not dress an unarmed load as success", async () => {
    // Three outcomes share one notice element and only ARMED lets the wizard
    // advance: loading unarmed leaves oracleSha256 null, so "Next" stays
    // disabled. Green-on-green there would promise a button the analyst cannot
    // press, which is the exact confusion this stage already cost us once.
    const entry = makeEntry({ filename: "custom.py" });
    loadOracleExample.mockResolvedValue(entry);
    mount([makeExample({ filename: "custom.py", config_template: null })]);

    fireEvent.click(screen.getByTestId("oracle-example-use-custom.py"));
    fireEvent.click(screen.getByTestId("oracle-example-load-custom.py"));

    const notice = await screen.findByTestId("oracle-example-notice");
    expect(notice).toHaveTextContent("unarmed");
    expect(notice).not.toHaveClass("md-text-success");
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
describe("OracleExamplePicker — an unanswered placeholder", () => {
  const armBtn = () => screen.getByTestId("oracle-example-arm-gocryptfs.py");
  const loadBtn = () => screen.getByTestId("oracle-example-load-gocryptfs.py");

  it("unblocks both buttons as soon as the row is answered", () => {
    mount([makeExample()]);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));
    expect(armBtn()).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Value for sample_ciphertext"), {
      target: { value: "/real/cipher/file" },
    });

    expect(armBtn()).toBeEnabled();
    expect(loadBtn()).toBeEnabled();
    expect(screen.queryByTestId("oracle-example-unfilled")).toBeNull();
    expect(armBtn()).not.toHaveAttribute("aria-describedby");
  });

  it("does not count whitespace as an answer", () => {
    mount([makeExample()]);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    fireEvent.change(screen.getByLabelText("Value for sample_ciphertext"), {
      target: { value: "   " },
    });

    // The server would see an empty string and reject it one round trip later.
    expect(armBtn()).toBeDisabled();
    expect(screen.getByTestId("oracle-example-unfilled")).toBeInTheDocument();
  });

  it("is blind to a row the user added by hand", async () => {
    const entry = makeEntry({ filename: "custom.py" });
    loadOracleExample.mockResolvedValue(entry);
    mount([makeExample({ filename: "custom.py", config_template: null })]);
    fireEvent.click(screen.getByTestId("oracle-example-use-custom.py"));

    // An empty row nobody asked for is not an unanswered question: it is a row
    // ``buildConfig`` drops, so it must never hold the load buttons hostage.
    fireEvent.click(screen.getByRole("button", { name: "+ Add field" }));

    expect(screen.getByTestId("oracle-example-load-custom.py")).toBeEnabled();
    expect(screen.queryByTestId("oracle-example-unfilled")).toBeNull();
  });

  it("trusts the server's placeholder list over the shape of the value", () => {
    mount([
      makeExample({
        config_template: PLAIN_TEMPLATE,
        config_placeholders: ["sample_ciphertext"],
      }),
    ]);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    // Matches no ${VAR}; it is a placeholder purely because the server said so.
    const sample = screen.getByLabelText("Value for sample_ciphertext");
    expect(sample).toHaveValue("");
    expect(sample).toHaveAttribute("placeholder", PLAIN_TEMPLATE.sample_ciphertext);
    expect(screen.getByTestId("oracle-cfg-note-sample_ciphertext")).toHaveTextContent(
      PLAIN_TEMPLATE.sample_ciphertext,
    );
    expect(armBtn()).toBeDisabled();
    // A key the server did NOT list is an answer and stays one.
    expect(screen.getByLabelText("Value for cipher")).toHaveValue("aes");
    expect(screen.getByTestId("oracle-example-unfilled")).not.toHaveTextContent(
      "cipher,",
    );
  });
});

describe("OracleExamplePicker — config derived from the picked dumps", () => {
  const sample = () => screen.getByLabelText("Value for sample_ciphertext");

  it("prefills the empty row and says where the value came from", async () => {
    suggestExampleConfig.mockResolvedValue(makeSuggestion());
    mount([makeExample()], vi.fn(), RUN_1_DUMPS);

    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    await waitFor(() => expect(sample()).toHaveValue("/vault/run_0001/cipher/aaa"));
    expect(suggestExampleConfig).toHaveBeenCalledWith("gocryptfs.py", RUN_1_DUMPS);
    // A value that appears by itself has to say where it came from.
    expect(
      screen.getByTestId("oracle-cfg-provenance-sample_ciphertext"),
    ).toHaveTextContent("the vault beside run_0001");
    expect(screen.queryByTestId("oracle-example-unfilled")).toBeNull();
    expect(screen.getByTestId("oracle-example-arm-gocryptfs.py")).toBeEnabled();
  });

  it("renders a half-made derivation's warnings without blocking on them", async () => {
    suggestExampleConfig.mockResolvedValue(
      makeSuggestion({ warnings: ["two vaults beside this dump; picked the first"] }),
    );
    mount([makeExample()], vi.fn(), RUN_1_DUMPS);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    const warning = await screen.findByTestId("oracle-example-suggest-warning");
    expect(warning).toHaveTextContent("two vaults beside this dump");
    expect(screen.getByTestId("oracle-example-arm-gocryptfs.py")).toBeEnabled();
  });

  it("never overwrites a value the user typed", async () => {
    let answer: (value: unknown) => void = () => {};
    suggestExampleConfig.mockReturnValue(
      new Promise((resolve) => {
        answer = resolve;
      }),
    );
    mount([makeExample()], vi.fn(), RUN_1_DUMPS);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    // The analyst answers first; the server's guess lands afterwards.
    fireEvent.change(sample(), { target: { value: "/my/own/choice" } });
    answer(makeSuggestion());

    await waitFor(() =>
      expect(
        screen.getByTestId("oracle-cfg-provenance-sample_ciphertext"),
      ).toBeInTheDocument(),
    );
    expect(sample()).toHaveValue("/my/own/choice");
  });

  it("refuses to load at all when the oracle cannot verify these dumps", async () => {
    suggestExampleConfig.mockResolvedValue(
      makeSuggestion({
        blocked_reason: "run_0001 was captured with chacha20, this oracle verifies aes.",
      }),
    );
    mount([makeExample()], vi.fn(), RUN_1_DUMPS);
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));

    // Arming here would sweep every candidate to false, which reads exactly
    // like "the key is not in the dump" -- the one wrong answer.
    const blocked = await screen.findByTestId("oracle-example-blocked");
    expect(blocked).toHaveTextContent("chacha20");
    const arm = screen.getByTestId("oracle-example-arm-gocryptfs.py");
    const load = screen.getByTestId("oracle-example-load-gocryptfs.py");
    expect(arm).toBeDisabled();
    expect(load).toBeDisabled();
    expect(arm.getAttribute("aria-describedby")).toContain(blocked.id);
    expect(load.getAttribute("aria-describedby")).toContain(blocked.id);
  });

  it("names the run the values came from once the dumps move on", async () => {
    suggestExampleConfig.mockResolvedValueOnce(makeSuggestion());
    useOracleStore.setState({ examples: [makeExample()] });
    const props = { selected: null, onSelect: vi.fn(), onLoaded: vi.fn() };
    const { rerender } = render(
      <OracleExamplePicker {...props} sourcePaths={RUN_1_DUMPS} />,
    );
    fireEvent.click(screen.getByTestId("oracle-example-use-gocryptfs.py"));
    await waitFor(() => expect(sample()).toHaveValue("/vault/run_0001/cipher/aaa"));

    suggestExampleConfig.mockResolvedValueOnce(
      makeSuggestion({
        config: { sample_ciphertext: "/vault/run_0002/cipher/bbb" },
        reference_run: "run_0002",
        reference_dump: RUN_2_DUMPS[0],
      }),
    );
    rerender(<OracleExamplePicker {...props} sourcePaths={RUN_2_DUMPS} />);

    // Only sourcePaths[0] is swept and every run has its own master key, so a
    // config for run_0001 against run_0002 is a silent zero-hit sweep.
    const notice = await screen.findByTestId("oracle-example-reference-changed");
    expect(notice).toHaveTextContent("run_0001");
    expect(suggestExampleConfig).toHaveBeenLastCalledWith("gocryptfs.py", RUN_2_DUMPS);
    // The typed/derived value is still the user's to keep or clear.
    expect(sample()).toHaveValue("/vault/run_0001/cipher/aaa");
  });
});
