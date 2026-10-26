import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ApiError } from "@/api/client";
import type { ProposedLayoutResult, ValidateModelResult } from "@/api/semantic";
import i18n from "@/i18n";
import { useDumpStore } from "@/stores/dump-store";

const api = vi.hoisted(() => ({
  getAnchorConsensus: vi.fn(), proposeLayout: vi.fn(),
  buildArtifactModel: vi.fn(), exportArtifactModel: vi.fn(), validateArtifactModel: vi.fn(),
}));
vi.mock("@/api/semantic", async (orig) => ({ ...(await orig<typeof import("@/api/semantic")>()), ...api }));

const { ObjectModelPanel } = await import("@/components/semantic/ObjectModelPanel");

const A = "/dumps/a.raw";
const B = "/dumps/b.raw";
const C = "/dumps/c.raw";
const KEYLOG_TEXT = "CLIENT_TRAFFIC_SECRET_0 aa bb\nSERVER_TRAFFIC_SECRET_0 aa cc\n\n";

const LAYOUT: ProposedLayoutResult = {
  cohort: null, delta_start: -16, length: 64, occurrence: 0, anchor_length: 32,
  instances: [{ dump_path: A, va: 4096, offset: 0, view: "va", basis: "keylog", captured_bytes: 64 }],
  unanchored: [
    { dump_path: B, occurrences: 0, reason: "no CLIENT_TRAFFIC_SECRET_0 secret from the key log occurs in this dump" },
    { dump_path: C, occurrences: 0, reason: "ambiguous: 2 key-log sessions occur in this dump" },
  ],
  alternatives: {}, class_counts: {}, warnings: [],
  base_delta: -16, total_size: 96, bounds_evidence: [],
  fields: [
    { delta: 0, length: 32, kind: "anchor", name: "anchor", evidence: [], alternatives: [] },
    { delta: 32, length: 32, kind: "key", name: "server_traffic_secret_0", evidence: [], alternatives: [] },
    { delta: 64, length: 32, kind: "key", name: "client_random", evidence: [], alternatives: [] },
  ],
  keylog_anchor_label: "CLIENT_TRAFFIC_SECRET_0",
  keylog_resolution: [
    { dump_path: A, anchored: true, client_random: "abcdef0123456789", candidates: 3,
      reason: "session abcdef0123456789... is the only one present", labels: {} },
    { dump_path: B, anchored: false, client_random: null, candidates: 3,
      reason: "no CLIENT_TRAFFIC_SECRET_0 secret from the key log occurs in this dump (3 candidates searched)", labels: {} },
    { dump_path: C, anchored: false, client_random: null, candidates: 3,
      reason: "ambiguous: 2 key-log sessions occur in this dump", labels: {} },
  ],
  suggested_meanings: [
    { field: "anchor", meaning: "tls.client_traffic_secret_0", label: "CLIENT_TRAFFIC_SECRET_0" },
    { field: "server_traffic_secret_0", meaning: "tls.server_traffic_secret_0", label: "SERVER_TRAFFIC_SECRET_0" },
    { field: "not_in_proposal", meaning: "tls.nope", label: "EXPORTER_SECRET" },
    { field: "client_random", meaning: "tls.client_random", label: "" },
  ],
};

const ph = (label: string) => screen.getByLabelText(label);

beforeEach(() => {
  useDumpStore.getState().hydrateDumps({
    dumps: [A, B, C].map((p) => ({ path: p, name: p.split("/").pop()!, size: 1, format: "raw" })),
  });
});
afterEach(() => vi.clearAllMocks());

const selectKeylogMode = () =>
  fireEvent.change(ph("Anchor input"), { target: { value: "keylog" } });
const pickFile = (file: File) =>
  fireEvent.change(ph("Key log file"), { target: { files: [file] } });

async function proposeFromKeylogFile(layout: ProposedLayoutResult = LAYOUT) {
  api.proposeLayout.mockResolvedValue(layout);
  render(<ObjectModelPanel />);
  selectKeylogMode();
  pickFile(new File([KEYLOG_TEXT], "k.log"));
  await screen.findByTestId("keylog-file-summary");
  fireEvent.click(screen.getByText("Propose layout"));
  await screen.findByTestId("build-model");
}

describe("key log learning input", () => {
  it("explains the NSS key log format and hides the needle inputs", () => {
    render(<ObjectModelPanel />);
    expect(screen.getByLabelText("Needle for a.raw")).toBeInTheDocument();
    selectKeylogMode();
    expect(screen.queryByLabelText("Needle for a.raw")).toBeNull();
    expect(screen.queryByText("Add related value")).toBeNull();
    const text = screen.getByTestId("keylog-input").textContent ?? "";
    for (const word of ["NSS", "SSLKEYLOGFILE", "friTap", "Wireshark"]) expect(text).toContain(word);
  });

  it("sends a browser-chosen file as keylog.text and shows its name and line count", async () => {
    api.getAnchorConsensus.mockResolvedValue({ ...LAYOUT, min_instances: 1, regions: [] });
    render(<ObjectModelPanel />);
    selectKeylogMode();
    pickFile(new File([KEYLOG_TEXT], "k.log"));
    expect(await screen.findByTestId("keylog-file-summary")).toHaveTextContent("k.log: 2 line(s)");
    fireEvent.click(screen.getByText("Anchor consensus"));
    await screen.findByTestId("anchor-results");
    const body = api.getAnchorConsensus.mock.calls[0][0];
    expect(body).toMatchObject({
      dump_paths: [A, B, C], keylog: { text: KEYLOG_TEXT },
    });
    expect(body).not.toHaveProperty("anchor_label"); // automatic: the server chooses
    expect(body.needles).toBeUndefined();
    expect(body.related_labels).toBeUndefined(); // default = every other label
  });

  it("rejects a file above 4 MiB client-side and sends nothing", async () => {
    render(<ObjectModelPanel />);
    selectKeylogMode();
    const big = new File(["x"], "huge.log");
    Object.defineProperty(big, "size", { value: 4 * 1024 * 1024 + 1 });
    pickFile(big);
    expect(await screen.findByTestId("keylog-file-error")).toHaveTextContent("huge.log is larger than 4 MiB");
    fireEvent.click(screen.getByText("Anchor consensus"));
    expect(api.getAnchorConsensus).not.toHaveBeenCalled();
  });

  it("sends one server path for all dumps", async () => {
    api.getAnchorConsensus.mockResolvedValue({ ...LAYOUT, min_instances: 1, regions: [] });
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.change(ph("Key log source"), { target: { value: "path" } });
    fireEvent.change(ph("Key log path on the server"), { target: { value: " /k/shared.log " } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    await waitFor(() => expect(api.getAnchorConsensus).toHaveBeenCalled());
    expect(api.getAnchorConsensus.mock.calls[0][0].keylog).toEqual({ path: "/k/shared.log" });
  });

  it("sends a server key log path per dump, skipping blanks", async () => {
    api.getAnchorConsensus.mockResolvedValue({ ...LAYOUT, min_instances: 1, regions: [] });
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.change(ph("Key log source"), { target: { value: "perDump" } });
    fireEvent.change(ph("Key log path for a.raw"), { target: { value: "/k/a.log" } });
    fireEvent.change(ph("Key log path for c.raw"), { target: { value: "/k/c.log" } });
    fireEvent.click(screen.getByText("Anchor consensus"));
    await waitFor(() => expect(api.getAnchorConsensus).toHaveBeenCalled());
    expect(api.getAnchorConsensus.mock.calls[0][0].keylog).toEqual({
      per_dump: { [A]: "/k/a.log", [C]: "/k/c.log" } });
  });

  it("asks for a key log when none was given", () => {
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.click(screen.getByText("Propose layout"));
    expect(screen.getByRole("alert")).toHaveTextContent("Choose a key log file or enter a key log path");
    expect(api.proposeLayout).not.toHaveBeenCalled();
  });

  it("automatic anchor omits anchor_label and shows the label the server used", async () => {
    api.proposeLayout.mockResolvedValue({ ...LAYOUT, keylog_anchor_label: "CLIENT_RANDOM" });
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.change(ph("Key log source"), { target: { value: "path" } });
    fireEvent.change(ph("Key log path on the server"), { target: { value: "/k.log" } });
    expect(screen.getByRole("combobox", { name: "Anchor label" })).toHaveValue("");
    fireEvent.click(screen.getByText("Propose layout"));
    await waitFor(() => expect(api.proposeLayout).toHaveBeenCalled());
    expect(api.proposeLayout.mock.calls[0][0]).not.toHaveProperty("anchor_label");
    expect(await screen.findByTestId("keylog-resolution")).toHaveTextContent("anchor label CLIENT_RANDOM");
  });

  it("sends the chosen anchor label and only the related labels left switched on", async () => {
    api.proposeLayout.mockResolvedValue(LAYOUT);
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.change(ph("Key log source"), { target: { value: "path" } });
    fireEvent.change(ph("Key log path on the server"), { target: { value: "/k.log" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Anchor label" }), { target: { value: "CLIENT_RANDOM" } });
    fireEvent.click(ph("Include related label EXPORTER_SECRET"));
    fireEvent.click(screen.getByText("Propose layout"));
    await waitFor(() => expect(api.proposeLayout).toHaveBeenCalled());
    const body = api.proposeLayout.mock.calls[0][0];
    expect(body.anchor_label).toBe("CLIENT_RANDOM");
    expect(body.related_labels).toEqual([
      "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
      "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    ]);
    expect(body.related).toBeUndefined();
  });
});

describe("key log resolution", () => {
  it("shows the chosen session and makes absent and ambiguous dumps prominent", async () => {
    await proposeFromKeylogFile();
    const rows = screen.getAllByTestId("keylog-resolution-row");
    expect(rows.map((r) => r.getAttribute("data-status"))).toEqual(["anchored", "absent", "ambiguous"]);
    expect(rows[0]).toHaveTextContent("abcdef0123456789");
    expect(rows[0]).toHaveTextContent("3");
    expect(rows[1]).toHaveTextContent("no CLIENT_TRAFFIC_SECRET_0 secret");
    expect(rows[2]).toHaveTextContent("ambiguous: 2 key-log sessions");
    expect(screen.getByTestId("keylog-unanchored")).toHaveTextContent("2 dump(s) could not be anchored");
    expect(rows[1].className).toContain("--md-variance-key-candidate");
    expect(screen.getByTestId("unanchored")).toBeInTheDocument();
  });

  const summary = (over: object) => ({
    text: "<uploaded>", sessions: 1, rows: 3, ignored: {}, malformed: 0, conflicts: 0,
    malformed_details: [], length_mismatches: [], ...over,
  });

  it("warns about malformed lines with line numbers and reasons, plus ignored and mismatches", async () => {
    await proposeFromKeylogFile({
      ...LAYOUT,
      keylog_summary: [summary({
        malformed: 2, ignored: { RSA_PREMASTER_SECRET: 1, CLIENT_EARLY_TRAFFIC_SECRET: 2 },
        malformed_details: [
          { line: 4, reason: "secret is 2 bytes, expected at least 16" },
          { line: 9, reason: "not a valid key-log line" },
        ],
        length_mismatches: ["ab".repeat(32)],
      })],
    });
    expect(await screen.findByTestId("keylog-malformed")).toHaveAttribute("role", "alert");
    expect(screen.getByTestId("keylog-malformed")).toHaveTextContent("2 malformed key log line(s)");
    const lines = screen.getAllByTestId("keylog-malformed-line");
    expect(lines[0]).toHaveTextContent("Line 4: secret is 2 bytes, expected at least 16");
    expect(lines[1]).toHaveTextContent("Line 9: not a valid key-log line");
    expect(screen.queryByTestId("keylog-malformed-more")).toBeNull();
    expect(screen.getByTestId("keylog-ignored")).toHaveTextContent("3 line(s) ignored");
    expect(screen.getByTestId("keylog-ignored")).toHaveTextContent("RSA_PREMASTER_SECRET x1");
    expect(screen.getByTestId("keylog-length-mismatch")).toHaveTextContent("1 session(s)");
  });

  it("caps the malformed list at 20 with a +N more line", async () => {
    const details = Array.from({ length: 25 }, (_, i) => ({ line: i + 1, reason: "bad" }));
    await proposeFromKeylogFile({
      ...LAYOUT, keylog_summary: [summary({ malformed: 25, malformed_details: details })],
    });
    expect(await screen.findAllByTestId("keylog-malformed-line")).toHaveLength(20);
    expect(screen.getByTestId("keylog-malformed-more")).toHaveTextContent("+5 more");
  });

  it("shows nothing extra for a clean key log", async () => {
    await proposeFromKeylogFile({ ...LAYOUT, keylog_summary: [summary({})] });
    await screen.findByTestId("keylog-resolution");
    expect(screen.queryByTestId("keylog-parse-report")).toBeNull();
  });
});

describe("build pre-filled from suggested_meanings", () => {
  it("pre-fills meanings, labels and owned_by relationships, and sends them unedited", async () => {
    await proposeFromKeylogFile();
    expect(screen.getByTestId("build-prefilled")).toBeInTheDocument();
    expect((ph("Meaning for anchor") as HTMLInputElement).value).toBe("tls.client_traffic_secret_0");
    expect((ph("Output label for anchor") as HTMLInputElement).value).toBe("CLIENT_TRAFFIC_SECRET_0");
    expect((ph("Meaning for client_random") as HTMLInputElement).value).toBe("tls.client_random");
    expect(screen.queryByLabelText("Meaning for not_in_proposal")).toBeNull();

    api.buildArtifactModel.mockResolvedValue({
      model: {}, path: "/out/m.json", sha256: "abc", problems: [], proposal: LAYOUT });
    fireEvent.change(ph("Model name"), { target: { value: "tls" } });
    fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/out/m.json" } });
    fireEvent.click(screen.getByText("Build model", { selector: "button" }));
    await screen.findByTestId("build-result");
    const body = api.buildArtifactModel.mock.calls[0][0];
    expect(body.keylog).toEqual({ text: KEYLOG_TEXT });
    expect(body.meanings).toEqual([
      { field: "anchor", meaning: "tls.client_traffic_secret_0", label: "CLIENT_TRAFFIC_SECRET_0" },
      { field: "server_traffic_secret_0", meaning: "tls.server_traffic_secret_0", label: "SERVER_TRAFFIC_SECRET_0" },
      { field: "client_random", meaning: "tls.client_random", label: "" },
    ]);
    expect(body.relationships).toEqual([
      { kind: "owned_by", source: "anchor", target: "client_random" },
      { kind: "owned_by", source: "server_traffic_secret_0", target: "client_random" },
    ]);
  });
});

const VALID = (captures: Partial<ValidateModelResult["captures"][number]>[]): ValidateModelResult => ({
  verdict: "indeterminate", labels: ["L"], plugin_sha256: "p", seconds: 1,
  captures: captures.map((c, i) => ({
    capture: `h${i}.msl`, expected: 0, true_positives: 0, false_positives: 0, false_negatives: 0,
    relationships_correct: 0, relationships_checked: 0, detail: "", ...c })),
  totals: { expected: 0, tp: 0, fp: 0, fn: 0, relationships_correct: 0, relationships_checked: 0 },
});

async function openValidate() {
  await proposeFromKeylogFile();
  api.buildArtifactModel.mockResolvedValue({
    model: {}, path: "/out/m.json", sha256: "abc", problems: [], proposal: LAYOUT });
  fireEvent.change(ph("Model name"), { target: { value: "tls" } });
  fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/out/m.json" } });
  fireEvent.click(screen.getByText("Build model", { selector: "button" }));
  await screen.findByTestId("validate-model");
}

describe("validate with one shared key log", () => {
  it("sends a shared key log file for all held-out dumps with no per-row key log", async () => {
    await openValidate();
    fireEvent.change(ph("Key log for the held-out dumps"), { target: { value: "file" } });
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.click(screen.getByText("Add held-out dump"));
    expect(screen.queryByLabelText("Keylog path")).toBeNull();
    const dumps = screen.getAllByLabelText("Held-out dump path");
    fireEvent.change(dumps[0], { target: { value: "/h/1.msl" } });
    fireEvent.change(dumps[1], { target: { value: "/h/2.msl" } });
    const validate = within(screen.getByTestId("validate-model"));
    fireEvent.change(validate.getByLabelText("Key log file"), { target: { files: [new File(["held text\n"], "h.log")] } });
    await validate.findByTestId("keylog-file-summary");
    api.validateArtifactModel.mockResolvedValue(VALID([{}]));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    await screen.findByTestId("validate-result");
    expect(api.validateArtifactModel).toHaveBeenCalledWith({
      model_path: "/out/m.json",
      held_out: [{ dump_path: "/h/1.msl" }, { dump_path: "/h/2.msl" }],
      keylog: { text: "held text\n" },
    });
  });

  it("sends a shared server path, and asks for one when missing", async () => {
    await openValidate();
    fireEvent.change(ph("Key log for the held-out dumps"), { target: { value: "path" } });
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/h/1.msl" } });
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    expect(screen.getByTestId("validate-error")).toHaveTextContent("shared key log");
    expect(api.validateArtifactModel).not.toHaveBeenCalled();
    fireEvent.change(ph("Shared key log path on the server"), { target: { value: "/k/held.log" } });
    api.validateArtifactModel.mockResolvedValue(VALID([{}]));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    await screen.findByTestId("validate-result");
    expect(api.validateArtifactModel.mock.calls[0][0].keylog).toEqual({ path: "/k/held.log" });
  });

  it("shows an indeterminate capture clearly and never as a pass", async () => {
    await openValidate();
    fireEvent.change(ph("Key log for the held-out dumps"), { target: { value: "path" } });
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/h/1.msl" } });
    fireEvent.change(ph("Shared key log path on the server"), { target: { value: "/k/held.log" } });
    api.validateArtifactModel.mockResolvedValue(VALID([
      { verdict: "indeterminate", detail: "0 sessions" }, { verdict: "pass", expected: 2, true_positives: 2 }]));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    await screen.findByTestId("validate-result");
    const rows = screen.getAllByTestId("validate-row");
    expect(rows[0]).toHaveAttribute("data-verdict", "indeterminate");
    expect(within(rows[0]).getByTestId("indeterminate-note")).toHaveTextContent("not a pass");
    expect(within(rows[0]).getByTestId("verdict-badge").style.color).toBe("var(--md-text-muted)");
    expect(within(rows[1]).queryByTestId("indeterminate-note")).toBeNull();
  });
});

describe("backend error detail is shown verbatim", () => {
  const FORBIDDEN = "Path is outside the allowed roots; set MEMDIVER_ALLOWED_ROOTS to widen the sandbox.";

  it("shows a 403 sandbox detail instead of a generic Forbidden", async () => {
    api.proposeLayout.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: FORBIDDEN })));
    render(<ObjectModelPanel />);
    selectKeylogMode();
    fireEvent.change(ph("Key log source"), { target: { value: "path" } });
    fireEvent.change(ph("Key log path on the server"), { target: { value: "/etc/k.log" } });
    fireEvent.click(screen.getByText("Propose layout"));
    expect(await screen.findByRole("alert")).toHaveTextContent(FORBIDDEN);
    expect(screen.getByRole("alert").textContent).not.toMatch(/^Request failed: Forbidden/);
  });

  it("shows the raw-dump import suggestion and a 403 write-location refusal", async () => {
    const noVa = "semantic.no_va_view: this raw dump has no virtual-address view; import it to .msl first.";
    api.proposeLayout.mockRejectedValue(new ApiError(400, JSON.stringify({ error: noVa, code: "semantic.no_va_view" })));
    await (async () => {
      render(<ObjectModelPanel />);
      selectKeylogMode();
      fireEvent.change(ph("Key log source"), { target: { value: "path" } });
      fireEvent.change(ph("Key log path on the server"), { target: { value: "/k.log" } });
      fireEvent.click(screen.getByText("Propose layout"));
    })();
    expect(await screen.findByRole("alert")).toHaveTextContent("import it to .msl first");
  });

  it("shows a 403 write-location detail on build", async () => {
    await proposeFromKeylogFile();
    const refusal = "out_path must be inside the upload directory /var/memdiver/uploads";
    api.buildArtifactModel.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: refusal })));
    fireEvent.change(ph("Model name"), { target: { value: "tls" } });
    fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/x/m.json" } });
    fireEvent.click(screen.getByText("Build model", { selector: "button" }));
    expect(await screen.findByTestId("build-error")).toHaveTextContent(refusal);
  });
});

describe("key log i18n", () => {
  it("every key the key log UI uses exists", () => {
    const keys = [
      "keylog.modeLabel", "keylog.modeNeedle", "keylog.modeKeylog", "keylog.explain", "keylog.sourceLabel",
      "keylog.source.file", "keylog.source.path", "keylog.source.perDump", "keylog.chooseFile",
      "keylog.fileSummary", "keylog.fileTooLarge", "keylog.fileReadFailed", "keylog.pathLabel", "keylog.pathFor",
      "keylog.anchorLabel", "keylog.anchorAutomatic", "keylog.anchorHint", "keylog.relatedLabels", "keylog.relatedLabel",
      "keylog.resolution.title", "keylog.resolution.failedTitle", "keylog.resolution.dump",
      "keylog.resolution.status", "keylog.resolution.clientRandom", "keylog.resolution.candidates",
      "keylog.resolution.reason", "keylog.resolution.anchored", "keylog.resolution.absent",
      "keylog.resolution.ambiguous", "errors.noKeylog", "build.prefilled", "validate.keylogMode",
      "validate.keylogModes.perRow", "validate.keylogModes.file", "validate.keylogModes.path",
      "validate.sharedPath", "validate.needDumps", "validate.needSharedKeylog", "validate.indeterminateNote",
    ];
    for (const k of keys) expect(i18n.exists(k, { ns: "objectModel" }), k).toBe(true);
  });
});
