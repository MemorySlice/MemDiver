import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ApiError } from "@/api/client";
import type { ProposedLayoutResult, ValidateModelResult } from "@/api/semantic";
import enObjectModel from "@/i18n/locales/en/objectModel.json";
import { useDumpStore } from "@/stores/dump-store";

const api = vi.hoisted(() => ({
  getAnchorConsensus: vi.fn(), proposeLayout: vi.fn(),
  buildArtifactModel: vi.fn(), exportArtifactModel: vi.fn(), validateArtifactModel: vi.fn(),
}));
vi.mock("@/api/semantic", async (orig) => ({ ...(await orig<typeof import("@/api/semantic")>()), ...api }));

const { ObjectModelPanel } = await import("@/components/semantic/ObjectModelPanel");

const A = "/dumps/a.raw";
const LAYOUT: ProposedLayoutResult = {
  cohort: null, delta_start: -16, length: 64, occurrence: 0, anchor_length: 8,
  instances: [{ dump_path: A, va: 4096, offset: 0, view: "va", basis: "needle", captured_bytes: 64 }],
  unanchored: [], alternatives: {}, class_counts: {}, warnings: [],
  base_delta: -16, total_size: 96, bounds_evidence: [],
  fields: [
    { delta: 0, length: 8, kind: "anchor", name: "anchor", evidence: [], alternatives: [] },
    { delta: 8, length: 32, kind: "key", name: "key_+0x8", evidence: [], alternatives: [] },
  ],
};
const VALID = (verdict: string): ValidateModelResult => ({
  verdict, labels: ["CLIENT"], plugin_sha256: "p", seconds: 1,
  captures: [{ capture: "h.msl", expected: 2, true_positives: 1, false_positives: 0,
    false_negatives: 1, relationships_correct: 1, relationships_checked: 1, detail: "3 runs" }],
  totals: { expected: 2, tp: 1, fp: 0, fn: 1, relationships_correct: 1, relationships_checked: 1 },
});

const ph = (label: string) => screen.getByLabelText(label);

async function openBuild() {
  api.proposeLayout.mockResolvedValue(LAYOUT);
  render(<ObjectModelPanel />);
  fireEvent.change(ph("Needle for a.raw"), { target: { value: "aabb" } });
  fireEvent.click(screen.getByText("Propose layout"));
  await screen.findByTestId("build-model");
}

async function buildOk() {
  api.buildArtifactModel.mockResolvedValue({
    model: {}, path: "/out/m.json", sha256: "abc123", problems: [], proposal: LAYOUT });
  fireEvent.change(ph("Model name"), { target: { value: "tls" } });
  fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/out/m.json" } });
  fireEvent.click(screen.getByText("Build model", { selector: "button" }));
  await screen.findByTestId("build-result");
}

beforeEach(() => {
  useDumpStore.getState().hydrateDumps({ dumps: [{ path: A, name: "a.raw", size: 1, format: "raw" }] });
});
afterEach(() => vi.clearAllMocks());

describe("Build model", () => {
  it("sends only chosen meanings, relationships and applicability with the learn inputs", async () => {
    await openBuild();
    api.buildArtifactModel.mockResolvedValue({
      model: {}, path: "/out/m.json", sha256: "abc123", problems: [], proposal: LAYOUT });
    fireEvent.change(ph("Model name"), { target: { value: "tls" } });
    fireEvent.change(ph("Meaning for key_+0x8"), { target: { value: "tls_secret" } });
    fireEvent.change(ph("Output label for key_+0x8"), { target: { value: "CLIENT" } });
    fireEvent.click(screen.getByText("Add relationship"));
    fireEvent.change(ph("Relationship kind"), { target: { value: "pointer" } });
    fireEvent.change(ph("Source field"), { target: { value: "key_+0x8" } });
    fireEvent.change(ph("Target field"), { target: { value: "anchor" } });
    fireEvent.change(ph("Applicability: library"), { target: { value: "boringssl" } });
    fireEvent.change(ph("Applicability: states (comma separated)"), { target: { value: "live, idle" } });
    fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/out/m.json" } });
    fireEvent.click(screen.getByText("Build model", { selector: "button" }));
    await screen.findByTestId("build-result");
    expect(api.buildArtifactModel.mock.calls[0][0]).toMatchObject({
      dump_paths: [A], needles: { [A]: "aabb" }, name: "tls", out_path: "/out/m.json",
      meanings: [{ field: "key_+0x8", meaning: "tls_secret", label: "CLIENT" }],
      relationships: [{ kind: "pointer", source: "key_+0x8", target: "anchor" }],
      applicability: { library: "boringssl", states: ["live", "idle"] },
    });
    expect(screen.getByTestId("build-result")).toHaveTextContent("abc123");
  });

  it("shows a builder refusal inline", async () => {
    await openBuild();
    api.buildArtifactModel.mockRejectedValue(
      new ApiError(400, JSON.stringify({ error: "meaning names an unproposed field 'zzz'" })));
    fireEvent.change(ph("Model name"), { target: { value: "tls" } });
    fireEvent.change(ph("Model JSON output path (new .json file)"), { target: { value: "/out/m.json" } });
    fireEvent.click(screen.getByText("Build model", { selector: "button" }));
    expect(await screen.findByTestId("build-error")).toHaveTextContent("unproposed field");
    expect(screen.queryByTestId("build-result")).toBeNull();
  });

  it("renders the export result", async () => {
    await openBuild();
    await buildOk();
    api.exportArtifactModel.mockResolvedValue({
      path: "/out/p.py", sha256: "ff00", locator_kind: "needle", class_name: "TlsKeys", bytes: 1234 });
    fireEvent.change(ph("Plugin output path (new .py file)"), { target: { value: "/out/p.py" } });
    fireEvent.click(screen.getByText("Export plugin", { selector: "button" }));
    const res = await screen.findByTestId("export-result");
    expect(api.exportArtifactModel).toHaveBeenCalledWith({ model_path: "/out/m.json", out_path: "/out/p.py" });
    for (const text of ["/out/p.py", "ff00", "TlsKeys", "1234"]) expect(res).toHaveTextContent(text);
  });

  it("warns on a learned dump, posts held-out entries and renders the table", async () => {
    await openBuild();
    await buildOk();
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: A } });
    fireEvent.change(ph("Keylog path"), { target: { value: "/k.log" } });
    expect(screen.getByTestId("leak-warning")).toHaveTextContent("a.raw");
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/dumps/h.raw" } });
    expect(screen.queryByTestId("leak-warning")).toBeNull();
    api.validateArtifactModel.mockResolvedValue(VALID("fail"));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    await screen.findByTestId("validate-result");
    expect(api.validateArtifactModel).toHaveBeenCalledWith({
      model_path: "/out/m.json", held_out: [{ dump_path: "/dumps/h.raw", keylog_path: "/k.log" }] });
    const row = within(screen.getByTestId("validate-row"));
    for (const text of ["h.msl", "1/1", "3 runs"]) expect(row.getByText(text)).toBeInTheDocument();
    expect(screen.getByTestId("validate-totals")).toHaveTextContent("1/1");
    expect(screen.getByTestId("verdict-badge")).toHaveAttribute("data-verdict", "fail");
  });

  it("displays the authoritative leak refusal from the server", async () => {
    await openBuild();
    await buildOk();
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/x" } });
    fireEvent.change(ph("Keylog path"), { target: { value: "/k" } });
    api.validateArtifactModel.mockRejectedValue(
      new ApiError(400, JSON.stringify({ error: "held-out dump was used for learning: /x" })));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    expect(await screen.findByTestId("validate-error")).toHaveTextContent("used for learning");
  });

  it.each([
    ["pass", "pass", "var(--md-accent-green)"],
    ["fail", "fail", "var(--md-variance-key-candidate)"],
    ["indeterminate", "indeterminate", "var(--md-text-muted)"],
    ["weird", "unknown (weird)", "var(--md-text-muted)"],
  ])("styles verdict %s without success colour unless pass", async (verdict, text, colour) => {
    await openBuild();
    await buildOk();
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/h" } });
    fireEvent.change(ph("Keylog path"), { target: { value: "/k" } });
    api.validateArtifactModel.mockResolvedValue(VALID(verdict));
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    const badge = await screen.findByTestId("verdict-badge");
    await waitFor(() => expect(badge).toHaveTextContent(text));
    expect(badge.style.color).toBe(colour);
  });

  it("shows dropped lines of the shared held-out key log next to the verdict", async () => {
    await openBuild();
    await buildOk();
    fireEvent.click(screen.getByText("Add held-out dump"));
    fireEvent.change(ph("Held-out dump path"), { target: { value: "/h" } });
    fireEvent.change(ph("Keylog path"), { target: { value: "/k" } });
    api.validateArtifactModel.mockResolvedValue({
      ...VALID("pass"),
      keylog_summary: [{ text: "shared", sessions: 1, rows: 3, conflicts: 0,
        malformed: 1, ignored: {}, length_mismatches: [],
        malformed_details: [{ line: 23, reason: "secret is 2 bytes, expected one of [32, 48]" }] }],
    } as ValidateModelResult);
    fireEvent.click(screen.getByText("Validate", { selector: "button" }));
    const report = await screen.findByTestId("keylog-parse-report");
    expect(report).toHaveTextContent("23");
    expect(report).toHaveTextContent("secret is 2 bytes");
  });
});

describe("objectModel i18n (part 2)", () => {
  it("defines every build/export/validate key", () => {
    const flat = (o: Record<string, unknown>, pre = ""): string[] =>
      Object.entries(o).flatMap(([k, v]) =>
        typeof v === "object" && v !== null ? flat(v as Record<string, unknown>, `${pre}${k}.`) : [`${pre}${k}`]);
    const keys = flat(enObjectModel as Record<string, unknown>);
    for (const k of ["build.title", "build.refused", "export.className", "validate.leakWarning",
      "validate.verdict.pass", "validate.verdict.fail", "validate.verdict.indeterminate"]) {
      expect(keys).toContain(k);
    }
  });
});

describe("Build model staleness", () => {
  it("drops the built model and field list when a new proposal is run", async () => {
    await openBuild();
    await buildOk();
    const next: ProposedLayoutResult = {
      ...LAYOUT,
      fields: [{ delta: 0, length: 4, kind: "anchor", name: "fresh_field", evidence: [], alternatives: [] }],
    };
    api.proposeLayout.mockResolvedValue(next);
    fireEvent.click(screen.getByText("Propose layout"));
    await screen.findByLabelText("Meaning for fresh_field");
    expect(screen.queryByTestId("build-result")).toBeNull();
    expect(screen.queryByLabelText("Meaning for key_+0x8")).toBeNull();
    expect((ph("Model name") as HTMLInputElement).value).toBe("");
  });
});

