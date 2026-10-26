import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { prov } from "./helpers";

const api = vi.hoisted(() => ({
  getIsfDraftVersions: vi.fn(), retractIsfEntry: vi.fn(), diffIsfDraft: vi.fn(), validateIsfDraft: vi.fn(),
}));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));

const { VersionsPanel } = await import("@/components/isf/VersionsPanel");
const { ValidateCards } = await import("@/components/isf/ValidateCards");
const REF = { caseDir: "case1", captureId: "c" };

const VERSIONS = [
  { entry_id: "e0", created: "t0", op: "create", key: null, provenance: prov(), retracted: false },
  { entry_id: "e1", created: "t1", op: "set_symbol", key: ["symbol", "init_task"], provenance: prov("probe"), retracted: false },
  { entry_id: "e2", created: "t2", op: "set_field", key: ["field", "cred", "uid"], provenance: prov("exact"), retracted: true },
];

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.getIsfDraftVersions.mockResolvedValue({ draft: "d1", versions: VERSIONS, total: 3, truncated: false });
});

describe("VersionsPanel", () => {
  it("lists operations newest first with provenance and marks retracted ones", async () => {
    render(<VersionsPanel draftRef={REF} draft="d1" rev={0} onChanged={vi.fn()} />);
    const rows = await screen.findAllByTestId("isf-version");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveAttribute("data-retracted", "true");
    expect(rows[1]).toHaveTextContent("init_task");
    expect(rows[1].querySelector("[data-tier='probe']")).not.toBeNull();
  });

  it("retracts an op only after confirmation, then asks for a refresh", async () => {
    api.retractIsfEntry.mockResolvedValue({ draft: "d1" });
    const changed = vi.fn();
    render(<VersionsPanel draftRef={REF} draft="d1" rev={0} onChanged={changed} />);
    const rows = await screen.findAllByTestId("isf-version");
    fireEvent.click(rows[1].querySelector("[data-testid='isf-retract']")!);
    expect(api.retractIsfEntry).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId("isf-retract-confirm"));
    await waitFor(() => expect(api.retractIsfEntry).toHaveBeenCalledWith(REF, "d1", "e1"));
    await waitFor(() => expect(changed).toHaveBeenCalled());
  });

  it("offers no retract for the create entry or an already retracted op", async () => {
    render(<VersionsPanel draftRef={REF} draft="d1" rev={0} onChanged={vi.fn()} />);
    const rows = await screen.findAllByTestId("isf-version");
    expect(rows[0].querySelector("[data-testid='isf-retract']")).toBeNull();
    expect(rows[2].querySelector("[data-testid='isf-retract']")).toBeNull();
  });

  it("diffs against an earlier version and shows added / removed / changed rows", async () => {
    api.diffIsfDraft.mockResolvedValue({
      draft: "d1", against: "e0", equal: false, counts: { added: 1, removed: 0, changed: 1 }, total: 5, truncated: true,
      items: [
        { key: ["symbol", "init_task"], change: "added", before: null, after: { address: "0x10" } },
        { key: ["field", "cred", "uid"], change: "changed", before: { offset: 4 }, after: { offset: 8 } },
      ] });
    render(<VersionsPanel draftRef={REF} draft="d1" rev={0} onChanged={vi.fn()} />);
    const rows = await screen.findAllByTestId("isf-version");
    fireEvent.click(rows[2].querySelector("[data-testid='isf-diff-version']")!);
    expect(await screen.findByTestId("isf-diff-summary")).toHaveTextContent("1 added, 0 removed, 1 changed");
    expect(screen.getByTestId("isf-diff-summary")).toHaveTextContent("showing 2 of 5");
    expect(screen.getAllByTestId("isf-diff-row").map((r) => r.getAttribute("data-change"))).toEqual(["added", "changed"]);
    expect(api.diffIsfDraft).toHaveBeenCalledWith(REF, "d1", { version: "e0" });
  });

  it("diffs against an ISF file path", async () => {
    api.diffIsfDraft.mockResolvedValue({ draft: "d1", against: "/x.json", equal: true, counts: { added: 0, removed: 0, changed: 0 }, total: 0, truncated: false, items: [] });
    render(<VersionsPanel draftRef={REF} draft="d1" rev={0} onChanged={vi.fn()} />);
    await screen.findAllByTestId("isf-version");
    fireEvent.change(screen.getByTestId("isf-diff-isf-path"), { target: { value: " /x.json " } });
    fireEvent.click(screen.getByTestId("isf-diff-isf"));
    await waitFor(() => expect(api.diffIsfDraft).toHaveBeenCalledWith(REF, "d1", { isf: "/x.json" }));
    expect(await screen.findByTestId("isf-diff-summary")).toHaveTextContent("Identical to /x.json");
  });
});

describe("ValidateCards", () => {
  it("renders one readiness card per plugin and retires the answer on an edit", async () => {
    api.validateIsfDraft.mockResolvedValue({
      draft: "d1", version: "v", is_valid: true, error_count: 0, warning_count: 2, errors: [], warnings: [], truncated: false,
      verdicts: { ready: 1, blocked: 1 },
      plugins: [
        { plugin: "linux.pslist", verdict: "ready", required_missing: [], optional_missing: 1, indeterminate: 0, upstream_defects: 0, reason: null },
        { plugin: "linux.lsof", verdict: "blocked", required_missing: [{}, {}], optional_missing: 0, indeterminate: 0, upstream_defects: 1, reason: "needs files_struct" },
      ] });
    const { rerender } = render(<ValidateCards draftRef={REF} draft="d1" rev={0} />);
    fireEvent.click(screen.getByTestId("isf-validate-run"));
    const cards = await screen.findAllByTestId("isf-readiness-card");
    expect(cards.map((c) => c.getAttribute("data-verdict"))).toEqual(["ready", "blocked"]);
    expect(cards[1]).toHaveTextContent("2 required");
    expect(cards[1]).toHaveTextContent("needs files_struct");
    expect(screen.getByTestId("isf-validate-summary")).toHaveTextContent("0 errors, 2 warnings");
    rerender(<ValidateCards draftRef={REF} draft="d1" rev={1} />);
    expect(screen.queryByTestId("isf-readiness")).toBeNull();
  });

  it("shows a refused validation as an error", async () => {
    api.validateIsfDraft.mockRejectedValue(new Error("pakunoda missing"));
    render(<ValidateCards draftRef={REF} draft="d1" rev={0} />);
    fireEvent.click(screen.getByTestId("isf-validate-run"));
    expect(await screen.findByTestId("isf-validate-error")).toHaveTextContent("pakunoda missing");
  });
});
