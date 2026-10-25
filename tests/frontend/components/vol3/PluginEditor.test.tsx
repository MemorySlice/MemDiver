import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { Vol3CheckOutcome } from "@/api/vol3";

const api = vi.hoisted(() => ({
  scaffoldVol3Plugin: vi.fn(), checkVol3Source: vi.fn(), listVol3Sources: vi.fn(),
  getVol3Source: vi.fn(), putVol3Source: vi.fn(), listVol3Fixtures: vi.fn(),
  putVol3Fixture: vi.fn(), runVol3Fixture: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const { PluginEditor } = await import("@/components/vol3/PluginEditor");

const VIEW = "/case/proc.mdview";
const CASE = "/case";
const SOURCE = "line one\nline two\nline three";
const GOOD: Vol3CheckOutcome = {
  ok: true,
  plugin: { name: "MyPlugin", description: "", version: "1.2.3", satisfied_by_context: [],
    requirements: [{ name: "pid", type: "array", requirement: "ListRequirement", description: "", optional: true, default: null }] },
};
const BAD: Vol3CheckOutcome = {
  ok: false,
  error: { type: "SyntaxError", message: "invalid syntax", line: 2, offset: 3, text: "line two", code: null },
};

const onRun = vi.fn();
function mount(props: Partial<{ viewPath: string; caseDir: string }> = {}) {
  return render(<PluginEditor viewPath={VIEW} caseDir={CASE} running={false} onRun={onRun} {...props} />);
}
const textarea = () => screen.getByTestId("editor-textarea") as HTMLTextAreaElement;
const type = (value: string) => fireEvent.change(textarea(), { target: { value } });

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  onRun.mockReset();
  api.listVol3Sources.mockResolvedValue({ sources: [], count: 0 });
  api.listVol3Fixtures.mockResolvedValue({ fixtures: [], count: 0 });
});

describe("PluginEditor source area", () => {
  it("numbers every line in the gutter", () => {
    mount();
    type(SOURCE);
    const lines = screen.getAllByTestId("gutter-line");
    expect(lines.map((l) => l.textContent)).toEqual(["1", "2", "3"]);
  });

  it("inserts four spaces on Tab", () => {
    mount();
    type("ab");
    textarea().setSelectionRange(1, 1);
    fireEvent.keyDown(textarea(), { key: "Tab" });
    expect(textarea().value).toBe("a    b");
  });

  it("shows the unsandboxed warning", () => {
    mount();
    expect(screen.getByTestId("editor-warning")).toHaveTextContent(/unsandboxed/i);
  });

  it("fills the textarea from a scaffold", async () => {
    api.scaffoldVol3Plugin.mockResolvedValue({ class_name: "Demo", os_family: "linux", per_process: false, source: "class Demo:\n    pass", line_count: 2 });
    mount();
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "demo" } });
    fireEvent.click(screen.getByTestId("editor-per-process"));
    fireEvent.click(screen.getByTestId("editor-scaffold"));
    await waitFor(() => expect(textarea().value).toBe("class Demo:\n    pass"));
    expect(api.scaffoldVol3Plugin).toHaveBeenCalledWith("demo", false);
  });

  it("loads a stored source and flags an external edit", async () => {
    api.listVol3Sources.mockResolvedValue({ sources: [{ name: "stored", version: 2 }], count: 1 });
    api.getVol3Source.mockResolvedValue({ name: "stored", source: "x = 1", modified_externally: true, version: 2 });
    mount();
    const select = await screen.findByTestId("editor-load");
    await waitFor(() => expect(select).not.toBeDisabled());
    fireEvent.change(select, { target: { value: "stored" } });
    await waitFor(() => expect(textarea().value).toBe("x = 1"));
    expect(screen.getByTestId("external-edit-notice")).toBeInTheDocument();
    expect((screen.getByTestId("editor-name") as HTMLInputElement).value).toBe("stored");
  });
});

describe("PluginEditor save / check / run", () => {
  it("saves with PUT and shows the error line in the gutter", async () => {
    api.putVol3Source.mockResolvedValue({ stored: { name: "p", version: 1 }, check: BAD });
    mount();
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "p" } });
    type(SOURCE);
    fireEvent.click(screen.getByTestId("editor-save"));
    await screen.findByTestId("check-error");
    expect(api.putVol3Source).toHaveBeenCalledWith(CASE, "p", SOURCE, VIEW);
    const marked = screen.getAllByTestId("gutter-line").filter((l) => l.dataset.error === "true");
    expect(marked).toHaveLength(1);
    expect(marked[0]).toHaveTextContent("2");
    expect(screen.getByTestId("check-error")).toHaveTextContent("invalid syntax");
  });

  it("shows plugin name, version and requirements after a good save", async () => {
    api.putVol3Source.mockResolvedValue({ stored: { name: "p", version: 1 }, check: GOOD });
    mount();
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "p" } });
    type("ok");
    fireEvent.click(screen.getByTestId("editor-save"));
    const ok = await screen.findByTestId("check-ok");
    expect(ok).toHaveTextContent("MyPlugin");
    expect(ok).toHaveTextContent("1.2.3");
    expect(within(ok).getByTestId("check-requirements")).toHaveTextContent("pid");
  });

  it("check lists requirements the active view leaves unsatisfied", async () => {
    api.checkVol3Source.mockResolvedValue({ ...GOOD, view_path: VIEW, satisfied: false,
      unsatisfied: [{ name: "kernel", requirement: "ModuleRequirement", reason: "no symbols" }] });
    mount();
    type("ok");
    fireEvent.click(screen.getByTestId("editor-check"));
    const list = await screen.findByTestId("check-unsatisfied");
    expect(list).toHaveTextContent("kernel");
    expect(api.checkVol3Source).toHaveBeenCalledWith({ source: "ok", view_path: VIEW });
  });

  it("runs the stored name after a save, but raw text once edited again", async () => {
    api.putVol3Source.mockResolvedValue({ stored: { name: "p", version: 1 }, check: GOOD });
    mount();
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "p" } });
    type("v1");
    fireEvent.click(screen.getByTestId("editor-run"));
    expect(onRun).toHaveBeenLastCalledWith({ view_path: VIEW, source: "v1", case_dir: CASE });
    fireEvent.click(screen.getByTestId("editor-save"));
    await screen.findByTestId("check-ok");
    fireEvent.click(screen.getByTestId("editor-run"));
    expect(onRun).toHaveBeenLastCalledWith({ view_path: VIEW, source_name: "p", case_dir: CASE });
    type("v2");
    fireEvent.click(screen.getByTestId("editor-run"));
    expect(onRun).toHaveBeenLastCalledWith({ view_path: VIEW, source: "v2", case_dir: CASE });
  });

  it("disables save without a case and run without a view", () => {
    mount({ caseDir: "", viewPath: "" });
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "p" } });
    type("ok");
    expect(screen.getByTestId("editor-save")).toBeDisabled();
    expect(screen.getByTestId("editor-run")).toBeDisabled();
    expect(screen.getByTestId("editor-needs-case")).toBeInTheDocument();
    expect(screen.getByTestId("editor-needs-view")).toBeInTheDocument();
    expect(screen.getByTestId("fixtures-needs-case")).toBeInTheDocument();
    expect(api.listVol3Fixtures).not.toHaveBeenCalled();
  });
});

describe("PluginEditor fixtures", () => {
  const fixture = (name: string) => ({ name, plugin: "", source_name: "p", view_path: VIEW, args: {}, expect: [{ min_rows: 1 }] });

  async function saved() {
    api.putVol3Source.mockResolvedValue({ stored: { name: "p", version: 1 }, check: GOOD });
    fireEvent.change(screen.getByTestId("editor-name"), { target: { value: "p" } });
    type("ok");
    fireEvent.click(screen.getByTestId("editor-save"));
    await screen.findByTestId("check-ok");
  }

  it("creates a fixture for the saved plugin", async () => {
    api.putVol3Fixture.mockResolvedValue(fixture("f1"));
    mount();
    expect(screen.getByTestId("fixture-create")).toBeDisabled();
    await saved();
    fireEvent.change(screen.getByTestId("fixture-name"), { target: { value: "f1" } });
    fireEvent.change(screen.getByTestId("fixture-kind"), { target: { value: "row_where" } });
    fireEvent.change(screen.getByTestId("fixture-column"), { target: { value: "COMM" } });
    fireEvent.change(screen.getByTestId("fixture-value"), { target: { value: "sshd" } });
    fireEvent.change(screen.getByTestId("fixture-count"), { target: { value: "2" } });
    fireEvent.click(screen.getByTestId("fixture-create"));
    await waitFor(() => expect(api.putVol3Fixture).toHaveBeenCalledWith(CASE, "f1", {
      view_path: VIEW, source_name: "p",
      expect: [{ row_where: { COMM: "sshd" }, count_at_least: 2 }] }));
    expect(api.listVol3Fixtures).toHaveBeenCalledTimes(2);
  });

  it("builds column_all with a numeric value", async () => {
    api.putVol3Fixture.mockResolvedValue(fixture("f2"));
    mount();
    await saved();
    fireEvent.change(screen.getByTestId("fixture-name"), { target: { value: "f2" } });
    fireEvent.change(screen.getByTestId("fixture-kind"), { target: { value: "column_all" } });
    fireEvent.change(screen.getByTestId("fixture-column"), { target: { value: "PID" } });
    fireEvent.change(screen.getByTestId("fixture-op"), { target: { value: ">=" } });
    fireEvent.change(screen.getByTestId("fixture-value"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("fixture-create"));
    await waitFor(() => expect(api.putVol3Fixture.mock.calls[0][2].expect)
      .toEqual([{ column_all: { column: "PID", op: ">=", value: 0 } }]));
  });

  it("rejects a bad count without calling the backend", async () => {
    mount();
    await saved();
    fireEvent.change(screen.getByTestId("fixture-name"), { target: { value: "f" } });
    fireEvent.change(screen.getByTestId("fixture-count"), { target: { value: "-1" } });
    fireEvent.click(screen.getByTestId("fixture-create"));
    expect(await screen.findByTestId("fixtures-error")).toBeInTheDocument();
    expect(api.putVol3Fixture).not.toHaveBeenCalled();
  });

  it.each([
    ["pass", "Pass"], ["fail", "Fail"], ["indeterminate", "Indeterminate"],
  ] as const)("renders a %s verdict badge with text and per-predicate details", async (verdict, word) => {
    api.listVol3Fixtures.mockResolvedValue({ fixtures: [fixture("f")], count: 1 });
    api.runVol3Fixture.mockResolvedValue({
      fixture: "f", verdict, reason: verdict === "indeterminate" ? "run stopped early: timeout" : null,
      predicates: verdict === "indeterminate" ? [] : [{ ok: verdict === "pass", detail: "3 rows, need min 1" }],
      row_count: 3, truncated: false, recorded: true });
    mount();
    const item = await screen.findByTestId("fixture-item");
    expect(within(item).getByTestId("fixture-not-run")).toBeInTheDocument();
    fireEvent.click(within(item).getByTestId("fixture-run"));
    const badge = await within(item).findByTestId("verdict-badge");
    expect(badge).toHaveAttribute("data-verdict", verdict);
    expect(badge).toHaveTextContent(word);
    expect(api.runVol3Fixture).toHaveBeenCalledWith(CASE, "f", VIEW);
    const details = within(item).getByTestId("fixture-details");
    if (verdict === "indeterminate") expect(details).toHaveTextContent("timeout");
    else expect(within(details).getByTestId("fixture-predicate")).toHaveAttribute("data-ok", String(verdict === "pass"));
  });
});
