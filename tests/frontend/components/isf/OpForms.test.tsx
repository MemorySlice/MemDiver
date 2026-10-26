import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useHexStore } from "@/stores/hex-store";

const api = vi.hoisted(() => ({ setIsfDraft: vi.fn() }));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));

const { OpForms } = await import("@/components/isf/OpForms");
const REF = { caseDir: "case1", captureId: "c" };
const type = (id: string, value: string) => fireEvent.change(screen.getByTestId(id), { target: { value } });

beforeEach(() => {
  api.setIsfDraft.mockReset();
  api.setIsfDraft.mockResolvedValue({ draft: "d1", op: "field", entry: { entry_id: "e" } });
  useHexStore.setState({
    viewMode: "va", availableViews: ["raw", "va"], vaSpanStart: 0x400000,
    selection: { anchor: 0x40, active: 0x47 },
  });
});

describe("OpForms", () => {
  it("prefills a field offset as selection address minus struct base", async () => {
    const applied = vi.fn();
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={applied} />);
    fireEvent.click(screen.getByTestId("isf-op-field"));
    type("isf-form-struct", "task_struct");
    type("isf-form-field", "pid");
    type("isf-form-base", "0x400000");
    fireEvent.click(screen.getByTestId("isf-from-selection-offset"));
    await waitFor(() => expect(screen.getByTestId("isf-form-offset")).toHaveValue(64));
    expect(screen.getByTestId("prov-evidence")).toHaveValue("hex selection 0x400040 minus struct base 0x400000");
    fireEvent.change(screen.getByTestId("isf-field-type-name"), { target: { value: "int" } });
    type("prov-source", "hand analysis");
    type("prov-tier", "exact");
    fireEvent.click(screen.getByTestId("isf-form-submit"));
    await waitFor(() => expect(api.setIsfDraft).toHaveBeenCalledWith(REF, "d1", {
      op: "field",
      args: { struct: "task_struct", field: "pid", offset: 64, type: { kind: "base", name: "int" } },
      provenance: { source: "hand analysis", tier: "exact", evidence: ["hex selection 0x400040 minus struct base 0x400000"], author: "human" },
    }));
    await waitFor(() => expect(applied).toHaveBeenCalled());
  });

  it("asks for a struct base before computing an offset", async () => {
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-op-field"));
    fireEvent.click(screen.getByTestId("isf-from-selection-offset"));
    expect(await screen.findByTestId("isf-form-error")).toHaveTextContent("struct base");
    expect(screen.getByTestId("isf-form-offset")).toHaveValue(null);
  });

  it("refuses when the selection lies below the struct base", async () => {
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-op-field"));
    type("isf-form-base", "0x500000");
    fireEvent.click(screen.getByTestId("isf-from-selection-offset"));
    expect(await screen.findByTestId("isf-form-error")).toHaveTextContent("below");
  });

  it("prefills a symbol address from the selection and records it as evidence", async () => {
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-from-selection-address"));
    await waitFor(() => expect(screen.getByTestId("isf-form-address")).toHaveValue("0x400040"));
    expect(screen.getByTestId("prov-evidence")).toHaveValue("hex selection 0x400040");
  });

  it("tells the analyst when there is nothing selected or the view cannot be addressed", async () => {
    useHexStore.setState({ selection: null });
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-from-selection-address"));
    expect(await screen.findByTestId("isf-form-error")).toHaveTextContent("Select bytes");
    useHexStore.setState({ selection: { anchor: 1, active: 1 }, viewMode: "raw" });
    fireEvent.click(screen.getByTestId("isf-from-selection-address"));
    await waitFor(() => expect(screen.getByTestId("isf-form-error")).toHaveTextContent("raw view"));
  });

  it("refuses a rounded kernel-scale span start instead of computing a wrong address", async () => {
    useHexStore.setState({ vaSpanStart: 1.8446744073709552e19 });
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-from-selection-address"));
    expect(await screen.findByTestId("isf-form-error")).toHaveTextContent("vas view");
    expect(screen.getByTestId("isf-form-address")).toHaveValue("");
  });

  it("builds a nested pointer-to-array type descriptor for a symbol", async () => {
    api.setIsfDraft.mockResolvedValue({ draft: "d1", op: "symbol", entry: { entry_id: "e" } });
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    type("isf-form-name", "init_task");
    type("isf-form-address", "0xffffffff81c0a000");
    fireEvent.click(screen.getByTestId("isf-symbol-typed"));
    fireEvent.change(screen.getByTestId("isf-symbol-type-kind"), { target: { value: "pointer" } });
    fireEvent.change(screen.getByTestId("isf-symbol-type-sub-kind"), { target: { value: "array" } });
    fireEvent.change(screen.getByTestId("isf-symbol-type-sub-count"), { target: { value: "4" } });
    fireEvent.click(screen.getByTestId("isf-form-submit"));
    await waitFor(() => expect(api.setIsfDraft).toHaveBeenCalled());
    expect(api.setIsfDraft.mock.calls[0][2].args).toEqual({
      name: "init_task", address: "0xffffffff81c0a000",
      type: { kind: "pointer", subtype: { kind: "array", count: 4, subtype: { kind: "base", name: "unsigned char" } } },
    });
  });

  it("will not submit an incomplete field", async () => {
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    fireEvent.click(screen.getByTestId("isf-op-field"));
    fireEvent.click(screen.getByTestId("isf-form-submit"));
    expect(await screen.findByTestId("isf-form-error")).toBeInTheDocument();
    expect(api.setIsfDraft).not.toHaveBeenCalled();
  });

  it("pre-fills the form an entry's Edit button points at", () => {
    render(<OpForms draftRef={REF} draft="d1" focus={{ op: "field", name: "cred", field: "uid", nonce: 1 }} onApplied={vi.fn()} />);
    expect(screen.getByTestId("isf-form-struct")).toHaveValue("cred");
    expect(screen.getByTestId("isf-form-field")).toHaveValue("uid");
  });

  it("resets Name/Size when switching op tabs", () => {
    render(<OpForms draftRef={REF} draft="d1" focus={null} onApplied={vi.fn()} />);
    type("isf-form-name", "task_struct");
    fireEvent.click(screen.getByTestId("isf-op-struct"));
    expect(screen.getByTestId("isf-form-name")).toHaveValue("");
    type("isf-form-name", "u32");
    type("isf-form-size", "4");
    fireEvent.click(screen.getByTestId("isf-op-base_type"));
    expect(screen.getByTestId("isf-form-name")).toHaveValue("");
    expect(screen.getByTestId("isf-form-size")).toHaveValue(null);
  });
});
