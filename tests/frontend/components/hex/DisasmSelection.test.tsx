import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { DisasmResult } from "@/api/disasm";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

const api = vi.hoisted(() => ({ disassemble: vi.fn() }));
vi.mock("@/api/disasm", () => api);

const { DisasmSelection } = await import("@/components/hex/DisasmSelection");

const RESULT: DisasmResult = {
  dump_path: "/d.raw", arch: "x86_64", space: "file_offset", address: "0x10", length: 4,
  rows: [
    { addr: "0x10", bytes: "55", mnemonic: "push", op_str: "rbp", size: 1 },
    { addr: "0x11", bytes: "ff", mnemonic: ".byte", op_str: "0xff", size: 1, stop_reason: "undecodable" },
  ],
  row_count: 2, max_insns: 2000, truncated: true,
  stops: [{ addr: "0x11", offset: 1, stop_reason: "undecodable" }],
  coverage: { requested: 4, captured: 2, complete: false, gaps: [{ start: 0x12, length: 2, reason: "not_captured" }] },
};

beforeEach(() => {
  api.disassemble.mockReset();
  api.disassemble.mockResolvedValue(RESULT);
  useDumpStore.getState().clearAll();
  useAppStore.setState({ inputMode: "file", inputPath: "/d.raw" });
  useHexStore.setState({ viewMode: "raw", availableViews: ["raw"], selection: { anchor: 0x10, active: 0x13 } });
});

describe("DisasmSelection", () => {
  it("renders nothing without a selection", () => {
    useHexStore.setState({ selection: null });
    const { container } = render(<DisasmSelection />);
    expect(container).toBeEmptyDOMElement();
  });

  it("disassembles the selection of a flat file at its file offset", async () => {
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    await waitFor(() => expect(api.disassemble).toHaveBeenCalledWith("/d.raw", 0x10n, 4, { arch: "auto" }));
    const rows = await screen.findAllByTestId("disasm-row");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("push");
    expect(rows[0]).toHaveTextContent("rbp");
  });

  it("makes gaps, undecodable stops and truncation explicit", async () => {
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    expect(await screen.findByTestId("disasm-gaps")).toHaveTextContent("Gap at 0x12, 2 bytes: not_captured");
    expect(screen.getByTestId("disasm-stops")).toHaveTextContent("1 undecodable positions, first at 0x11");
    expect(screen.getByTestId("disasm-truncated")).toHaveTextContent("2000");
    expect(screen.getByTestId("disasm-summary")).toHaveTextContent("2 of 4 bytes captured");
    expect(screen.getAllByTestId("disasm-row")[1]).toHaveAttribute("data-stop", "undecodable");
  });

  it("says when only part of a huge selection was decoded", async () => {
    useHexStore.setState({ selection: { anchor: 0, active: 99999 } });
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    await waitFor(() => expect(api.disassemble).toHaveBeenCalledWith("/d.raw", 0n, 65536, { arch: "auto" }));
    expect(await screen.findByTestId("disasm-capped")).toHaveTextContent("first 65536 of 100000");
  });

  it("re-runs with the chosen architecture", async () => {
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    await screen.findAllByTestId("disasm-row");
    fireEvent.change(screen.getByTestId("disasm-arch"), { target: { value: "aarch64" } });
    await waitFor(() => expect(api.disassemble).toHaveBeenLastCalledWith("/d.raw", 0x10n, 4, { arch: "aarch64" }));
  });

  it("explains a refused address instead of sending one", async () => {
    useHexStore.setState({ viewMode: "raw", availableViews: ["raw", "va"] });
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    expect(await screen.findByTestId("disasm-error")).toHaveTextContent("raw view");
    expect(api.disassemble).not.toHaveBeenCalled();
  });

  it("shows a backend failure as text", async () => {
    api.disassemble.mockRejectedValue(new Error("disasm needs capstone"));
    render(<DisasmSelection />);
    fireEvent.click(screen.getByTestId("disasm-open"));
    expect(await screen.findByTestId("disasm-error")).toHaveTextContent("capstone");
  });
});
