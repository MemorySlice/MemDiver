import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@/i18n";

import { ToolCallCard } from "@/components/agent/ToolCallCard";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

const base = { kind: "tool" as const, id: "t", name: "scan_dump", input: { q: "x" }, access: "read" };

describe("ToolCallCard", () => {
  beforeEach(() => {
    useDumpStore.setState({ dumps: [{ id: "d1", path: "/open.raw", name: "open.raw", size: 1, format: "raw", sameProcess: false }], activeDumpId: null });
  });

  it("shows access, result summary, bytes and truncated, with collapsible input", () => {
    render(<ToolCallCard item={{ ...base, result: { ok: true, summary: "3 hits", bytes: 99, truncated: true, locations: [] } }} />);
    expect(screen.getByTestId("tool-access")).toHaveTextContent("read");
    expect(screen.getByText("3 hits")).toBeInTheDocument();
    expect(screen.getByText("99 bytes")).toBeInTheDocument();
    expect(screen.getByTestId("tool-truncated")).toBeInTheDocument();
    expect(screen.queryByText(/"q"/)).toBeNull();
    fireEvent.click(screen.getByText("Show input"));
    expect(screen.getByText(/"q": "x"/)).toBeInTheDocument();
  });

  it("opens an open dump in hex and disables the button for a closed one", () => {
    const scroll: number[] = [];
    useHexStore.setState({ scrollToOffset: (o: number) => { scroll.push(o); } } as never);
    render(<ToolCallCard item={{ ...base, access: "write", result: { ok: true, summary: "s", bytes: 1, truncated: false,
      locations: [{ dump_path: "/open.raw", offset: 64 }, { dump_path: "/closed.raw", offset: 1 }] } }} />);
    const buttons = screen.getAllByText("Open in hex");
    expect(buttons[1]).toBeDisabled();
    expect(buttons[1]).toHaveAttribute("title", "That dump is not open in the workspace.");
    fireEvent.click(buttons[0]);
    expect(useDumpStore.getState().activeDumpId).toBe("d1");
    expect(scroll).toEqual([64]);
  });
});
