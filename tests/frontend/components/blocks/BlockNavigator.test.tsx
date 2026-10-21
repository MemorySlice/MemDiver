import { describe, it, expect, vi, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import "@/i18n";
import { BlockNavigator } from "@/components/blocks/BlockNavigator";

const GROUPS = [
  {
    category: "Memory",
    blocks: [
      { label: "region-a", block_type: 1, offset: 0x10, size: 4, detail: "" },
      { label: "region-b", block_type: 1, offset: 0x20, size: 8, detail: "" },
    ],
  },
  { category: "Modules", blocks: [{ label: "libc", block_type: 2, offset: 0x30, size: 2, detail: "" }] },
];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("BlockNavigator", () => {
  it("derives the block total from the fetched groups", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(GROUPS))));
    render(<BlockNavigator mslPath="/x.msl" />);
    expect(await screen.findByText("3 blocks total")).toBeInTheDocument();
  });

  it("toggles a category open and closed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(GROUPS))));
    const onBlockClick = vi.fn();
    render(<BlockNavigator mslPath="/x.msl" onBlockClick={onBlockClick} />);
    fireEvent.click(await screen.findByText("Memory"));
    fireEvent.click(screen.getByText("region-b"));
    expect(onBlockClick).toHaveBeenCalledWith(0x20);
    fireEvent.click(screen.getByText("Memory"));
    expect(screen.queryByText("region-b")).not.toBeInTheDocument();
  });

  it("shows the fetch error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 500 })));
    render(<BlockNavigator mslPath="/x.msl" />);
    expect(await screen.findByText("Error: HTTP 500")).toBeInTheDocument();
  });
});
