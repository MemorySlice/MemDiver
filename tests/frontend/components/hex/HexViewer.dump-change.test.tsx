import { beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useHexStore } from "@/stores/hex-store";
import { stubVirtualizerLayout } from "@tests/helpers/virtualizer";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
  getPageStates: vi.fn(() => new Promise(() => {})),
  fetchChunkData: vi.fn(() => new Promise(() => {})),
}));

const { HexViewer } = await import("@/components/hex/HexViewer");

const scroller = (c: HTMLElement) =>
  c.querySelector<HTMLDivElement>("div.flex-1.overflow-auto") as HTMLDivElement;

describe("HexViewer dump change", () => {
  beforeEach(() => {
    stubVirtualizerLayout?.();
    useHexStore.setState({ dumpPath: null });
  });

  it("resets the scroll position when the dump changes, not when it stays", () => {
    const { container, rerender } = render(<HexViewer dumpPath="/a.dump" fileSize={1 << 20} />);
    const el = scroller(container);
    el.scrollTop = 400;
    rerender(<HexViewer dumpPath="/a.dump" fileSize={1 << 20} />);
    expect(el.scrollTop).toBe(400);
    rerender(<HexViewer dumpPath="/b.dump" fileSize={1 << 20} />);
    expect(el.scrollTop).toBe(0);
  });
});
