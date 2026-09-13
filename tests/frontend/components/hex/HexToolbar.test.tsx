import { beforeEach, describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useHexStore } from "@/stores/hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { HexToolbar } = await import("@/components/hex/HexToolbar");

/**
 * The file-name label is the only thing in the workspace that says WHICH dump
 * the bytes belong to, and it matters more once several panes are open.
 *
 * It was measured at ZERO pixels wide at the default viewport — in the
 * single-dump viewer too: the view-mode tabs (~201px), the go-to box (~132px)
 * and the find box (~209px) are all `shrink-0` and together take 542px of a
 * 572px toolbar, so the one flexible item absorbed the whole deficit. These
 * tests pin the two properties that stop it happening again: a width floor on
 * the label, and a toolbar that wraps rather than squeezing it.
 */
function label(): HTMLElement {
  return screen.getByTitle("/dumps/run_1.msl");
}

beforeEach(() => {
  useHexStore.setState({
    dumpPath: "/dumps/run_1.msl",
    fileSize: 8192,
    format: "msl",
    viewMode: "vas",
  });
});

describe("HexToolbar file-name label", () => {
  it("names the dump on screen", () => {
    render(<HexToolbar />);
    expect(label()).toHaveTextContent("run_1.msl");
  });

  it("keeps a width floor so it can never be squeezed to nothing", () => {
    render(<HexToolbar />);
    expect(label()).toHaveClass("min-w-[9rem]");
    // Still flexible, and still truncating a long name gracefully.
    expect(label()).toHaveClass("flex-1");
    expect(label()).toHaveClass("truncate");
  });

  it("lets the toolbar wrap instead of eating the label", () => {
    render(<HexToolbar />);
    expect(label().parentElement).toHaveClass("flex-wrap");
  });
});
