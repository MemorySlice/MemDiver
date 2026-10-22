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

/**
 * The view switch follows the views the BACKEND detected (`availableViews`
 * from the `/hex-raw` probe), not the `.msl` extension: a gcore core is "raw"
 * by extension but has distinct raw and vas views.
 */
describe("HexToolbar view switch", () => {
  function switchTabs(): string[] {
    return screen.queryAllByRole("tab").map((el) => el.textContent ?? "");
  }

  it("offers raw + vas for a gcore core classified raw by extension", () => {
    useHexStore.setState({
      dumpPath: "/dumps/planted.core",
      format: "raw",
      viewMode: "raw",
      availableViews: ["raw", "vas"],
      detectedFormat: "gcore",
    });
    render(<HexToolbar />);
    expect(switchTabs()).toEqual(["Raw file", "Memory (VAS)"]);
    expect(screen.getByRole("tablist", { name: "Dump view mode" })).toBeInTheDocument();
  });

  it("shows no switch for a flat raw dump", () => {
    useHexStore.setState({
      dumpPath: "/dumps/flat.dump",
      format: "raw",
      viewMode: "raw",
      availableViews: ["raw"],
      detectedFormat: "raw",
    });
    render(<HexToolbar />);
    expect(switchTabs()).toEqual([]);
  });

  it("shows no switch for an unprobed non-msl dump", () => {
    useHexStore.setState({
      dumpPath: "/dumps/flat.dump",
      format: "raw",
      availableViews: [],
    });
    render(<HexToolbar />);
    expect(switchTabs()).toEqual([]);
  });

  it("keeps all three .msl views before the probe answers", () => {
    useHexStore.setState({ availableViews: [] });
    render(<HexToolbar />);
    expect(switchTabs()).toEqual(["Raw file", "Memory (VAS)", "VA"]);
    expect(screen.getByRole("tablist", { name: "MSL view mode" })).toBeInTheDocument();
  });
});
