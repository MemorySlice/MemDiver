import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

// InvestigationPanel fires two client calls on mount; stub both so the render
// path is exercised without a backend.
const getEntropy = vi.fn();
const readHex = vi.fn();
vi.mock("@/api/client", () => ({
  getEntropy: (...a: unknown[]) => getEntropy(...a),
  readHex: (...a: unknown[]) => readHex(...a),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/stores/dump-store", () => {
  const state = { getKeyMaterialByPath: () => undefined };
  const useDumpStore = (sel: (s: unknown) => unknown) => sel(state);
  useDumpStore.getState = () => state;
  return { useDumpStore };
});

import { InvestigationPanel } from "@/components/investigation/InvestigationPanel";
import { firstByteOfHexLines } from "@/hooks/useCursorInspection";
import { useHexStore } from "@/stores/hex-store";

describe("InvestigationPanel", () => {
  beforeEach(() => {
    getEntropy.mockReset();
    readHex.mockReset();
    localStorage.clear();
    useHexStore.getState().reset();
    useHexStore.setState({ viewMode: "raw" });
  });

  // Regression: near EOF the backend returns an error envelope with NO
  // `overall_entropy`. Before the fix the panel called (undefined).toFixed()
  // and threw, which the workspace ErrorBoundary caught by unmounting the whole
  // hex viewer (a "blank"/crash). It must degrade gracefully instead.
  it("does not crash when entropy is unavailable near EOF", async () => {
    readHex.mockResolvedValue({ hex_lines: ["00000000  ab"] });
    getEntropy.mockResolvedValue({
      error: "offset out of range",
      offset: 100,
      file_size: 90,
    });

    render(<InvestigationPanel dumpPath="/x" offset={100} />);

    // Byte value still renders → the panel mounted and survived the async
    // entropy resolution without throwing.
    await waitFor(() =>
      expect(screen.getByText(/0xab/i)).toBeInTheDocument(),
    );
    // Entropy bar is omitted (no value to show) rather than crashing.
    expect(screen.queryByText(/7\.\d\d/)).not.toBeInTheDocument();
  });

  it("renders the entropy value when the backend returns one", async () => {
    readHex.mockResolvedValue({ hex_lines: ["00000000  ab"] });
    getEntropy.mockResolvedValue({
      overall_entropy: 7.5,
      high_entropy_regions: [],
      profile_sample: [],
      stats: { min: 0, max: 0, mean: 0 },
    });

    render(<InvestigationPanel dumpPath="/x" offset={0} />);

    await waitFor(() => expect(screen.getByText(/7\.50/)).toBeInTheDocument());
  });

  // The cursor addresses the hex viewer's CURRENT view. Reading it in the
  // backend's default ("raw") made the panel describe the container byte at
  // the same number: on a gcore at VAS 0x1100 it showed 0x33, not 0x73.
  describe("view consistency", () => {
    beforeEach(() => {
      getEntropy.mockResolvedValue({ overall_entropy: 1 });
      useHexStore.getState().setDumpPath("/core", 8320, "raw");
      useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    });

    it("reads the byte in the viewer's current (data-driven) view", async () => {
      useHexStore.getState().showView("vas"); // not persisted
      readHex.mockResolvedValue({ hex_lines: ["00001100  73"] });
      render(<InvestigationPanel dumpPath="/core" offset={0x1100} />);
      await waitFor(() => expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x73"));
      expect(readHex).toHaveBeenCalledWith("/core", 0x1100, 1, undefined, { view: "vas" });
      // Local entropy: the 256-byte window around the cursor, same view.
      expect(getEntropy).toHaveBeenCalledWith("/core", 0x1100 - 128, 256, undefined, { view: "vas" });
      expect(screen.getByText(/VAS offset 0x00001100/)).toBeInTheDocument();
    });

    it("reads in raw when the viewer shows raw", async () => {
      readHex.mockResolvedValue({ hex_lines: ["000001b0  73"] });
      render(<InvestigationPanel dumpPath="/core" offset={0x1b0} />);
      await waitFor(() => expect(readHex).toHaveBeenCalled());
      expect(readHex).toHaveBeenCalledWith("/core", 0x1b0, 1, undefined, { view: "raw" });
    });

    it("refetches when the view changes under an unchanged offset", async () => {
      readHex.mockResolvedValueOnce({ hex_lines: ["00001100  33"] });
      render(<InvestigationPanel dumpPath="/core" offset={0x1100} />);
      await waitFor(() => expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x33"));

      readHex.mockResolvedValueOnce({ hex_lines: ["00001100  73"] });
      act(() => {
        useHexStore.getState().showView("vas");
      });
      await waitFor(() => expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x73"));
      expect(readHex).toHaveBeenLastCalledWith("/core", 0x1100, 1, undefined, { view: "vas" });
      expect(readHex).toHaveBeenCalledTimes(2);
      expect(getEntropy).toHaveBeenLastCalledWith("/core", 0x1100 - 128, 256, undefined, { view: "vas" });
    });

    it("ignores a late answer for the previous view", async () => {
      let resolveRaw: (v: unknown) => void = () => {};
      readHex.mockImplementationOnce(() => new Promise((r) => { resolveRaw = r; }));
      readHex.mockResolvedValueOnce({ hex_lines: ["00001100  73"] });
      render(<InvestigationPanel dumpPath="/core" offset={0x1100} />);
      act(() => {
        useHexStore.getState().showView("vas");
      });
      await waitFor(() => expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x73"));
      await act(async () => {
        resolveRaw({ hex_lines: ["00001100  33"] });
      });
      expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x73");
    });

    it("passes the va-relative offset through and shows the absolute VA", async () => {
      useHexStore.getState().setDumpPath("/x.msl", 0x10000, "msl");
      useHexStore.getState().setAvailableViews(["raw", "vas", "va"], "msl");
      useHexStore.getState().showView("va");
      useHexStore.setState({ pageStatesLoaded: true, vaSpanStart: 0x7f0000000000 });
      readHex.mockResolvedValue({ hex_lines: ["00000010  41"] });
      render(<InvestigationPanel dumpPath="/x.msl" offset={0x10} />);
      await waitFor(() => expect(screen.getByTestId("investigation-byte-hex")).toHaveTextContent("0x41"));
      expect(readHex).toHaveBeenCalledWith("/x.msl", 0x10, 1, undefined, { view: "va" });
      expect(getEntropy).toHaveBeenCalledWith("/x.msl", 0, 256, undefined, { view: "va" });
      expect(screen.getByTestId("investigation-va")).toHaveTextContent("0x7f0000000010");
    });
  });

  it("parses the first byte of a hex line", () => {
    expect(firstByteOfHexLines(["00000000  ab cd"])).toBe(0xab);
    expect(firstByteOfHexLines([])).toBeNull();
    expect(firstByteOfHexLines(["00000000"])).toBeNull();
  });
});
