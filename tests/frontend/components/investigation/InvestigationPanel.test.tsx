import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
}));
vi.mock("@/stores/dump-store", () => ({
  useDumpStore: (sel: (s: unknown) => unknown) =>
    sel({ getKeyMaterialByPath: () => undefined }),
}));

import { InvestigationPanel } from "@/components/investigation/InvestigationPanel";

describe("InvestigationPanel", () => {
  beforeEach(() => {
    getEntropy.mockReset();
    readHex.mockReset();
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
});
