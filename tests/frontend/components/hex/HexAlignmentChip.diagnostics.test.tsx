import { afterEach, describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { CLASSIFICATION_BASIS_MIXED } from "@/api/diagnostics";
import { HexAlignmentChip } from "@/components/hex/HexAlignmentChip";
import { useMultiHexStore } from "@/stores/multi-hex-store";

const MIXED_MESSAGE = "BACKEND: classification basis mixed";

const ALIGNED: AlignedWindowAlignment = {
  method: "virtual_address",
  bytes_compared: 4096,
  bytes_discarded: 0,
  sizes_differed: false,
  n_sources: 3,
  warnings: [],
};

afterEach(() => {
  useMultiHexStore.setState({ alignment: null });
});

describe("HexAlignmentChip classification-basis warning", () => {
  it("renders the banner from the aligned-window alignment diagnostics", () => {
    useMultiHexStore.setState({
      alignment: {
        ...ALIGNED,
        warnings: [MIXED_MESSAGE, "another warning"],
        diagnostics: [
          {
            code: CLASSIFICATION_BASIS_MIXED,
            message: MIXED_MESSAGE,
            severity: "warning",
            details: { named_dumps: [0, 1], stored_type_dumps: [2], total_dumps: 3, remedy: "" },
          },
        ],
      },
    });
    render(<HexAlignmentChip paths={["/a", "/b", "/c"]} hasMsl />);
    const banner = screen.getByTestId("classification-basis-warning");
    expect(banner).toHaveAttribute("data-scope", "aligned-window");
    expect(banner).toHaveTextContent("2 of 3 dumps are classified by mapping names");
    // The raw English duplicate is suppressed; unrelated warnings stay.
    const raw = screen.getAllByTestId("hex-alignment-warning").map((w) => w.textContent);
    expect(raw).toEqual(["another warning"]);
  });

  it("renders no banner when the alignment has no diagnostics (older server)", () => {
    useMultiHexStore.setState({ alignment: ALIGNED });
    render(<HexAlignmentChip paths={["/a", "/b"]} hasMsl />);
    expect(screen.queryByTestId("classification-basis-warning")).not.toBeInTheDocument();
  });
});
