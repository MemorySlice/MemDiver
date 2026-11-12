import { afterEach, describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { AlignedWindowAlignment } from "@/api/aligned-window";
import { offsetsAreDumpOffsets, type AlignmentMethod } from "@/api/candidates";
import { HexAlignmentChip } from "@/components/hex/HexAlignmentChip";
import { useMultiHexStore } from "@/stores/multi-hex-store";

type Method = AlignedWindowAlignment["method"];

// Record over the full union: adding a method without a row here fails tsc.
const LABELS: Record<Method, string> = {
  module_offset: "Aligned by module offset",
  module_relative: "Aligned by module-relative offset (per-process)",
  virtual_address: "Aligned by virtual address",
  file_offset: "Aligned by file offset",
};

// The two method unions must stay identical.
const _same: AlignmentMethod extends Method ? (Method extends AlignmentMethod ? true : never) : never = true;

afterEach(() => useMultiHexStore.setState({ alignment: null }));

describe("HexAlignmentChip method labels", () => {
  it.each(Object.keys(LABELS) as Method[])("labels %s", (method) => {
    expect(_same).toBe(true);
    useMultiHexStore.setState({
      alignment: {
        method,
        bytes_compared: 1,
        bytes_discarded: 0,
        sizes_differed: false,
        n_sources: 2,
        warnings: [],
      },
    });
    render(<HexAlignmentChip paths={["a", "b"]} hasMsl={false} />);
    expect(screen.getByTestId("hex-alignment-method")).toHaveTextContent(LABELS[method]);
  });

  it("refuses dump-offset jumps for every method but file_offset", () => {
    const base = { bytes_compared: 0, bytes_discarded: 0, sizes_differed: false, n_sources: 2, warnings: [] };
    for (const method of Object.keys(LABELS) as Method[]) {
      expect(offsetsAreDumpOffsets({ ...base, method })).toBe(method === "file_offset");
    }
  });
});
