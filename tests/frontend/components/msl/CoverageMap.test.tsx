import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import "@/i18n";
import type { PageStatesResponse } from "@/api/types";

const RESPONSE: PageStatesResponse = {
  regions: [
    {
      base_addr: 0x1000,
      region_size: 0x4000,
      page_size: 0x1000,
      intervals: [
        { va: 0x1000, length: 0x1000, state: "CAPTURED", page_count: 1, vas_offset: 0 },
        { va: 0x2000, length: 0x2000, state: "NOT_RESIDENT", page_count: 2 },
        { va: 0x4000, length: 0x1000, state: "FAILED", page_count: 1 },
      ],
    },
  ],
  total_pages: 4,
  captured_pages: 1,
  coverage: 0.25,
  vas_size: 0x4000,
};

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => Promise.resolve(RESPONSE)),
}));

import { CoverageMap } from "@/components/msl/CoverageMap";

describe("CoverageMap", () => {
  it("styles NOT_RESIDENT intervals with the hyphenated hex.css class", async () => {
    render(<CoverageMap mslPath="/x/a.msl" />);
    const interval = await screen.findByTitle("0x2000–0x4000 · Not resident · 2 pages");
    expect(interval).toHaveClass("page-state-not-resident");
    expect(interval.className).not.toContain("not_resident");
  });

  it("keeps the single-word state classes unchanged", async () => {
    render(<CoverageMap mslPath="/x/a.msl" />);
    expect(await screen.findByTitle(/· Captured ·/)).toHaveClass("page-state-captured");
    expect(screen.getByTitle(/· Failed ·/)).toHaveClass("page-state-failed");
  });

  it("shows a NOT_RESIDENT legend chip with label, tooltip and page count", async () => {
    render(<CoverageMap mslPath="/x/a.msl" />);
    const chip = await screen.findByTestId("page-state-legend-NOT_RESIDENT");
    expect(chip).toHaveTextContent("Not resident");
    expect(chip).toHaveTextContent("(2)");
    expect(chip).toHaveAttribute(
      "title",
      "Mapped but never touched (zero page, not captured)",
    );
    expect(chip.querySelector(".page-state-not-resident")).not.toBeNull();
    expect(screen.getByTestId("page-state-legend-UNMAPPED")).toHaveTextContent("(0)");
    expect(screen.getByTestId("page-state-legend-CAPTURED")).not.toHaveAttribute("title");
  });
});
