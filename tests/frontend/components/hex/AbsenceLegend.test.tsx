/**
 * The absence legend explains the MSL page-state tints (failed / unmapped /
 * not resident) — but only over a grid that can paint them, and only while the
 * page states are loaded for the "va" view, the one coordinate they answer in.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { AbsenceLegend } from "@/components/hex/AbsenceLegend";
import { HexLegend } from "@/components/hex/HexLegend";
import { useHexStore } from "@/stores/hex-store";
import { useHeapStore } from "@/stores/heap-store";

const PAGE_STATE_ENTRIES = [
  {
    testId: "hex-absence-legend-absence-page-failed",
    label: "Failed",
    title: "Mapped but the read failed (zero-filled, not captured)",
  },
  {
    testId: "hex-absence-legend-absence-page-unmapped",
    label: "Unmapped",
    title: "Not mapped when read (zero-filled, not captured)",
  },
  {
    testId: "hex-absence-legend-absence-page-not-resident",
    label: "Not resident",
    title: "Mapped but never touched (zero page, not captured)",
  },
] as const;

const VOID_TEST_IDS = [
  "hex-absence-legend-absence-gap",
  "hex-absence-legend-absence-absent",
  "hex-absence-legend-absence-error",
];

function pageStatesOnScreen(on: boolean) {
  useHexStore.setState({ viewMode: on ? "va" : "raw", pageStatesLoaded: on });
}

beforeEach(() => {
  useHexStore.setState({ dumpPath: "/dumps/a.msl", highlightedRegions: [] });
  useHeapStore.setState({ dumps: {}, roleWindows: {}, roleWindowsVersion: 0 });
  pageStatesOnScreen(false);
});

describe("AbsenceLegend page-state entries", () => {
  it("renders the three page states with translated label and tooltip", () => {
    pageStatesOnScreen(true);
    render(<AbsenceLegend pageStates />);
    for (const { testId, label, title } of PAGE_STATE_ENTRIES) {
      const entry = screen.getByTestId(testId);
      expect(entry).toHaveTextContent(label);
      expect(entry).toHaveAttribute("title", title);
    }
  });

  it("paints each swatch with the page-state modifier, not a hatch", () => {
    pageStatesOnScreen(true);
    render(<AbsenceLegend pageStates />);
    for (const { testId } of PAGE_STATE_ENTRIES) {
      const swatch = screen.getByTestId(testId).querySelector(".md-variance-swatch");
      expect(swatch).not.toBeNull();
      expect(swatch!.className).toMatch(/absence-page-/);
    }
  });

  it("keeps the void causes alongside the page states", () => {
    pageStatesOnScreen(true);
    render(<AbsenceLegend pageStates />);
    for (const id of VOID_TEST_IDS) expect(screen.getByTestId(id)).toBeInTheDocument();
  });

  /** Side-by-side panes never consult page states, so they get no entry. */
  it("omits the page states over a grid that cannot paint them", () => {
    pageStatesOnScreen(true);
    render(<AbsenceLegend />);
    for (const { testId } of PAGE_STATE_ENTRIES) {
      expect(screen.queryByTestId(testId)).not.toBeInTheDocument();
    }
    for (const id of VOID_TEST_IDS) expect(screen.getByTestId(id)).toBeInTheDocument();
  });

  it("omits the page states while none are loaded for the va view", () => {
    render(<AbsenceLegend pageStates />);
    for (const { testId } of PAGE_STATE_ENTRIES) {
      expect(screen.queryByTestId(testId)).not.toBeInTheDocument();
    }
  });
});

describe("HexLegend page-state entries (single-dump viewer)", () => {
  it("renders nothing when no page states are on screen", () => {
    const { container } = render(<HexLegend />);
    expect(container).toBeEmptyDOMElement();
  });

  it("explains the three page-state tints, and only those, in the va view", () => {
    pageStatesOnScreen(true);
    render(<HexLegend />);
    expect(screen.getByTestId("hex-page-state-legend")).toBeInTheDocument();
    for (const { testId, label } of PAGE_STATE_ENTRIES) {
      expect(screen.getByTestId(testId)).toHaveTextContent(label);
    }
    for (const id of VOID_TEST_IDS) expect(screen.queryByTestId(id)).not.toBeInTheDocument();
  });
});
