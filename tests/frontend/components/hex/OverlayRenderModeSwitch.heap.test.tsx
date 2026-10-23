import { afterEach, describe, expect, it } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { OverlayModeLegend } from "@/components/hex/OverlayModeLegend";
import { OverlayRenderModeSwitch } from "@/components/hex/OverlayRenderModeSwitch";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useOverlayRenderStore } from "@/stores/overlay-render-store";

/** The `Heap` segment of the overlay render-mode switch, and its legend. */

function setHeapStatus(heapStatus: string | null) {
  act(() => useMultiHexStore.setState({ heapStatus }));
}

afterEach(() => {
  act(() => {
    useMultiHexStore.getState().reset();
    useOverlayRenderStore.getState().reset();
  });
});

describe("OverlayRenderModeSwitch heap segment", () => {
  it("offers Heap and selects it when the window's heap roles are ok", () => {
    setHeapStatus("ok");
    render(<OverlayRenderModeSwitch enabled />);
    const heap = screen.getByTestId("hex-overlay-render-mode-heap");
    expect(heap).toHaveTextContent("Heap");
    expect(heap).not.toBeDisabled();
    fireEvent.click(heap);
    expect(useOverlayRenderStore.getState().renderMode).toBe("heap");
  });

  it.each([
    ["no_va_coordinate", /no VA coordinate/],
    ["empty_consensus", /consensus is empty/],
    ["error", /heap annotation of this consensus failed/],
    [null, /carries no heap annotation/],
  ])("disables Heap with a localized reason for status %s", (status, reason) => {
    setHeapStatus(status);
    render(<OverlayRenderModeSwitch enabled />);
    const heap = screen.getByTestId("hex-overlay-render-mode-heap");
    expect(heap).toBeDisabled();
    expect(heap.getAttribute("title")).toMatch(reason);
    // The other modes stay available.
    expect(screen.getByTestId("hex-overlay-render-mode-class")).not.toBeDisabled();
  });

  it("does not show an unavailable Heap choice as selected", () => {
    act(() => useOverlayRenderStore.getState().setRenderMode("heap"));
    setHeapStatus("error");
    render(<OverlayRenderModeSwitch enabled />);
    expect(screen.getByTestId("hex-overlay-render-mode-class")).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});

describe("OverlayModeLegend heap", () => {
  it("lists the seven roles and MIXED with their swatches", () => {
    render(<OverlayModeLegend mode="heap" />);
    const legend = screen.getByTestId("hex-overlay-legend-heap");
    expect(legend).toHaveTextContent("Heap roles");
    expect(legend).toHaveTextContent("Chunk header");
    expect(legend).toHaveTextContent("Mixed (dumps disagree)");
    expect(screen.getByTestId("hex-overlay-legend-heap-mixed")).toHaveClass("heap-swatch-mixed");
    expect(screen.getByTestId("hex-overlay-legend-heap-free_link")).toHaveClass(
      "heap-swatch-freelink",
    );
  });
});
