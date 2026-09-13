import { vi } from "vitest";

/**
 * Gives jsdom enough geometry for TanStack Virtual to produce rows.
 *
 * jsdom lays nothing out: every `getBoundingClientRect()` is a zero rect and
 * `ResizeObserver` does not exist. A virtualizer handed a zero-height scroll
 * element computes an EMPTY visible range and renders nothing — and a test
 * asserting "every pane got the same row offset" over zero rows passes for the
 * wrong reason, which is worse than failing. Every test that renders a
 * virtualized hex view therefore installs this first and then asserts that it
 * actually got rows.
 *
 * Both stubs are undone by `vi.restoreAllMocks()` / `vi.unstubAllGlobals()`.
 */
export function stubVirtualizerLayout(width = 1600, height = 400): void {
  if (!("ResizeObserver" in globalThis)) {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
  }
  // TanStack Virtual measures the scroll element with `offsetWidth` /
  // `offsetHeight` (see `getRect` in @tanstack/virtual-core), NOT with
  // `getBoundingClientRect` — jsdom returns 0 for both, and a 0-height scroll
  // element yields an empty range. Stubbing only the bounding rect looks right
  // and changes nothing.
  vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockReturnValue(height);
  vi.spyOn(HTMLElement.prototype, "offsetWidth", "get").mockReturnValue(width);
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue({
    width,
    height,
    top: 0,
    left: 0,
    right: width,
    bottom: height,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  } as DOMRect);
}
