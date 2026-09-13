import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";

import { useRef } from "react";

import { useHexKeyboard } from "@/hooks/useHexKeyboard";
import { useHexStore } from "@/stores/hex-store";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";

/**
 * `n` / `p` — next and previous OCCURRENCE of the selected consensus class.
 *
 * `g` was already taken (ctrl/cmd-G, goto), so these two are the free letters,
 * and they are the pager keys `less` and `vim` already teach. The case that
 * earns its keep is the TEXT-ENTRY one: this listener is bound to the hex pane,
 * and the goto field lives inside it, so an unguarded bare letter would eat a
 * character out of whatever the user was typing — a bug that only ever shows up
 * as "the search box swallows my n".
 */

/** The hook's real host: a focusable pane with an input and a button inside. */
function Harness() {
  const ref = useRef<HTMLDivElement>(null);
  useHexKeyboard(ref);
  return (
    <div ref={ref} data-testid="pane" tabIndex={0}>
      <input data-testid="goto" />
      <button data-testid="chip">chip</button>
    </div>
  );
}

beforeEach(() => {
  act(() => {
    useHexStore.getState().reset();
    // The hook refuses every key while the file is empty; a size makes the
    // cursor arithmetic (and therefore the switch) live.
    useHexStore.setState({ fileSize: 64 * 1024, cursorOffset: 0 });
    useVarianceRegionsStore.getState().reset();
  });
});

afterEach(() => {
  act(() => {
    useHexStore.getState().reset();
    useVarianceRegionsStore.getState().reset();
  });
});

describe("useHexKeyboard region shortcuts", () => {
  it("advances and retreats through the region list", () => {
    const jumpNext = vi.fn();
    const jumpPrev = vi.fn();
    act(() => {
      useVarianceRegionsStore.setState({ jumpNext, jumpPrev });
    });
    const { getByTestId } = render(<Harness />);

    fireEvent.keyDown(getByTestId("pane"), { key: "n" });
    expect(jumpNext).toHaveBeenCalledTimes(1);
    expect(jumpPrev).not.toHaveBeenCalled();

    fireEvent.keyDown(getByTestId("pane"), { key: "p" });
    expect(jumpPrev).toHaveBeenCalledTimes(1);
  });

  it("does not fire while a text input has focus", () => {
    const jumpNext = vi.fn();
    const jumpPrev = vi.fn();
    act(() => {
      useVarianceRegionsStore.setState({ jumpNext, jumpPrev });
    });
    const { getByTestId } = render(<Harness />);

    // The event still reaches the pane — it BUBBLES from the input — which is
    // exactly why the guard has to look at the target rather than at the
    // listener's own element.
    fireEvent.keyDown(getByTestId("goto"), { key: "n" });
    fireEvent.keyDown(getByTestId("goto"), { key: "p" });

    expect(jumpNext).not.toHaveBeenCalled();
    expect(jumpPrev).not.toHaveBeenCalled();
  });

  it("leaves modified n/p to the browser and the OS", () => {
    const jumpNext = vi.fn();
    act(() => {
      useVarianceRegionsStore.setState({ jumpNext });
    });
    const { getByTestId } = render(<Harness />);

    // cmd-N is "new window"; hijacking it would be a worse bug than the one
    // the shortcut fixes.
    fireEvent.keyDown(getByTestId("pane"), { key: "n", metaKey: true });
    fireEvent.keyDown(getByTestId("pane"), { key: "n", ctrlKey: true });
    expect(jumpNext).not.toHaveBeenCalled();
  });

  it("still moves the byte cursor with the arrow keys", () => {
    const { getByTestId } = render(<Harness />);

    fireEvent.keyDown(getByTestId("pane"), { key: "ArrowRight" });
    expect(useHexStore.getState().cursorOffset).toBe(1);
  });
});

/**
 * TAB — the column toggle that must not become a keyboard trap.
 *
 * This listener is bound to the PANE and `keydown` bubbles, so the
 * unconditional `preventDefault()` this case used to carry swallowed every Tab
 * and Shift+Tab raised anywhere inside the pane: the toolbar, the goto field,
 * the align and render-mode switches, the chips, the rail, the status bar. A
 * keyboard-only user could reach none of them and could not leave the pane
 * without a mouse — WCAG 2.1.2 "No Keyboard Trap", Level A.
 */
describe("useHexKeyboard Tab handling", () => {
  it("toggles hex -> ascii when the GRID itself has focus", () => {
    const { getByTestId } = render(<Harness />);

    const prevented = !fireEvent.keyDown(getByTestId("pane"), { key: "Tab" });

    expect(useHexStore.getState().focusColumn).toBe("ascii");
    expect(prevented).toBe(true);
  });

  it("lets the SECOND Tab out of the pane, so the toggle is never a trap", () => {
    const { getByTestId } = render(<Harness />);

    fireEvent.keyDown(getByTestId("pane"), { key: "Tab" });
    const prevented = !fireEvent.keyDown(getByTestId("pane"), { key: "Tab" });

    expect(prevented).toBe(false);
    // …and the column resets, so the next entry into the grid starts on hex.
    expect(useHexStore.getState().focusColumn).toBe("hex");
  });

  it("never swallows Shift+Tab — backwards always leaves immediately", () => {
    const { getByTestId } = render(<Harness />);

    const prevented = !fireEvent.keyDown(getByTestId("pane"), {
      key: "Tab",
      shiftKey: true,
    });

    expect(prevented).toBe(false);
  });

  it("leaves Tab alone for every control INSIDE the pane", () => {
    const { getByTestId } = render(<Harness />);

    // Both events BUBBLE to the pane's listener — which is exactly why the
    // guard has to look at the target rather than at the listener's element.
    for (const id of ["goto", "chip"]) {
      const prevented = !fireEvent.keyDown(getByTestId(id), { key: "Tab" });
      expect(prevented, `Tab was swallowed for '${id}'`).toBe(false);
    }
    expect(useHexStore.getState().focusColumn).toBe("hex");
  });
});
