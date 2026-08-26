import { describe, it, expect, beforeEach } from "vitest";
import { act } from "@testing-library/react";

import { useActiveDump } from "@/hooks/useActiveDump";
import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { renderWithCount } from "@tests/helpers/render-counter";

/**
 * `useActiveDump` is read by most of the workspace, so its subscription width
 * multiplies across every consumer: one over-broad read here re-renders half
 * the app on an unrelated app-store `set()`. These tests pin it to the four
 * fields it actually uses.
 */
function Consumer() {
  const dump = useActiveDump();
  return <div data-testid="path">{dump?.path ?? "none"}</div>;
}

describe("useActiveDump subscription width", () => {
  beforeEach(() => {
    act(() => {
      useAppStore.getState().resetWizard();
      useDumpStore.getState().clearAll();
      useAppStore.getState().setInputMode("file");
    });
  });

  it("mounts without an update-depth loop", () => {
    expect(() => renderWithCount(<Consumer />)).not.toThrow();
  });

  it("does not re-render on app-store fields it never reads", () => {
    const { counter } = renderWithCount(<Consumer />);
    const initial = counter.count;

    // hexFocus and mode are app-store fields `useActiveDump` does not observe.
    for (const offset of [16, 32, 48, 64, 80]) {
      act(() => {
        useAppStore.getState().setHexFocus({ offset, length: 4 });
      });
    }
    act(() => {
      useAppStore.getState().setMode("exploration");
    });

    expect(counter.count - initial).toBe(0);
  });

  it("still re-renders when a field it reads changes", () => {
    const { counter } = renderWithCount(<Consumer />);
    const initial = counter.count;

    act(() => {
      useAppStore.getState().setInputPath("/dumps/live.msl");
    });

    expect(counter.count - initial).toBe(1);
  });
});
