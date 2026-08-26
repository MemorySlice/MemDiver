import { describe, it, expect, beforeEach, vi } from "vitest";
import { act, render } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `src/test/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { Wizard } from "./Wizard";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";
import { renderWithCount } from "@/test/render-counter";

// Keep the wizard off the network: neither call is part of what is under test.
vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/api/algorithms", () => ({
  getAlgorithmAvailability: vi.fn(() => new Promise(() => {})),
}));

/**
 * `Wizard.tsx` held four whole-store `useAppStore()` destructures, the widest
 * of them seven fields. Under zustand v5 a selector returning a fresh object
 * without `useShallow` re-renders forever, so mounting at all is a real
 * assertion here — `tsc` cannot catch that failure mode.
 */
// The wizard renders a ThemeToggle, which reads the theme context.
function mount() {
  return (
    <ThemeProvider>
      <Wizard />
    </ThemeProvider>
  );
}

describe("Wizard store selectors", () => {
  beforeEach(() => {
    act(() => {
      useAppStore.getState().resetWizard();
    });
  });

  it("mounts without exceeding the update depth", () => {
    expect(() => render(mount())).not.toThrow();
  });

  it("does not re-render on app-store fields the wizard never reads", () => {
    const { counter } = renderWithCount(mount());
    const initial = counter.count;

    // hexFocus belongs to the hex viewer's app-store slice; no wizard step
    // reads it, so a correctly-scoped selector must ignore all five writes.
    for (const offset of [16, 32, 48, 64, 80]) {
      act(() => {
        useAppStore.getState().setHexFocus({ offset, length: 4 });
      });
    }

    expect(counter.count - initial).toBe(0);
  });

  it("still re-renders when the wizard step it reads changes", () => {
    const { counter } = renderWithCount(mount());
    const initial = counter.count;

    act(() => {
      useAppStore.getState().setWizardStep(1);
    });

    expect(counter.count - initial).toBeGreaterThanOrEqual(1);
  });
});
