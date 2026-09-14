import { describe, it, expect, beforeEach, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { Wizard } from "@/components/wizard/Wizard";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";
import { renderWithCount } from "@tests/helpers/render-counter";

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

describe("Wizard final button names what will actually happen", () => {
  beforeEach(() => {
    act(() => {
      useAppStore.getState().resetWizard();
      // With no `pathInfo` the step list is ["Select Data", "Analysis"], so
      // step 1 is the last one and the nav button is the final action.
      useAppStore.getState().setWizardStep(1);
    });
  });

  it("promises an analysis when Auto-Analyze is chosen", () => {
    act(() => {
      useAppStore.getState().setAnalysisApproach("auto");
    });
    render(mount());

    expect(screen.getByRole("button", { name: "Start Analysis" })).toBeInTheDocument();
  });

  /**
   * The bug this covers: "Inspect Only" is the user declining an analysis, and
   * the button then offered to start one anyway. `completeWizard` never read
   * the mode, so the label was the ONLY thing that could have been wrong — and
   * it was.
   */
  it("promises only the workspace when Inspect Only is chosen", () => {
    act(() => {
      useAppStore.getState().setAnalysisApproach("inspect");
    });
    render(mount());

    expect(screen.getByRole("button", { name: "Open Workspace" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start Analysis" })).not.toBeInTheDocument();
  });

  it("renames itself the moment the card is clicked", () => {
    act(() => {
      useAppStore.getState().setAnalysisApproach("auto");
    });
    render(mount());

    fireEvent.click(screen.getByRole("button", { name: /^Inspect Only/ }));

    expect(screen.getByRole("button", { name: "Open Workspace" })).toBeInTheDocument();
  });
});

/**
 * The wizard used to be a dead end. It is reached from the session list (and
 * from "New Session"), and Back at step 0 was disabled -- so every route out of
 * it required completing it. Escape is bound to the same callback, which is why
 * both are asserted here.
 */
describe("Wizard Back leaves the wizard rather than dead-ending", () => {
  beforeEach(() => {
    act(() => {
      useAppStore.getState().resetWizard();
      // `resetWizard` lands on "landing"; the wizard is only ever rendered
      // from "wizard", and the assertions below are about leaving it.
      useAppStore.getState().setAppView("wizard");
    });
  });

  it("offers an enabled 'Back to sessions' at step 0", () => {
    render(mount());

    const back = screen.getByRole("button", { name: "Back to sessions" });
    expect(back).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Back" })).not.toBeInTheDocument();
  });

  it("returns to the session list when it is clicked", () => {
    render(mount());

    fireEvent.click(screen.getByRole("button", { name: "Back to sessions" }));

    expect(useAppStore.getState().appView).toBe("landing");
    // The step is left alone -- leaving the wizard is not the same as
    // restarting it.
    expect(useAppStore.getState().wizardStep).toBe(0);
  });

  it("leaves the wizard on Escape at step 0 too", () => {
    render(mount());

    fireEvent.keyDown(window, { key: "Escape" });

    expect(useAppStore.getState().appView).toBe("landing");
  });

  it("still steps back one page from a later step", () => {
    act(() => {
      useAppStore.getState().setWizardStep(1);
    });
    render(mount());

    fireEvent.click(screen.getByRole("button", { name: "Back" }));

    expect(useAppStore.getState().wizardStep).toBe(0);
    // Still in the wizard: only step 0 is an exit.
    expect(useAppStore.getState().appView).toBe("wizard");
  });
});
