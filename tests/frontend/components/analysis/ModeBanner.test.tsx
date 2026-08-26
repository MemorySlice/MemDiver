import { describe, it, expect, beforeEach } from "vitest";
import { act, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ModeBanner } from "@/components/analysis/ModeBanner";
import { useAppStore } from "@/stores/app-store";
import { renderWithCount } from "@tests/helpers/render-counter";

describe("ModeBanner", () => {
  beforeEach(() => {
    act(() => {
      useAppStore.getState().resetWizard();
    });
  });

  it("mounts without exceeding the update depth", () => {
    // Under zustand v5 a bare object-returning selector loops forever inside
    // useSyncExternalStore; mounting at all is the assertion.
    expect(() => render(<ModeBanner />)).not.toThrow();
    expect(screen.getAllByRole("button").length).toBe(2);
  });

  it("does not re-render on app-store fields it never reads", () => {
    const { counter } = renderWithCount(<ModeBanner />);
    const initial = counter.count;

    for (const offset of [16, 32, 48, 64, 80]) {
      act(() => {
        useAppStore.getState().setHexFocus({ offset, length: 4 });
      });
    }

    expect(counter.count - initial).toBe(0);
  });

  it("re-renders when the mode it reads changes", () => {
    const { counter } = renderWithCount(<ModeBanner />);
    const initial = counter.count;

    act(() => {
      useAppStore.getState().setMode("exploration");
    });

    // Measured at 2 commits: one from the `mode` subscription and one more
    // from react-i18next re-resolving the mode-keyed strings. The second is
    // not the store's doing — the pre-sweep whole-store destructure measured
    // the same 2 here, and differed only on the unrelated-field case above
    // (1 commit then, 0 now). Asserted as a floor so an i18n change does not
    // fail a test about store subscriptions.
    expect(counter.count - initial).toBeGreaterThanOrEqual(1);
  });
});
