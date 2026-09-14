import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` -- needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
// Real strings, so every assertion below checks the English the user actually
// sees rather than a key name -- this repo's only guard against a missing key.
import "@/i18n";

// The policy is under test elsewhere; here the question is only WHICH function
// the two affordances reach, so the hook is a spy that returns a fixed guard.
vi.mock("@/hooks/useNewSessionGuard", () => ({
  useNewSessionGuard: vi.fn(),
}));

// Keep the workspace off the network. Everything else in the client module
// stays real so the rest of the import graph is untouched.
vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return {
    ...actual,
    getNotebookStatus: vi.fn(async () => ({ available: false })),
    getEntropy: vi.fn(() => new Promise(() => {})),
    getVasRegions: vi.fn(() => new Promise(() => {})),
    listDatasetRuns: vi.fn(() => new Promise(() => {})),
  };
});

import { useNewSessionGuard, type NewSessionGuard } from "@/hooks/useNewSessionGuard";
import { Workspace } from "@/components/layout/Workspace";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";

/**
 * jsdom has neither observer, and `react-resizable-panels` constructs a
 * ResizeObserver in a layout effect -- so the whole workspace fails to mount
 * without these two.
 */
class NoopObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}
vi.stubGlobal("ResizeObserver", NoopObserver);
vi.stubGlobal("IntersectionObserver", NoopObserver);

const guardHook = useNewSessionGuard as unknown as Mock;

let requestNewSession: Mock;
let resetWizard: Mock;
let realResetWizard: () => void;

function makeGuard(overrides: Partial<NewSessionGuard> = {}): NewSessionGuard {
  return {
    open: false,
    defaultName: "target.raw-2026-09-14-1200",
    summary: { dumps: 1, bookmarks: 0, hasAnalysisResult: false },
    busy: false,
    error: null,
    recoveryFailed: false,
    requestNewSession,
    saveAndStartNew: vi.fn(async () => {}),
    discardAndStartNew: vi.fn(async () => {}),
    forceDiscardAndStartNew: vi.fn(),
    cancel: vi.fn(),
    ...overrides,
  };
}

function mount(overrides: Partial<NewSessionGuard> = {}) {
  guardHook.mockReturnValue(makeGuard(overrides));
  return render(
    <ThemeProvider>
      <Workspace />
    </ThemeProvider>,
  );
}

beforeEach(() => {
  guardHook.mockReset();
  requestNewSession = vi.fn();
  // A wipe that did NOT come through the guard is the failure this file exists
  // to catch, so `resetWizard` is watched rather than left to run.
  realResetWizard = useAppStore.getState().resetWizard;
  resetWizard = vi.fn();
  useAppStore.setState({ resetWizard });
});

afterEach(() => {
  useAppStore.setState({ resetWizard: realResetWizard });
});

describe("Workspace new-session entry points", () => {
  it("mounts the guard exactly once, so there is a single policy owner", () => {
    mount();

    // Ctrl+N is registered here while the button lives in `Toolbar` two
    // components away; a second call would give the two halves two dialogs.
    expect(guardHook).toHaveBeenCalled();
    const instances = new Set(guardHook.mock.results.map((r) => r.value));
    expect(instances.size).toBe(1);
  });

  /**
   * THE anti-duplication assertion. Before the guard existed, the toolbar
   * button and Ctrl+N each called `resetWizard` directly -- two code paths, one
   * of which could grow a prompt while the other stayed silent.
   */
  it("routes the toolbar button and Ctrl+N through the same function", () => {
    mount();

    fireEvent.click(screen.getByTestId("new-session"));
    expect(requestNewSession).toHaveBeenCalledTimes(1);

    fireEvent.keyDown(window, { key: "n", ctrlKey: true });
    expect(requestNewSession).toHaveBeenCalledTimes(2);

    // Neither path wipes the workspace itself; only the guard may decide that.
    expect(resetWizard).not.toHaveBeenCalled();
  });

  it("accepts Cmd+N too, since the shortcut map folds meta into ctrl", () => {
    mount();

    fireEvent.keyDown(window, { key: "N", metaKey: true });

    expect(requestNewSession).toHaveBeenCalledTimes(1);
    expect(resetWizard).not.toHaveBeenCalled();
  });

  it("shows no dialog while the guard says it is closed", () => {
    mount();

    expect(screen.queryByTestId("new-session-dialog")).not.toBeInTheDocument();
  });

  it("renders the dialog, and only it, once the guard opens", () => {
    mount({ open: true });

    expect(screen.getByTestId("new-session-dialog")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Start a new session?" })).toBeInTheDocument();
    expect(screen.getAllByTestId("new-session-dialog")).toHaveLength(1);
  });
});
