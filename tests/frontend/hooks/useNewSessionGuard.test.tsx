import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import { act, renderHook } from "@testing-library/react";

// The whole persistence module is replaced: this hook is a policy, and what is
// under test is WHICH call it makes and IN WHAT ORDER -- not what the call does.
vi.mock("@/utils/session-persistence", () => ({
  isWorkspaceDirty: vi.fn(() => false),
  persistSession: vi.fn(async () => "saved"),
  persistRecoverySnapshot: vi.fn(async () => undefined),
  markSessionSaved: vi.fn(),
}));

import {
  isWorkspaceDirty,
  persistRecoverySnapshot,
  persistSession,
} from "@/utils/session-persistence";
import { useNewSessionGuard } from "@/hooks/useNewSessionGuard";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

const dirtyMock = isWorkspaceDirty as unknown as Mock;
const saveMock = persistSession as unknown as Mock;
const recoveryMock = persistRecoverySnapshot as unknown as Mock;

/**
 * `resetWizard` is replaced by a spy rather than left real.
 *
 * What the hook owes its caller is "the wipe happened / did not happen", and
 * the wipe itself is covered exhaustively by `stores/app-store.test.ts`. Using
 * a spy also keeps the seeded stores below intact, so a test can assert that a
 * failed save left the work where it was.
 */
let resetWizard: Mock;
/** Shared ordering ledger, so "A before B" is an assertion and not a guess. */
let order: string[];

function seedDirtyWorkspace(): void {
  useAppStore.setState({ inputPath: "/data/dumps/target.raw" });
  useDumpStore.getState().addDump({
    path: "/data/dumps/target.raw",
    name: "target.raw",
    size: 4096,
    format: "raw",
  });
  useHexStore.setState({
    bookmarks: [
      { offset: 16, length: 4, label: "a" },
      { offset: 32, length: 4, label: "b" },
    ],
  });
  useAnalysisStore.setState({
    result: { hits: [] } as unknown as ReturnType<
      typeof useAnalysisStore.getState
    >["result"],
  });
  dirtyMock.mockReturnValue(true);
}

beforeEach(() => {
  order = [];
  dirtyMock.mockReset();
  dirtyMock.mockReturnValue(false);
  saveMock.mockReset();
  saveMock.mockImplementation(async () => {
    order.push("save");
    return "saved";
  });
  recoveryMock.mockReset();
  recoveryMock.mockImplementation(async () => {
    order.push("recovery");
  });

  useDumpStore.getState().clearAll();
  useHexStore.setState({ bookmarks: [] });
  useAnalysisStore.getState().reset();
  useAppStore.setState({ inputPath: "", datasetRoot: "" });

  resetWizard = vi.fn(() => {
    order.push("reset");
  });
  useAppStore.setState({ resetWizard });
});

describe("useNewSessionGuard on a clean workspace", () => {
  it("resets immediately and never shows the dialog", () => {
    const { result } = renderHook(() => useNewSessionGuard());

    act(() => result.current.requestNewSession());

    expect(resetWizard).toHaveBeenCalledTimes(1);
    expect(result.current.open).toBe(false);
    expect(saveMock).not.toHaveBeenCalled();
    expect(recoveryMock).not.toHaveBeenCalled();
  });
});

describe("useNewSessionGuard on a dirty workspace", () => {
  beforeEach(seedDirtyWorkspace);

  it("opens the dialog instead of wiping, with a pre-filled name", () => {
    const { result } = renderHook(() => useNewSessionGuard());

    act(() => result.current.requestNewSession());

    expect(resetWizard).not.toHaveBeenCalled();
    expect(result.current.open).toBe(true);
    // Named after the dump the workspace was built from, plus a timestamp.
    expect(result.current.defaultName).toMatch(/^target\.raw-\d{4}-\d{2}-\d{2}-\d{4}$/);
  });

  it("summarises what is at stake", () => {
    const { result } = renderHook(() => useNewSessionGuard());

    act(() => result.current.requestNewSession());

    expect(result.current.summary).toEqual({
      dumps: 1,
      bookmarks: 2,
      hasAnalysisResult: true,
    });
  });

  /**
   * THE regression guard. Ctrl+N is registered on `window`, so it keeps firing
   * while the dialog has focus; a re-entrant request that recomputed the
   * suggestion would reset the name field under whatever the user had typed.
   */
  it("ignores a re-entrant request while the dialog is open", () => {
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());
    const firstName = result.current.defaultName;

    // Change everything the suggestion and the summary are derived from...
    act(() => {
      useAppStore.setState({ inputPath: "/data/dumps/OTHER.raw" });
      useHexStore.setState({ bookmarks: [] });
    });
    act(() => result.current.requestNewSession());

    // ...and none of it lands, because the second request was a no-op.
    expect(result.current.defaultName).toBe(firstName);
    expect(result.current.summary.bookmarks).toBe(2);
    expect(result.current.open).toBe(true);
  });

  it("saves, then resets", async () => {
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());

    await act(async () => {
      await result.current.saveAndStartNew("  keeper  ");
    });

    // Trimmed, because the server turns the name into a filename.
    expect(saveMock).toHaveBeenCalledWith("keeper");
    expect(order).toEqual(["save", "reset"]);
    expect(result.current.open).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("falls back to the suggested name when the field was emptied", async () => {
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());
    const suggested = result.current.defaultName;

    await act(async () => {
      await result.current.saveAndStartNew("   ");
    });

    expect(saveMock).toHaveBeenCalledWith(suggested);
  });

  it("keeps the dialog open and does NOT reset when the save fails", async () => {
    saveMock.mockRejectedValue(new Error("disk full"));
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());

    await act(async () => {
      await result.current.saveAndStartNew("keeper");
    });

    expect(resetWizard).not.toHaveBeenCalled();
    expect(result.current.open).toBe(true);
    expect(result.current.error).toBe("disk full");
    // Not stuck on "Saving…" -- the user has to be able to retry.
    expect(result.current.busy).toBe(false);
    // And the work is still there.
    expect(useDumpStore.getState().dumps).toHaveLength(1);
  });

  it("writes the recovery copy BEFORE resetting, not merely as well as", async () => {
    // A deferred recovery write makes the ordering observable rather than
    // inferred: while it is pending, nothing may have been wiped yet.
    let release!: () => void;
    recoveryMock.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          release = () => {
            order.push("recovery");
            resolve();
          };
        }),
    );
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());

    let pending!: Promise<void>;
    act(() => {
      pending = result.current.discardAndStartNew();
    });
    expect(recoveryMock).toHaveBeenCalledTimes(1);
    expect(resetWizard).not.toHaveBeenCalled();

    await act(async () => {
      release();
      await pending;
    });

    expect(order).toEqual(["recovery", "reset"]);
  });

  it("does not reset when the recovery write fails, and says why", async () => {
    recoveryMock.mockRejectedValue(new Error("no space"));
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());

    await act(async () => {
      await result.current.discardAndStartNew();
    });

    expect(resetWizard).not.toHaveBeenCalled();
    expect(result.current.recoveryFailed).toBe(true);
    expect(result.current.error).toBe("no space");
    expect(result.current.open).toBe(true);
    expect(result.current.busy).toBe(false);
  });

  it("still lets the user discard after a failed recovery write", async () => {
    recoveryMock.mockRejectedValue(new Error("no space"));
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());
    await act(async () => {
      await result.current.discardAndStartNew();
    });

    act(() => result.current.forceDiscardAndStartNew());

    expect(resetWizard).toHaveBeenCalledTimes(1);
    expect(result.current.open).toBe(false);
    expect(result.current.recoveryFailed).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("cancel closes the dialog and changes nothing else", () => {
    const { result } = renderHook(() => useNewSessionGuard());
    act(() => result.current.requestNewSession());

    act(() => result.current.cancel());

    expect(result.current.open).toBe(false);
    expect(resetWizard).not.toHaveBeenCalled();
    expect(saveMock).not.toHaveBeenCalled();
    expect(recoveryMock).not.toHaveBeenCalled();
    expect(useDumpStore.getState().dumps).toHaveLength(1);
  });
});
