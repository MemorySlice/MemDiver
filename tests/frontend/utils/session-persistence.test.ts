import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";

// Only `saveSession` is replaced. Everything else in the client module stays
// real so that nothing else in the import graph (app-store pulls `getPathInfo`
// from here) has to be re-declared just to keep this file honest.
vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return { ...actual, saveSession: vi.fn() };
});

import { saveSession } from "@/api/client";
import { useAppStore } from "@/stores/app-store";
import { RECOVERY_SESSION_NAME } from "@/utils/session-names";
import {
  abandonPristineRestore,
  beginPristineRestore,
  isRestorePristine,
  isWorkspaceDirty,
  markSessionSaved,
  persistRecoverySnapshot,
  persistSession,
} from "@/utils/session-persistence";

const saveSessionMock = saveSession as unknown as Mock;

/** Put the app in the only view where dirtiness is a meaningful question. */
function enterWorkspace(): void {
  useAppStore.getState().setAppView("workspace");
}

beforeEach(() => {
  saveSessionMock.mockReset();
  saveSessionMock.mockResolvedValue({ name: "saved" });
  useAppStore.getState().resetWizard();
  // Module-level state: a window left open by one test would answer the next
  // one's dirty check.
  abandonPristineRestore();
});

/** The capture-phase signal the pristine window listens for. */
function analystTouchesThePage(): void {
  window.dispatchEvent(new Event("pointerdown"));
}

describe("isWorkspaceDirty", () => {
  /**
   * The reason `beforeunload` does not fire on an empty app. A fresh store has
   * `lastSavedDigest === null`, which reads as dirty -- so without the view
   * check the landing page would prompt before every reload.
   */
  it("is false outside the workspace even with a never-saved digest", () => {
    expect(useAppStore.getState().lastSavedDigest).toBeNull();

    useAppStore.getState().setAppView("landing");
    expect(isWorkspaceDirty()).toBe(false);

    useAppStore.getState().setAppView("wizard");
    expect(isWorkspaceDirty()).toBe(false);
  });

  it("reads a null digest inside the workspace as dirty", () => {
    enterWorkspace();
    // "The wizard finished and nothing has been saved since" -- the case the
    // reported bug silently discarded.
    expect(useAppStore.getState().lastSavedDigest).toBeNull();
    expect(isWorkspaceDirty()).toBe(true);
  });

  it("is clean right after a save and dirty again once the workspace changes", async () => {
    enterWorkspace();
    useAppStore.getState().setInputPath("/dumps/first.raw");

    await persistSession("run-1");
    expect(isWorkspaceDirty()).toBe(false);

    useAppStore.getState().setInputPath("/dumps/second.raw");
    expect(isWorkspaceDirty()).toBe(true);
  });

  it("ignores the session name, so re-saving under a new name is not a change", async () => {
    enterWorkspace();
    await persistSession("run-1");

    // `session_name` is a volatile field: it says which save this is, not what
    // was saved, so the digest must not move with it.
    markSessionSaved({ ...saveSessionMock.mock.calls[0][0], session_name: "other" });
    expect(isWorkspaceDirty()).toBe(false);
  });
});

describe("persistSession", () => {
  it("posts the built snapshot under the given name and marks the workspace clean", async () => {
    enterWorkspace();
    saveSessionMock.mockResolvedValue({ name: "run-1" });

    const name = await persistSession("run-1");

    expect(name).toBe("run-1");
    expect(saveSessionMock).toHaveBeenCalledTimes(1);
    expect(saveSessionMock.mock.calls[0][0]).toMatchObject({ session_name: "run-1" });
    expect(useAppStore.getState().lastSavedDigest).not.toBeNull();
    expect(isWorkspaceDirty()).toBe(false);
  });

  /**
   * The critical one. A caller that resets after a rejected save destroys the
   * very work it was asked to keep, and the only thing standing between the
   * two is that `markSessionSaved` is never reached.
   */
  it("does NOT mark the workspace clean when the write is rejected", async () => {
    enterWorkspace();
    useAppStore.getState().setLastSavedDigest("SENTINEL");
    saveSessionMock.mockRejectedValue(new Error("disk full"));

    await expect(persistSession("run-1")).rejects.toThrow("disk full");

    expect(useAppStore.getState().lastSavedDigest).toBe("SENTINEL");
    expect(isWorkspaceDirty()).toBe(true);
  });
});

describe("persistRecoverySnapshot", () => {
  it("posts under the reserved recovery name", async () => {
    enterWorkspace();

    await persistRecoverySnapshot();

    expect(saveSessionMock).toHaveBeenCalledTimes(1);
    expect(saveSessionMock.mock.calls[0][0]).toMatchObject({
      session_name: RECOVERY_SESSION_NAME,
    });
  });

  /**
   * The recovery copy is a safety net for work the analyst just said they did
   * not want -- not a save they asked for. Marking it clean would make a later
   * prompt claim the work is already stored under a name they chose.
   */
  it("deliberately leaves the workspace dirty", async () => {
    enterWorkspace();
    useAppStore.getState().setLastSavedDigest("SENTINEL");

    await persistRecoverySnapshot();

    expect(useAppStore.getState().lastSavedDigest).toBe("SENTINEL");
    expect(isWorkspaceDirty()).toBe(true);
  });

  it("propagates a rejected write rather than swallowing it", async () => {
    enterWorkspace();
    saveSessionMock.mockRejectedValue(new Error("no space"));

    await expect(persistRecoverySnapshot()).rejects.toThrow("no space");
  });
});

describe("beginPristineRestore", () => {
  /**
   * The regression this exists for. `restoreSession` sets `appView` to
   * "workspace" on its FIRST line and only then awaits the path-info pass, so
   * the workspace is on screen and clickable while `lastSavedDigest` is still
   * null -- which every other rule in `isWorkspaceDirty` reads as unsaved work.
   * A window opened only after the restore resolved could not cover this at all.
   */
  it("covers the gap between the workspace appearing and the baseline landing", () => {
    const restore = beginPristineRestore();
    enterWorkspace();

    expect(useAppStore.getState().lastSavedDigest).toBeNull();
    expect(isWorkspaceDirty()).toBe(false);

    restore.abandon();
    expect(isWorkspaceDirty()).toBe(true);
  });

  /**
   * Effects downstream of a restore keep writing snapshot fields after its
   * promise resolves -- bookmark rehydration, a scan result arriving over the
   * task socket. None of it is the analyst's work, and none of it is on a clock.
   */
  it("absorbs a late write with no user interaction, however late it lands", () => {
    enterWorkspace();
    const restore = beginPristineRestore();
    markSessionSaved({ input_path: "/dumps/restored.raw" });
    restore.settle();

    // Something downstream of the restore writes a snapshot field.
    useAppStore.getState().setInputPath("/dumps/rehydrated.raw");

    expect(isWorkspaceDirty()).toBe(false);
    expect(isRestorePristine()).toBe(true);
  });

  it("seals the baseline on the first touch, and reads clean immediately after", () => {
    enterWorkspace();
    const restore = beginPristineRestore();
    restore.settle();
    useAppStore.getState().setInputPath("/dumps/rehydrated.raw");

    analystTouchesThePage();

    expect(isRestorePristine()).toBe(false);
    expect(useAppStore.getState().lastSavedDigest).not.toBeNull();
    expect(isWorkspaceDirty()).toBe(false);
  });

  /**
   * The safety property the capture phase buys. An edit the analyst makes AFTER
   * the window closed must read as dirty -- the whole point of the guard.
   */
  it("reports an edit made after the window closed as dirty", () => {
    enterWorkspace();
    const restore = beginPristineRestore();
    restore.settle();
    analystTouchesThePage();

    useAppStore.getState().setInputPath("/dumps/the-analyst-changed-this.raw");

    expect(isWorkspaceDirty()).toBe(true);
  });

  /**
   * The ordering that makes this safe rather than merely longer: the capture
   * listener fires BEFORE React handles the same event, so the baseline is taken
   * from the state the analyst is about to act on, never from the state their
   * action produced.
   */
  it("takes the baseline from before the edit when the touch IS the edit", () => {
    enterWorkspace();
    const restore = beginPristineRestore();
    restore.settle();

    // The capture-phase seal, then the edit that same interaction causes.
    analystTouchesThePage();
    useAppStore.getState().setInputPath("/dumps/typed-by-the-analyst.raw");

    expect(isWorkspaceDirty()).toBe(true);
  });

  /**
   * A restore whose chain has not finished has nothing of the analyst's in it,
   * so touching the page mid-restore must not freeze a half-applied snapshot in
   * as the baseline. The seal waits for both.
   */
  it("does not seal on a touch while the restore is still in flight", () => {
    enterWorkspace();
    const restore = beginPristineRestore();

    analystTouchesThePage();
    expect(isRestorePristine()).toBe(true);
    expect(isWorkspaceDirty()).toBe(false);

    restore.settle();
    expect(isRestorePristine()).toBe(false);
  });

  /** A failed restore must not be blessed as saved -- what landed is not the file. */
  it("abandon leaves the workspace dirty and takes no baseline", () => {
    enterWorkspace();
    const restore = beginPristineRestore();

    restore.abandon();

    expect(isRestorePristine()).toBe(false);
    expect(useAppStore.getState().lastSavedDigest).toBeNull();
    expect(isWorkspaceDirty()).toBe(true);
  });

  it("a second restore supersedes the first without sealing it", () => {
    enterWorkspace();
    const first = beginPristineRestore();
    beginPristineRestore();

    // The superseded handle must not seal the window the second restore owns.
    first.settle();
    expect(isRestorePristine()).toBe(true);

    analystTouchesThePage();
    expect(isRestorePristine()).toBe(false);
  });

  /**
   * A reset can land before the analyst ever touches the page. Re-baselining a
   * workspace that is no longer on screen would describe nothing.
   */
  it("does not baseline a workspace that has already been reset away", () => {
    enterWorkspace();
    const restore = beginPristineRestore();
    restore.settle();

    useAppStore.getState().resetWizard();
    analystTouchesThePage();

    expect(useAppStore.getState().lastSavedDigest).toBeNull();
  });
});
