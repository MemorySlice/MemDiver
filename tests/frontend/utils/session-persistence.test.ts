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
});

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
