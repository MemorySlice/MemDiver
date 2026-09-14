import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import { renderHook } from "@testing-library/react";

vi.mock("@/utils/session-persistence", () => ({
  isWorkspaceDirty: vi.fn(() => false),
}));

import { isWorkspaceDirty } from "@/utils/session-persistence";
import { useBeforeUnloadGuard } from "@/hooks/useBeforeUnloadGuard";

const dirtyMock = isWorkspaceDirty as unknown as Mock;

/** Fire a real cancelable `beforeunload` and report whether it was blocked. */
function fireBeforeUnload(): boolean {
  const event = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

beforeEach(() => {
  dirtyMock.mockReset();
  dirtyMock.mockReturnValue(false);
});

describe("useBeforeUnloadGuard", () => {
  it("lets a clean workspace close without a prompt", () => {
    renderHook(() => useBeforeUnloadGuard());

    expect(fireBeforeUnload()).toBe(false);
  });

  it("blocks the unload once the workspace is dirty", () => {
    renderHook(() => useBeforeUnloadGuard());
    dirtyMock.mockReturnValue(true);

    expect(fireBeforeUnload()).toBe(true);
  });

  /**
   * The effect has an empty dependency list, so the listener is registered once
   * and never re-added. That is only correct because the handler asks
   * `isWorkspaceDirty()` at FIRE time; a stale closure would answer with
   * whatever was true at mount.
   */
  it("asks at fire time, so one registration tracks the workspace", () => {
    renderHook(() => useBeforeUnloadGuard());

    expect(fireBeforeUnload()).toBe(false);
    dirtyMock.mockReturnValue(true);
    expect(fireBeforeUnload()).toBe(true);
    dirtyMock.mockReturnValue(false);
    expect(fireBeforeUnload()).toBe(false);
  });

  it("removes the listener on unmount", () => {
    const remove = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() => useBeforeUnloadGuard());

    unmount();
    dirtyMock.mockReturnValue(true);

    expect(remove).toHaveBeenCalledWith("beforeunload", expect.any(Function));
    // The behavioural half: a dirty workspace no longer blocks anything once
    // the component that owned the guard has gone.
    expect(fireBeforeUnload()).toBe(false);
    remove.mockRestore();
  });
});
