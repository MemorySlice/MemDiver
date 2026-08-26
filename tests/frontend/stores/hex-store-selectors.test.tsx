import { describe, it, expect, beforeEach, vi } from "vitest";
import { act } from "@testing-library/react";
import { useShallow } from "zustand/react/shallow";

import { useHexStore } from "@/stores/hex-store";
import { renderWithCount } from "@tests/helpers/render-counter";

// getPageStates is only reached via the "va" view; stub it so nothing here
// touches the network through the api client.
vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

/**
 * The hex store `set()`s on every chunk fetch, prefetch, cursor move and
 * scroll. Any component that destructures the whole store therefore re-renders
 * on every one of those, even when it reads none of the mutated fields. With
 * the brute-force stride default at 1 a run emits ~6.4x the ticks it used to,
 * so those storms now last long enough to matter.
 *
 * These tests pin the selector shapes the sweep introduced: the bookmarks
 * reader (Workspace's Sidebar) and the keyboard reader (useHexKeyboard) must
 * not re-render for store mutations they do not observe.
 */

// Mirrors Workspace.tsx's Sidebar bookmark read verbatim.
function BookmarkReader() {
  const { bookmarks, addBookmark, removeBookmark } = useHexStore(
    useShallow((s) => ({
      bookmarks: s.bookmarks,
      addBookmark: s.addBookmark,
      removeBookmark: s.removeBookmark,
    })),
  );
  void addBookmark;
  void removeBookmark;
  return <div data-testid="count">{bookmarks.length}</div>;
}

// The pre-sweep shape, kept as a control: it proves the harness has teeth by
// showing the storm the sweep removes. Not a pattern to copy into src/.
function WholeStoreReader() {
  const { bookmarks } = useHexStore();
  return <div>{bookmarks.length}</div>;
}

// Mirrors HexFocusBridge's single-field read.
function ScrollReader() {
  const scrollToOffset = useHexStore((s) => s.scrollToOffset);
  void scrollToOffset;
  return <div />;
}

describe("hex store selector subscriptions", () => {
  beforeEach(() => {
    act(() => {
      useHexStore.getState().reset();
      useHexStore.getState().setDumpPath("/dumps/sel.msl", 65536, "msl");
    });
  });

  it("does not re-render the bookmark reader on cursor mutations", () => {
    const { counter } = renderWithCount(<BookmarkReader />);
    const initial = counter.count;

    for (const offset of [16, 32, 48, 64, 80]) {
      // One act() per mutation: batching a whole loop into a single commit
      // would hide exactly the per-tick storm being measured.
      act(() => {
        useHexStore.getState().setCursor(offset);
      });
    }

    // Five cursor moves the component does not read -> zero extra renders.
    expect(counter.count - initial).toBe(0);
  });

  it("re-renders the bookmark reader exactly once when bookmarks change", () => {
    const { counter } = renderWithCount(<BookmarkReader />);
    const initial = counter.count;

    act(() => {
      useHexStore.getState().addBookmark({ offset: 0x10, length: 4, label: "b" });
    });

    expect(counter.count - initial).toBe(1);
  });

  it("does not re-render the single-field scroll reader on cursor mutations", () => {
    const { counter } = renderWithCount(<ScrollReader />);
    const initial = counter.count;

    for (const offset of [16, 32, 48, 64, 80]) {
      act(() => {
        useHexStore.getState().setCursor(offset);
      });
    }
    act(() => {
      useHexStore.getState().setFocusColumn("ascii");
    });

    expect(counter.count - initial).toBe(0);
  });

  it("control: a whole-store destructure re-renders on every cursor move", () => {
    const { counter } = renderWithCount(<WholeStoreReader />);
    const initial = counter.count;

    for (const offset of [16, 32, 48, 64, 80]) {
      // One act() per mutation: batching a whole loop into a single commit
      // would hide exactly the per-tick storm being measured.
      act(() => {
        useHexStore.getState().setCursor(offset);
      });
    }

    // This is the behaviour the sweep removes; if this ever drops to 0 the
    // harness has stopped measuring anything and the assertions above are void.
    expect(counter.count - initial).toBe(5);
  });

  it("mounts the shallow selector without an update-depth loop", () => {
    // A bare object-returning selector under zustand v5 re-renders forever;
    // reaching this assertion at all proves the useShallow wrapper is present.
    expect(() => renderWithCount(<BookmarkReader />)).not.toThrow();
  });
});
