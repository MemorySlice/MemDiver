/**
 * Tests for `useConsensusRun` and `selectionKey` in `@/stores/consensus-store`.
 *
 * FOUR controls could start the same global operation — `HexAlignmentChip`,
 * `OverlayAlignSwitch`, `HexOverlayPane`'s raw-offset banner and
 * `NoConsensusPrompt` — and the first three render SIMULTANEOUSLY in the
 * overlay. With a `useState` each, clicking one left the other two enabled and
 * a second build could be issued over the first, which mints a second
 * `consensus_id` and leaves whichever response lands last describing the grid.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

import { selectionKey, useConsensusRun, useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const PATHS = ["/dumps/a.msl", "/dumps/b.msl"];

/** Two independent consumers of the hook, exactly as the overlay mounts them. */
function TwoButtons({ normalize = true }: { normalize?: boolean }) {
  const one = useConsensusRun();
  const two = useConsensusRun();
  return (
    <>
      <button data-testid="one" disabled={one.running} onClick={() => one.run(PATHS, normalize)}>
        {one.running ? "running" : "run"}
      </button>
      <button data-testid="two" disabled={two.running} onClick={() => two.run(PATHS, normalize)}>
        {two.running ? "running" : "run"}
      </button>
    </>
  );
}

/** Swap `runConsensus` for a spy that never settles unless told to. */
function spyConsensus(impl: () => Promise<void> = () => Promise.resolve()) {
  const runConsensus = vi.fn(impl);
  act(() => {
    useConsensusStore.setState({ runConsensus });
  });
  return runConsensus;
}

afterEach(() => {
  act(() => {
    useConsensusStore.getState().reset();
    useDumpStore.getState().clearAll();
  });
});

describe("useConsensusRun shared in-flight flag", () => {
  it("disables EVERY consumer while one build is running", () => {
    spyConsensus(() => new Promise<void>(() => {}));
    render(<TwoButtons />);

    fireEvent.click(screen.getByTestId("one"));

    expect(screen.getByTestId("one")).toBeDisabled();
    // The bug this replaces: the other affordance stayed live mid-build.
    expect(screen.getByTestId("two")).toBeDisabled();
  });

  it("refuses a second build issued from a different control", () => {
    const runConsensus = spyConsensus(() => new Promise<void>(() => {}));
    render(<TwoButtons />);

    fireEvent.click(screen.getByTestId("one"));
    fireEvent.click(screen.getByTestId("two"));

    expect(runConsensus).toHaveBeenCalledTimes(1);
  });

  it("re-enables every consumer once the build settles", async () => {
    let resolve!: () => void;
    spyConsensus(() => new Promise<void>((r) => (resolve = r)));
    render(<TwoButtons />);

    fireEvent.click(screen.getByTestId("one"));
    expect(screen.getByTestId("two")).toBeDisabled();

    await act(async () => {
      resolve();
    });

    expect(screen.getByTestId("one")).toBeEnabled();
    expect(screen.getByTestId("two")).toBeEnabled();
  });
});

describe("useConsensusRun aslrNormalize nudge", () => {
  it("brings the shared intent along with the coordinate asked for", () => {
    const runConsensus = spyConsensus();
    act(() => {
      useDumpStore.setState({ aslrNormalize: false });
    });
    render(<TwoButtons normalize />);

    fireEvent.click(screen.getByTestId("one"));

    expect(runConsensus).toHaveBeenCalledWith(PATHS, true);
    expect(useDumpStore.getState().aslrNormalize).toBe(true);
  });

  /** It is a TOGGLE, not a setter, so it is nudged only when it disagrees. */
  it("leaves an already-agreeing intent alone", () => {
    spyConsensus();
    act(() => {
      useDumpStore.setState({ aslrNormalize: true });
    });
    render(<TwoButtons normalize />);

    fireEvent.click(screen.getByTestId("one"));

    expect(useDumpStore.getState().aslrNormalize).toBe(true);
  });
});

describe("selectionKey", () => {
  it("is order-insensitive", () => {
    expect(selectionKey(["b", "a"])).toBe(selectionKey(["a", "b"]));
  });

  it("does not mutate the caller's array", () => {
    const paths = ["b", "a"];
    selectionKey(paths);
    expect(paths).toEqual(["b", "a"]);
  });

  it("separates membership, so a different set is a different key", () => {
    expect(selectionKey(["a", "b"])).not.toBe(selectionKey(["a", "c"]));
  });
});
