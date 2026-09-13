/**
 * Tests for `useConsensusUsable` and `useOverlayComposition`
 * (`@/hooks/useAlignedPanes`).
 *
 * Both are extractions of a question that was being answered in several places
 * at once. `useConsensusUsable` was derived three times, and the copies had
 * already diverged over which path list they read. `useOverlayComposition` was
 * derived twice — by the pane that OWNS the grid and by the bar that CAPTIONS
 * it — each with its own solo resolution, its own included-paths expression and
 * its own hardcoded default weight, while both files carried a comment saying
 * the two must not disagree.
 */

import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { render, screen, act } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { useConsensusUsable, useOverlayComposition } = await import("@/hooks/useAlignedPanes");

const A = "/dumps/a.msl";
const B = "/dumps/b.msl";
const C = "/dumps/c.msl";

function entry(path: string): DumpEntry {
  return {
    id: path,
    path,
    name: path.split("/").pop()!,
    size: 4096,
    format: "msl",
    sameProcess: true,
  };
}

const SELECTED = [entry(A), entry(B), entry(C)];

function UsableProbe({ paths }: { paths: string[] }) {
  return <div data-testid="usable">{String(useConsensusUsable(paths))}</div>;
}

function CompositionProbe() {
  const { soloPath, soloDump, includedPaths, weightFor } = useOverlayComposition(SELECTED);
  return (
    <>
      <div data-testid="solo">{soloPath ?? "none"}</div>
      <div data-testid="solo-name">{soloDump?.name ?? "none"}</div>
      <div data-testid="included">{includedPaths.join(",")}</div>
      <div data-testid="weights">{SELECTED.map((d) => weightFor(d.path)).join(",")}</div>
    </>
  );
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  useDumpRailStore.getState().reset();
  useConsensusStore.getState().reset();
});

afterEach(() => {
  useDumpRailStore.getState().reset();
  useConsensusStore.getState().reset();
});

describe("useConsensusUsable", () => {
  it("is false with no build at all", () => {
    render(<UsableProbe paths={[A, B]} />);

    expect(screen.getByTestId("usable")).toHaveTextContent("false");
  });

  it("is true for a build over exactly these dumps, in any order", () => {
    act(() => {
      useConsensusStore.setState({ consensusId: "c1", builtFrom: [B, A] });
    });
    render(<UsableProbe paths={[A, B]} />);

    expect(screen.getByTestId("usable")).toHaveTextContent("true");
  });

  /**
   * The failure this fence exists for: the server answers, the panes paint, and
   * every class, gap and "Differs" ring is a confident statement about bytes
   * nobody is looking at.
   */
  it("is false for a build over a DIFFERENT set", () => {
    act(() => {
      useConsensusStore.setState({ consensusId: "c1", builtFrom: [A, C] });
    });
    render(<UsableProbe paths={[A, B]} />);

    expect(screen.getByTestId("usable")).toHaveTextContent("false");
  });

  /** Unknown is not the same as wrong — an incremental fold reports no paths. */
  it("is permissive when the build cannot say what it covers", () => {
    act(() => {
      useConsensusStore.setState({ consensusId: "inc-1", builtFrom: [] });
    });
    render(<UsableProbe paths={[A, B]} />);

    expect(screen.getByTestId("usable")).toHaveTextContent("true");
  });
});

describe("useOverlayComposition", () => {
  it("includes every selected dump by default, at the default weight", () => {
    render(<CompositionProbe />);

    expect(screen.getByTestId("included")).toHaveTextContent(`${A},${B},${C}`);
    expect(screen.getByTestId("weights")).toHaveTextContent("1,1,1");
    expect(screen.getByTestId("solo")).toHaveTextContent("none");
  });

  it("drops an excluded dump from the plurality without refetching anything", () => {
    act(() => {
      useDumpRailStore.getState().toggleIncluded(B);
    });
    render(<CompositionProbe />);

    expect(screen.getByTestId("included")).toHaveTextContent(`${A},${C}`);
  });

  it("reports a rail weight rather than the default", () => {
    act(() => {
      useDumpRailStore.getState().setWeight(B, 1.5);
    });
    render(<CompositionProbe />);

    expect(screen.getByTestId("weights")).toHaveTextContent("1,1.5,1");
  });

  it("resolves a solo to both its path and its entry", () => {
    act(() => {
      useDumpRailStore.setState({ soloPath: B });
    });
    render(<CompositionProbe />);

    expect(screen.getByTestId("solo")).toHaveTextContent(B);
    expect(screen.getByTestId("solo-name")).toHaveTextContent("b.msl");
  });

  /**
   * A solo left over from a PREVIOUS selection names a dump that is no longer
   * aligned; reading its bytes would paint a stream nothing on screen describes.
   */
  it("reads a stale solo as no solo at all", () => {
    act(() => {
      useDumpRailStore.setState({ soloPath: "/dumps/gone.msl" });
    });
    render(<CompositionProbe />);

    expect(screen.getByTestId("solo")).toHaveTextContent("none");
    expect(screen.getByTestId("solo-name")).toHaveTextContent("none");
  });
});
