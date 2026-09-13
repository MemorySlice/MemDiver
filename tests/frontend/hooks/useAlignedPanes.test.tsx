import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { render } from "@testing-library/react";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { useAlignedWindowLoader, useMslPaneCoordinate } = await import(
  "@/hooks/useAlignedPanes"
);

/**
 * `POST /api/analysis/consensus/aligned-window` REFUSES `view="raw"` for an
 * `.msl` anchor, and is right to: `MslDumpSource.va_to_file_offset` resolves to
 * the enclosing BLOCK HEADER's offset, so a peer read in raw coordinates would
 * return real bytes from the wrong address.
 *
 * "raw" is also the hex viewer's DEFAULT view — so without this hook an analyst
 * on the primary file type clicks "Side by side" and gets a per-pane error
 * instead of bytes, on first use. These tests pin the switch, and pin that a
 * raw-format dump (where "raw" is the only meaningful coordinate) is untouched.
 */
function entry(format: DumpEntry["format"]): DumpEntry {
  return {
    id: "d0",
    path: `/dumps/d0.${format}`,
    name: `d0.${format}`,
    size: 4096,
    format,
    sameProcess: true,
  };
}

function Probe({ anchor }: { anchor: DumpEntry | null }) {
  useMslPaneCoordinate(anchor);
  const viewMode = useHexStore((s) => s.viewMode);
  return <div data-testid="view">{viewMode}</div>;
}

function viewAfterMount(anchor: DumpEntry | null): string {
  const { getByTestId } = render(<Probe anchor={anchor} />);
  return getByTestId("view").textContent ?? "";
}

beforeEach(() => {
  useDumpStore.getState().clearAll();
  useHexStore.setState({ viewMode: "raw" });
});

afterEach(() => {
  useConsensusStore.getState().reset();
  useMultiHexStore.getState().reset();
});

describe("useMslPaneCoordinate", () => {
  it("takes an .msl anchor off the raw view when side-by-side mounts", () => {
    useDumpStore.setState({ mainView: "sideBySide" });
    expect(viewAfterMount(entry("msl"))).not.toBe("raw");
  });

  it("takes an .msl anchor off the raw view when the overlay mounts", () => {
    useDumpStore.setState({ mainView: "overlay" });
    expect(viewAfterMount(entry("msl"))).not.toBe("raw");
  });

  it("leaves a raw-format dump in the raw view", () => {
    useDumpStore.setState({ mainView: "sideBySide" });
    expect(viewAfterMount(entry("raw"))).toBe("raw");
  });

  it("leaves the single-dump layout alone", () => {
    useDumpStore.setState({ mainView: "single" });
    expect(viewAfterMount(entry("msl"))).toBe("raw");
  });

  it("does not override a coordinate the analyst already chose", () => {
    useDumpStore.setState({ mainView: "sideBySide" });
    useHexStore.setState({ viewMode: "va" });
    expect(viewAfterMount(entry("msl"))).toBe("va");
  });
});

/**
 * THE fence: nothing goes on the wire without a consensus that describes THIS
 * selection.
 *
 * `HexOverlayPane`'s render guard looks like it covers this, but only by
 * accident — this hook runs BEFORE that early return and is saved solely
 * because the scroll element never mounts, so `firstVisibleIndex === -1`. Any
 * virtualizer change turns that accident into a request storm asking a build
 * made over other dumps for a window it cannot describe. These tests pin the
 * explicit guard instead, at the seam where the requests are actually issued.
 */
function loaderEntry(i: number): DumpEntry {
  return {
    id: `d${i}`,
    // A raw dump: `useMslViewSizes` resolves it immediately, so nothing but
    // the consensus guard can be the reason a request is or is not made.
    path: `/dumps/d${i}.bin`,
    name: `d${i}.bin`,
    size: 64 * 1024,
    format: "raw",
    sameProcess: true,
  };
}

function LoaderProbe({ paths }: { paths: string[] }) {
  useAlignedWindowLoader({
    anchor: loaderEntry(0),
    paths,
    firstRow: 0,
    lastRow: 8,
  });
  return null;
}

/** Render the loader over `paths` and report every aligned-window request. */
function requestsFor(paths: string[]): unknown[] {
  const ensureLoaded = vi.fn();
  useMultiHexStore.setState({ ensureLoaded });
  useHexStore.setState({
    dumpPath: paths[0],
    fileSize: 64 * 1024,
    format: "raw",
    ensureChunksLoaded: vi.fn(),
  });
  render(<LoaderProbe paths={paths} />);
  return ensureLoaded.mock.calls;
}

describe("useAlignedWindowLoader consensus fence", () => {
  const A = "/dumps/d0.bin";
  const B = "/dumps/d1.bin";
  const C = "/dumps/d2.bin";

  it("issues no request at all when there is no consensus", () => {
    useConsensusStore.setState({ consensusId: null, builtFrom: [] });
    expect(requestsFor([A, B])).toHaveLength(0);
  });

  it("issues no request when the consensus was built over other dumps", () => {
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [A, B] });
    expect(requestsFor([A, C])).toHaveLength(0);
  });

  it("loads once the consensus describes the selection", () => {
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [A, B] });
    expect(requestsFor([A, B]).length).toBeGreaterThan(0);
  });

  it("still loads for a build that cannot name its dumps", () => {
    // An incremental fold records no paths; "unknown" must not read as
    // "mismatch" or Finalize would leave the viewer permanently empty.
    useConsensusStore.setState({ consensusId: "session-1", builtFrom: [] });
    expect(requestsFor([A, B]).length).toBeGreaterThan(0);
  });

  it("ignores the order the selection happens to be in", () => {
    useConsensusStore.setState({ consensusId: "c1", builtFrom: [B, A] });
    expect(requestsFor([A, B]).length).toBeGreaterThan(0);
  });
});
