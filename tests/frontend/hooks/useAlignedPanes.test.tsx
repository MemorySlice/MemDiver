import { beforeEach, describe, it, expect, vi } from "vitest";
import { render } from "@testing-library/react";

import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

vi.mock("@/api/client", () => ({
  getPathInfo: vi.fn(() => new Promise(() => {})),
  getTagStatus: vi.fn(() => new Promise(() => {})),
  probeTagStatusWithKey: vi.fn(() => new Promise(() => {})),
}));

const { useMslPaneCoordinate } = await import("@/hooks/useAlignedPanes");

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
