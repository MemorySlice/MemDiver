import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { HexRow } from "@/components/hex/HexRow";
import { buildRegionIndex } from "@/components/hex/highlight-utils";

/**
 * The offset gutter prints an absolute virtual address in the "va" coordinate
 * when the caller hands it a server-given base, and stays view-relative
 * otherwise. Display only: the reads still use the relative offset.
 */
function gutterOf(extra: Partial<React.ComponentProps<typeof HexRow>> = {}) {
  const { container } = render(
    <HexRow
      rowOffset={0x20}
      getByteAt={() => 0}
      cursorOffset={null}
      selectionStart={null}
      selectionEnd={null}
      regionIndex={buildRegionIndex([])}
      {...extra}
    />,
  );
  return container.querySelector(".hex-offset") as HTMLElement;
}

describe("HexRow offset gutter", () => {
  it("stays relative and untitled by default", () => {
    const g = gutterOf();
    expect(g).toHaveTextContent("00000020");
    expect(g).not.toHaveAttribute("title");
    expect(g.style.width).toBe("");
  });

  it("prints base + row offset with a virtual-address tooltip", () => {
    const g = gutterOf({ offsetBase: 0x1000, addressDigits: 8 });
    expect(g).toHaveTextContent("00001020");
    expect(g).toHaveAttribute("title", "Virtual address");
  });

  it("widens the gutter for addresses above 32 bits", () => {
    const g = gutterOf({ offsetBase: 0x7f0000000000, addressDigits: 12 });
    expect(g).toHaveTextContent("7f0000000020");
    expect(g.style.width).toBe("108px");
  });

  it("uses 16 digits when asked", () => {
    const g = gutterOf({ offsetBase: 0x1000000000000, addressDigits: 16 });
    expect(g).toHaveTextContent("0001000000000020");
    expect(g.style.width).toBe("140px");
  });

  it("falls back to the relative label for an unsafe integer sum", () => {
    const g = gutterOf({ offsetBase: Number.MAX_SAFE_INTEGER, addressDigits: 16 });
    expect(g).toHaveTextContent("0000000000000020");
    expect(g).not.toHaveAttribute("title");
  });
});
