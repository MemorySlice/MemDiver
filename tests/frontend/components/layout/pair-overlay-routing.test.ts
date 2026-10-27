import { describe, expect, it } from "vitest";
import { pairOverlayKind } from "@/components/layout/pair-overlay-routing";

const raw = (n: string) => ({ path: `/d/${n}.raw`, format: "raw" });
const msl = (n: string) => ({ path: `/d/${n}.msl`, format: "msl" });

describe("pairOverlayKind", () => {
  it("routes an msl pair to the aligned pane", () => {
    expect(pairOverlayKind(msl("a"), msl("b"))).toBe("aligned");
  });
  it("routes a mixed pair to the aligned pane", () => {
    expect(pairOverlayKind(raw("a"), msl("b"))).toBe("aligned");
    expect(pairOverlayKind(msl("a"), raw("b"))).toBe("aligned");
  });
  it("routes an mdview to the aligned pane even though its format is raw", () => {
    expect(pairOverlayKind(raw("a"), { path: "/d/x.MDVIEW", format: "raw" })).toBe("aligned");
  });
  it("keeps raw pairs on the file-offset overlay", () => {
    expect(pairOverlayKind(raw("a"), raw("b"))).toBe("raw");
  });
});
