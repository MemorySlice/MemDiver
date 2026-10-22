import { describe, it, expect } from "vitest";
import { resolveRequestView } from "@/components/verification/request-view";

describe("resolveRequestView", () => {
  const base = { typedOffset: false, prefillFromViewer: false, hasDistinctViews: false, viewMode: "vas" as const };

  it("sends the viewer view for a cursor/selection prefill, even on a single-view dump", () => {
    expect(resolveRequestView({ ...base, prefillFromViewer: true })).toBe("vas");
  });

  it("sends the viewer view for a typed offset on a multi-view dump", () => {
    expect(resolveRequestView({ ...base, typedOffset: true, prefillFromViewer: true, hasDistinctViews: true })).toBe("vas");
  });

  it("sends no view for a typed offset on a single-view dump", () => {
    expect(resolveRequestView({ ...base, typedOffset: true, prefillFromViewer: true })).toBeUndefined();
  });

  it("sends the viewer view for the default offset on a multi-view dump", () => {
    expect(resolveRequestView({ ...base, hasDistinctViews: true, viewMode: "raw" })).toBe("raw");
  });

  it("sends no view for the default offset on a single-view dump", () => {
    expect(resolveRequestView(base)).toBeUndefined();
  });
});
