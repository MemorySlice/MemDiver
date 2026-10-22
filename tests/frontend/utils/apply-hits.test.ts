import { describe, it, expect, beforeEach, vi } from "vitest";

import { applyHitsToStores, hitOffsetView } from "@/utils/apply-hits";
import { useHexStore } from "@/stores/hex-store";
import type { SecretHit } from "@/api/types";

vi.mock("@/api/client", () => ({
  getPageStates: vi.fn(() => new Promise(() => {})),
}));

function hit(offset: number): SecretHit {
  return {
    secret_type: "user_regex",
    offset,
    length: 15,
    dump_path: "/dumps/planted.core",
    library: "planted.core",
    phase: "file",
    run_id: 0,
    confidence: 1,
  } as SecretHit;
}

beforeEach(() => {
  localStorage.clear();
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath("/dumps/planted.core", 8320, "raw");
});

describe("hitOffsetView", () => {
  it("reads a known view from library metadata", () => {
    expect(hitOffsetView({ offset_view: "vas" })).toBe("vas");
    expect(hitOffsetView({ offset_view: "raw" })).toBe("raw");
  });

  it("is undefined when the report does not say or says nonsense", () => {
    expect(hitOffsetView(undefined)).toBeUndefined();
    expect(hitOffsetView({})).toBeUndefined();
    expect(hitOffsetView({ offset_view: "bogus" })).toBeUndefined();
  });
});

describe("applyHitsToStores view alignment", () => {
  it("tags highlights with the hit view and switches a multi-view dump to it", () => {
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    applyHitsToStores({
      libraries: [{ hits: [hit(4352)], metadata: { offset_view: "vas" } }],
    });
    const s = useHexStore.getState();
    expect(s.viewMode).toBe("vas");
    expect(s.highlightedRegions).toEqual([
      expect.objectContaining({ offset: 4352, length: 15, view: "vas" }),
    ]);
  });

  it("keeps a flat dump in its view", () => {
    useHexStore.getState().setAvailableViews(["raw"], "raw");
    applyHitsToStores({
      libraries: [{ hits: [hit(300)], metadata: { offset_view: "raw" } }],
    });
    expect(useHexStore.getState().viewMode).toBe("raw");
    expect(useHexStore.getState().highlightedRegions[0].offset).toBe(300);
  });

  it("leaves untagged hits (no offset_view) in the current view", () => {
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    applyHitsToStores({ libraries: [{ hits: [hit(10)] }] });
    expect(useHexStore.getState().viewMode).toBe("raw");
    expect(useHexStore.getState().highlightedRegions[0].view).toBeUndefined();
  });

  it("defers the switch until the views are probed", () => {
    applyHitsToStores({
      libraries: [{ hits: [hit(4352)], metadata: { offset_view: "vas" } }],
    });
    expect(useHexStore.getState().viewMode).toBe("raw");
    useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
    expect(useHexStore.getState().viewMode).toBe("vas");
  });
});
