import { beforeEach, describe, expect, it } from "vitest";

import { isLocationNavigable, openLocationInHex } from "@/components/agent/open-location";
import { reduceChatEvent, EMPTY_CHAT } from "@/stores/agent-reducer";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

describe("agent chat locations", () => {
  beforeEach(() => {
    useDumpStore.setState({ dumps: [{ id: "d1", path: "/d.msl" } as never], activeDumpId: "d1" });
  });

  it("only an offset in a hex-viewable view is navigable; a bare va is not", () => {
    expect(isLocationNavigable({ dump_path: "/d.msl", offset: 4 })).toBe(true);
    expect(isLocationNavigable({ dump_path: "/d.msl", offset: 4, view: "va" })).toBe(true);
    expect(isLocationNavigable({ dump_path: "/d.msl", offset: 4, view: "vas" })).toBe(false);
    expect(isLocationNavigable({ dump_path: "/d.msl", va: 0x7f000000 })).toBe(false);
  });

  it("never jumps for a va-only location, and keeps the view of an offset", () => {
    expect(openLocationInHex({ dump_path: "/d.msl", va: 0x7f000000 })).toBe(false);
    expect(openLocationInHex({ dump_path: "/d.msl", offset: 4096, view: "va" })).toBe(true);
    // no view list is known yet in a unit test, so the request is parked until the probe lands
    expect(useHexStore.getState().requestedView).toBe("va");
  });

  it("the reducer keeps the view of a location", () => {
    const v = reduceChatEvent(
      reduceChatEvent(EMPTY_CHAT, { type: "tool_call", id: "a", name: "t", input: {}, access: "read" }),
      { type: "tool_result", id: "a", ok: true, summary: "", bytes: 1, truncated: false,
        locations: [{ dump_path: "/d", offset: 1, view: "va" }] });
    expect((v.items[0] as { result: { locations: unknown[] } }).result.locations)
      .toEqual([{ dump_path: "/d", offset: 1, view: "va" }]);
  });
});
