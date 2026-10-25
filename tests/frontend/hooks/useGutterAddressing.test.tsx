import { beforeEach, describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";

import {
  gutterAddressing,
  useAlignedGutterAddressing,
  useSingleGutterAddressing,
} from "@/hooks/useGutterAddressing";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

const RELATIVE = { offsetBase: null, addressDigits: 8 };

beforeEach(() => {
  useHexStore.getState().reset();
  useMultiHexStore.getState().reset();
});

describe("gutterAddressing", () => {
  it("is relative outside the va view", () => {
    expect(gutterAddressing("vas", 0x1000, 64)).toEqual(RELATIVE);
    expect(gutterAddressing("raw", 0x1000, 64)).toEqual(RELATIVE);
  });

  it("is relative without a base", () => {
    expect(gutterAddressing("va", null, 64)).toEqual(RELATIVE);
  });

  it("widens with the highest address", () => {
    expect(gutterAddressing("va", 0x1000, 64)).toEqual({ offsetBase: 0x1000, addressDigits: 8 });
    expect(gutterAddressing("va", 0x7f0000000000, 64).addressDigits).toBe(12);
  });
});

describe("useSingleGutterAddressing", () => {
  it("uses vaSpanStart only once page states are loaded in va", () => {
    useHexStore.setState({ viewMode: "va", vaSpanStart: 0x5605_6590_c000, fileSize: 4096 });
    expect(renderHook(() => useSingleGutterAddressing()).result.current).toEqual(RELATIVE);

    useHexStore.setState({ pageStatesLoaded: true });
    expect(renderHook(() => useSingleGutterAddressing()).result.current).toEqual({
      offsetBase: 0x5605_6590_c000,
      addressDigits: 12,
    });

    useHexStore.setState({ viewMode: "vas" });
    expect(renderHook(() => useSingleGutterAddressing()).result.current).toEqual(RELATIVE);
  });
});

describe("useAlignedGutterAddressing", () => {
  it("uses the server-given anchor base for the live identity only", () => {
    useHexStore.setState({ viewMode: "va", fileSize: 4096 });
    useMultiHexStore.setState({
      identity: "live",
      anchorVaLabel: { identity: "live", spanStart: 0x7f00_0000_0000 },
    });
    expect(renderHook(() => useAlignedGutterAddressing()).result.current).toEqual({
      offsetBase: 0x7f00_0000_0000,
      addressDigits: 12,
    });

    useMultiHexStore.setState({ identity: "next" });
    expect(renderHook(() => useAlignedGutterAddressing()).result.current).toEqual(RELATIVE);
  });
});
