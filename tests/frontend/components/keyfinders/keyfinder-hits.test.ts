import { describe, expect, it } from "vitest";

import { hexOffsetOf, keySpanOf, scanAddressOf } from "@/components/keyfinders/keyfinder-hits";
import type { KeyHitRow } from "@/api/keyfinders";

describe("keyfinder-hits coordinates", () => {
  it("rebases va addresses by the span start and leaves vas/raw alone", () => {
    expect(hexOffsetOf(0x1040, "va", 0x1000)).toBe(0x40);
    expect(hexOffsetOf(0x40, "vas", 0x1000)).toBe(0x40);
    expect(scanAddressOf(0x40, "va", 0x1000)).toBe(0x1040);
  });

  it("refuses an address that is inexact or below the span", () => {
    expect(hexOffsetOf(2 ** 60, "va", 0)).toBeNull();
    expect(hexOffsetOf(0x10, "va", 0x1000)).toBeNull();
  });

  it("uses key_offset + key_bits as the key span, else the whole hit", () => {
    const base = { addr: 100, length: 176, metadata: {} } as unknown as KeyHitRow;
    expect(keySpanOf({ ...base, metadata: { key_offset: 108, key_bits: 256 } })).toEqual({ addr: 108, length: 32 });
    expect(keySpanOf(base)).toEqual({ addr: 100, length: 176 });
  });
});
