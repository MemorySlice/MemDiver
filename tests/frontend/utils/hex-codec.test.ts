import { describe, it, expect } from "vitest";

import { byteToHex, byteToAscii, offsetToHex, decodeBase64 } from "@/utils/hex-codec";

describe("byteToHex", () => {
  it("pads to two lowercase hex digits", () => {
    expect(byteToHex(0x00)).toBe("00");
    expect(byteToHex(0x0f)).toBe("0f");
    expect(byteToHex(0xa5)).toBe("a5");
    expect(byteToHex(0xff)).toBe("ff");
  });
});

describe("byteToAscii", () => {
  it("returns the printable character for bytes in [0x20, 0x7f)", () => {
    expect(byteToAscii(0x20)).toBe(" ");
    expect(byteToAscii(0x41)).toBe("A");
    expect(byteToAscii(0x7e)).toBe("~");
  });

  it("returns '.' for control and high bytes", () => {
    expect(byteToAscii(0x00)).toBe(".");
    expect(byteToAscii(0x1f)).toBe(".");
    expect(byteToAscii(0x7f)).toBe(".");
    expect(byteToAscii(0xff)).toBe(".");
  });
});

describe("offsetToHex", () => {
  it("formats as 8-digit zero-padded hex", () => {
    expect(offsetToHex(0)).toBe("00000000");
    expect(offsetToHex(255)).toBe("000000ff");
    expect(offsetToHex(0xdeadbeef)).toBe("deadbeef");
  });

  it("does not truncate offsets wider than 8 digits", () => {
    expect(offsetToHex(0x1_0000_0000)).toBe("100000000");
  });
});

describe("decodeBase64", () => {
  it("decodes base64 to the original bytes", () => {
    // "ABC" -> [0x41, 0x42, 0x43]
    expect(Array.from(decodeBase64("QUJD"))).toEqual([0x41, 0x42, 0x43]);
  });

  it("returns an empty Uint8Array for empty input", () => {
    const bytes = decodeBase64("");
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(0);
  });

  it("decodes non-ASCII byte values", () => {
    // 0x00 0xFF 0x80 -> "AP+A"
    expect(Array.from(decodeBase64("AP+A"))).toEqual([0x00, 0xff, 0x80]);
  });
});
