/**
 * `utils/needle` — the TS half of a contract written twice.
 *
 * `core/needle.py` does the real parse, but the search box previews the
 * resolved bytes as you type, so the rules exist in both languages. The tables
 * replayed here are the SAME FILE `tests/test_needle.py` replays
 * (`tests/fixtures/needle_vectors.json`), which is the only thing that turns a
 * drift between the two into a failing test instead of a preview that
 * disagrees with the search it just ran.
 *
 * If you add a case, add it to the JSON — not to this file — so both suites
 * gain it at once.
 */

import { describe, expect, it } from "vitest";

// Imported, not read off disk: Vite resolves and inlines the JSON, so the
// table travels with the module graph instead of depending on what the
// process cwd happens to be when vitest runs.
import VECTORS from "../../fixtures/needle_vectors.json";

import {
  NeedleError,
  detectFormat,
  looksLikeBase64,
  looksLikeHex,
  parseNeedle,
  plausibleAlternatives,
  previewHex,
  type NeedleFormat,
} from "@/utils/needle";

interface ParseCase { input: string; format: NeedleFormat; expect_hex: string }
interface DetectCase { input: string; expect: string }
interface AltCase { input: string; expect: string[] }
interface InvalidCase { input: string; format: NeedleFormat; why: string }

const TABLE = VECTORS as unknown as {
  parse: ParseCase[];
  detect: DetectCase[];
  alternatives: AltCase[];
  invalid: InvalidCase[];
};

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("the shared vector table", () => {
  it("has actually been loaded (a silent empty table would pass everything)", () => {
    expect(TABLE.parse.length).toBeGreaterThan(15);
    expect(TABLE.detect.length).toBeGreaterThan(8);
    expect(TABLE.invalid.length).toBeGreaterThan(5);
  });

  it.each(TABLE.parse)("parses $input as $format", (c) => {
    expect(hex(parseNeedle(c.input, c.format))).toBe(c.expect_hex);
  });

  it.each(TABLE.detect)("auto-detects $input", (c) => {
    expect(detectFormat(c.input)).toBe(c.expect);
  });

  it.each(TABLE.alternatives)("offers alternatives for $input", (c) => {
    expect(plausibleAlternatives(c.input)).toEqual(c.expect);
  });

  it.each(TABLE.invalid)("refuses $input as $format ($why)", (c) => {
    expect(() => parseNeedle(c.input, c.format)).toThrow(NeedleError);
  });
});

describe("auto-detection surfaces ambiguity instead of guessing", () => {
  it.each(["dead", "cafe", "face", "beef", "decade"])(
    "%s is a word AND a byte run: hex wins, text is offered",
    (word) => {
      expect(detectFormat(word)).toBe("hex");
      expect(plausibleAlternatives(word)).toContain("text");
    },
  );

  it("never offers the reading already in effect", () => {
    for (const t of ["dead", "password", "aGVsbG8gd29ybGQxMjM0", "deadbeef"]) {
      expect(plausibleAlternatives(t)).not.toContain(detectFormat(t));
    }
  });

  it("never auto-detects base64 — only offers it", () => {
    const blob = "aGVsbG8gd29ybGQxMjM0";
    expect(detectFormat(blob)).toBe("text");
    expect(plausibleAlternatives(blob)).toContain("base64");
  });

  it("has no alternatives for blank input, and refuses to detect it", () => {
    expect(plausibleAlternatives("   ")).toEqual([]);
    expect(() => detectFormat("   ")).toThrow(NeedleError);
  });
});

describe("hex spellings", () => {
  it.each([
    "deadbeef", "0xdeadbeef", "0XDEADBEEF", "DEADBEEF",
    "de ad be ef", " deadbeef ", "dead beef",
  ])("%s is the same four bytes", (spelling) => {
    expect(hex(parseNeedle(spelling, "hex"))).toBe("deadbeef");
  });

  it("says WHY an odd digit count is wrong", () => {
    expect(() => parseNeedle("dea", "hex")).toThrow(/odd number of hex digits/);
  });

  it("agrees with its own predicates", () => {
    expect(looksLikeHex("0xdead")).toBe(true);
    expect(looksLikeHex("dea")).toBe(false);   // odd -> half a byte
    expect(looksLikeHex("d")).toBe(false);     // too short to be a byte
    expect(looksLikeHex("nothex")).toBe(false);
    expect(looksLikeBase64("aGVsbG8gd29ybGQxMjM0")).toBe(true);
    expect(looksLikeBase64("dead")).toBe(false); // too short to be worth offering
  });
});

describe("integers keep every bit", () => {
  it("does not lose precision above 2^53, where Number would", () => {
    // A real u64 pointer. Through `Number` the low bytes come back wrong, and
    // the needle would be silently, undetectably incorrect.
    expect(hex(parseNeedle("0x7fffffffffffffff", "u64be")))
      .toBe("7fffffffffffffff");
    expect(hex(parseNeedle("0x123456789abcdef1", "u64le")))
      .toBe("f1debc9a78563412");
  });

  it("differs from big-endian only by byte order", () => {
    expect(Array.from(parseNeedle("0x7f9c1234", "u32le")))
      .toEqual(Array.from(parseNeedle("0x7f9c1234", "u32be")).reverse());
  });

  it("refuses a value too wide for the format", () => {
    expect(() => parseNeedle("0x1FFFFFFFF", "u32le"))
      .toThrow(/does not fit in 4 bytes/);
  });

  it("accepts decimal and prefixed spellings alike", () => {
    expect(hex(parseNeedle("0x10", "u32be"))).toBe(hex(parseNeedle("16", "u32be")));
  });
});

describe("empty needles are refused where the user can still see why", () => {
  it.each<[string, NeedleFormat]>([
    ["", "hex"], ["   ", "hex"], ["", "text"], ["  ", "auto"], ["", "base64"],
  ])("refuses %j as %s", (text, fmt) => {
    // The scan returns no hits for an empty needle (it must -- an empty needle
    // makes an mmap search loop forever), so letting one through would report
    // a confident "0 hits" for a query that was never searchable.
    expect(() => parseNeedle(text, fmt)).toThrow(/[Ee]mpty byte pattern/);
  });
});

describe("previewHex", () => {
  it("uses the spelling the byte inspector already uses", () => {
    expect(previewHex(new Uint8Array([0xde, 0xad, 0x00, 0x0f])))
      .toBe("de ad 00 0f");
    expect(previewHex(new Uint8Array())).toBe("");
  });
});
