/**
 * Turning what an analyst TYPED into the bytes to search for.
 *
 * The TS half of a contract written twice. `core/needle.py` does the real
 * parse — it is what actually runs against the dump — but the search box has
 * to show the resolved bytes AS YOU TYPE, and a round trip per keystroke is
 * not an option. So the rules live here as well.
 *
 * `tests/fixtures/needle_vectors.json` is what stops the two drifting: the
 * same table is replayed by `tests/test_needle.py` and by
 * `tests/frontend/utils/needle.test.ts`. A divergence fails a test instead of
 * shipping a preview that disagrees with the search it just ran — which would
 * be worse than no preview at all, because the whole point of the preview is
 * that the user can trust it.
 *
 * WHY `auto` RESOLVES TO HEX. `dead`, `cafe` and `face` are valid hex AND
 * valid words. No reading is right every time, so `auto` keeps what the box
 * has always done — pure hex input is hex — and the ambiguity is SURFACED by
 * `plausibleAlternatives` rather than guessed at. A wrong guess you can see
 * costs one click.
 *
 * WHY base64 AND THE INTEGERS ARE NEVER AUTO-DETECTED. Their character sets
 * overlap ordinary text completely, so auto-detecting them would make `auto`
 * unpredictable — the one thing it must not be. They stay one click away.
 */

import { isHex, normalizeHex } from "@/utils/hex";

export const NEEDLE_FORMATS = [
  "auto",
  "hex",
  "text",
  "utf16le",
  "base64",
  "u32le",
  "u32be",
  "u64le",
  "u64be",
] as const;

export type NeedleFormat = (typeof NEEDLE_FORMATS)[number];

/** Everything `detectFormat` may return — every format except `auto`. */
export type ConcreteNeedleFormat = Exclude<NeedleFormat, "auto">;

/** `{format: [byte width, littleEndian]}` for the fixed-width integers. */
const INT_FORMATS: Record<string, [number, boolean]> = {
  u32le: [4, true],
  u32be: [4, false],
  u64le: [8, true],
  u64be: [8, false],
};

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Shortest input worth offering as base64.
 *
 * Short words are far too easy to read as base64 by accident (`dead` decodes
 * to three bytes), so a lower bound would make the hint fire constantly and
 * mean nothing.
 */
const BASE64_HINT_MIN_CHARS = 16;

/** Thrown for anything the user can fix by typing something else. */
export class NeedleError extends Error {}

/** Is this an unambiguous, WHOLE-byte hex string? */
export function looksLikeHex(text: string): boolean {
  const cleaned = normalizeHex(text);
  return cleaned.length >= 2 && cleaned.length % 2 === 0 && isHex(cleaned);
}

/** Could this be a base64 blob worth OFFERING? Never a decision, only a hint. */
export function looksLikeBase64(text: string): boolean {
  const cleaned = text.replace(/\s+/g, "");
  return (
    cleaned.length >= BASE64_HINT_MIN_CHARS &&
    cleaned.length % 4 === 0 &&
    BASE64_RE.test(cleaned)
  );
}

/** Resolve `auto` to a concrete format: hex when unambiguous, else text. */
export function detectFormat(text: string): ConcreteNeedleFormat {
  if (!text.trim()) throw new NeedleError("Empty byte pattern");
  return looksLikeHex(text) ? "hex" : "text";
}

/**
 * Other readings of `text`, best first — the "also valid as …" hint.
 *
 * Never includes the format already in effect: echoing the current reading
 * back is noise, and noise trains people to ignore the hint that matters.
 */
export function plausibleAlternatives(text: string): ConcreteNeedleFormat[] {
  if (!text.trim()) return [];
  const resolved = detectFormat(text);
  const out: ConcreteNeedleFormat[] = [];
  if (resolved !== "hex" && looksLikeHex(text)) out.push("hex");
  if (resolved !== "text") out.push("text");
  if (looksLikeBase64(text)) out.push("base64");
  return out;
}

/**
 * Parse typed text into the bytes that will be searched for.
 *
 * @throws NeedleError with a message meant for the user, not a console.
 */
export function parseNeedle(text: string, fmt: NeedleFormat = "hex"): Uint8Array {
  if (!text.trim()) throw new NeedleError("Empty byte pattern");
  const resolved = fmt === "auto" ? detectFormat(text) : fmt;
  const bytes = decode(text, resolved);
  if (bytes.length === 0) {
    // An empty needle is not a query: the scan returns no hits for one (it
    // must -- an empty needle makes an mmap search loop forever), so letting
    // it through would report a confident "0 hits" for something that was
    // never searchable.
    throw new NeedleError(`Empty byte pattern after decoding as ${resolved}`);
  }
  return bytes;
}

function decode(text: string, fmt: ConcreteNeedleFormat): Uint8Array {
  if (fmt === "hex") {
    const cleaned = normalizeHex(text);
    if (!cleaned) throw new NeedleError("Empty byte pattern");
    if (!isHex(cleaned)) {
      throw new NeedleError(`Invalid hex byte pattern: ${text}`);
    }
    if (cleaned.length % 2 !== 0) {
      throw new NeedleError(
        `Invalid hex byte pattern: ${text} (odd number of hex digits — a byte needs two)`,
      );
    }
    const out = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  if (fmt === "text") return new TextEncoder().encode(text);

  if (fmt === "utf16le") {
    // No BOM: a needle is a fragment to find INSIDE a buffer, so a BOM would
    // only ever match a string the process happened to store with one -- i.e.
    // it would make the common case fail.
    const out = new Uint8Array(text.length * 2);
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      out[i * 2] = code & 0xff;
      out[i * 2 + 1] = code >> 8;
    }
    return out;
  }

  if (fmt === "base64") {
    const cleaned = text.replace(/\s+/g, "");
    if (!BASE64_RE.test(cleaned) || cleaned.length % 4 !== 0) {
      throw new NeedleError(`Invalid base64 pattern: ${text}`);
    }
    try {
      const binary = atob(cleaned);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    } catch {
      throw new NeedleError(`Invalid base64 pattern: ${text}`);
    }
  }

  const [width, littleEndian] = INT_FORMATS[fmt];
  const value = parseIntegerLiteral(text.trim());
  if (value < 0n) {
    throw new NeedleError(`Integer pattern must not be negative: ${text}`);
  }
  if (value >= 1n << BigInt(width * 8)) {
    throw new NeedleError(
      `Integer pattern ${text.trim()} does not fit in ${width} bytes (${fmt})`,
    );
  }
  const out = new Uint8Array(width);
  let rest = value;
  for (let i = 0; i < width; i++) {
    const byte = Number(rest & 0xffn);
    out[littleEndian ? i : width - 1 - i] = byte;
    rest >>= 8n;
  }
  return out;
}

/**
 * `BigInt` so a u64 keeps every bit.
 *
 * `Number` loses precision above 2^53, which is inside the range a u64 pointer
 * search routinely uses — the needle would be silently wrong in its low bytes.
 * Accepts the same spellings Python's `int(x, 0)` does, because an analyst
 * reads a pointer off one pane as hex and a length off another as decimal.
 */
function parseIntegerLiteral(text: string): bigint {
  const negative = text.startsWith("-");
  const body = negative ? text.slice(1) : text;
  if (!/^(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d+)$/.test(body)) {
    throw new NeedleError(`Invalid integer pattern: ${text}`);
  }
  try {
    const value = BigInt(body);
    return negative ? -value : value;
  } catch {
    throw new NeedleError(`Invalid integer pattern: ${text}`);
  }
}

/** `de ad be ef` — the spelling the byte inspector and the legend already use. */
export function previewHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");
}
