import { ApiError } from "./client";

/** Marks a cell whose JSON integer would not survive `JSON.parse` as a Number. */
const UNSAFE_INT = /^-?\d{16,}$/;

/**
 * Parse a JSON body keeping every integer literal beyond 2^53 as a DECIMAL STRING.
 *
 * Kernel virtual addresses (`0xffff88...`) exceed 2^53, and `JSON.parse` would
 * round them silently — a forensic tool must never show an address whose low
 * bits were invented. Strings are skipped so only real number tokens convert.
 */
export function parseJsonLossless(text: string): unknown {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "-" || (ch >= "0" && ch <= "9")) {
      const token = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i))![0];
      out += UNSAFE_INT.test(token) ? `"${token}"` : token;
      i += token.length;
    } else {
      out += ch;
      i += 1;
    }
  }
  return JSON.parse(out);
}

/** An integer field after {@link parseJsonLossless}: a Number, or a decimal STRING past 2^53. */
export type WireInt = number | string;

/** The exact value of a {@link WireInt}, or `null` (absent, non-integer, or already rounded). */
export function wireIntToBigInt(v: unknown): bigint | null {
  if (typeof v === "number") return Number.isSafeInteger(v) ? BigInt(v) : null;
  if (typeof v === "string" && /^-?\d+$/.test(v)) return BigInt(v);
  return null;
}

/** `0x...` text of a {@link WireInt} (exact for a kernel VA), or `?` when it cannot be read exactly. */
export function wireIntHex(v: unknown, pad = 0): string {
  const exact = wireIntToBigInt(v);
  return exact === null ? "?" : `0x${exact.toString(16).padStart(pad, "0")}`;
}

/** `v - base` as a safe Number, or `null` when inexact or outside `[0, 2^53)`. */
export function wireIntOffset(v: unknown, base = 0): number | null {
  const exact = wireIntToBigInt(v);
  if (exact === null) return null;
  const off = exact - BigInt(base);
  return off >= 0n && off <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(off) : null;
}

/** A hit's place in the hex viewer: its offset, and the view that offset is in. */
export interface HexPlace {
  view: "va" | "vas" | "raw";
  offset: number;
}

/**
 * Where a server row (`addr` in `scanView`, plus the server-computed `vas_offset`)
 * lands in the viewer. A `va` address is rebased only while BOTH it and the span
 * start are exact; a kernel VA (past 2^53, or over a rounded span start) is placed
 * by the server's own `vas_offset` in the `vas` view instead — the client never
 * computes a coordinate from a rounded number.
 */
export function placeRow(
  row: { addr: WireInt; vas_offset?: number },
  scanView: string,
  vaSpanStart: number,
  availableViews: readonly string[] | null = null,
): HexPlace | null {
  const view = scanView === "va" || scanView === "vas" || scanView === "raw" ? scanView : "raw";
  const base = view === "va" ? vaSpanStart : 0;
  const exact = wireIntToBigInt(row.addr);
  if (exact !== null && Number.isSafeInteger(base)) {
    const offset = exact - BigInt(base);
    if (offset < 0n) return null; // genuinely before the view: no fallback
    if (offset <= BigInt(Number.MAX_SAFE_INTEGER)) return { view, offset: Number(offset) };
  }
  const vasOk = typeof row.vas_offset === "number" && Number.isSafeInteger(row.vas_offset) && row.vas_offset >= 0
    && view === "va" && (availableViews === null || availableViews.includes("vas"));
  return vasOk ? { view: "vas", offset: row.vas_offset as number } : null;
}

/** POST JSON and decode the answer with {@link parseJsonLossless}. */
export async function postLossless<T>(url: string, body: object, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    ...(signal ? { signal } : {}),
  });
  const text = await res.text();
  if (!res.ok) throw new ApiError(res.status, text);
  return parseJsonLossless(text) as T;
}

