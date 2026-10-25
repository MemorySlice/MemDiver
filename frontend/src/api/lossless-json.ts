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

/** POST JSON and decode the answer with {@link parseJsonLossless}. */
export async function postLossless<T>(url: string, body: object): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new ApiError(res.status, text);
  return parseJsonLossless(text) as T;
}

