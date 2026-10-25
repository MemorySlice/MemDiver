const HEX_CHARS = "0123456789abcdef";

export function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function byteToHex(b: number): string {
  return HEX_CHARS[b >> 4] + HEX_CHARS[b & 0xf];
}

export function byteToAscii(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

export function offsetToHex(offset: number): string {
  return offset.toString(16).padStart(8, "0");
}

/** Hex digits of the default (view-relative) offset gutter. */
export const OFFSET_DIGITS_DEFAULT = 8;
/** The `.hex-offset` width at the default digit count; each extra digit is one 8px cell. */
const OFFSET_GUTTER_BASE_PX = 76;
const OFFSET_CELL_PX = 8;

/** CSS width of the offset gutter for `digits` hex digits (76px at the default 8). */
export function offsetGutterWidthPx(digits: number = OFFSET_DIGITS_DEFAULT): number {
  return OFFSET_GUTTER_BASE_PX + (digits - OFFSET_DIGITS_DEFAULT) * OFFSET_CELL_PX;
}

/**
 * How many hex digits an address of at most `maxAddress` needs, in the three
 * fixed steps the layout supports: 8 (32-bit), 12 (48-bit, every user-space
 * x86-64 / arm64 address) and 16.
 */
export function addressDigitsFor(maxAddress: number): number {
  if (!Number.isFinite(maxAddress) || maxAddress <= 0xffffffff) return OFFSET_DIGITS_DEFAULT;
  if (maxAddress <= 0xffffffffffff) return 12;
  return 16;
}

/**
 * The text for one offset-gutter cell.
 *
 * With a `base` (the server-given virtual address of offset 0) the cell shows
 * the absolute address; without one — or when `base + offset` is not an exact
 * integer — it falls back to the view-relative offset. DISPLAY ONLY: the sum
 * is never used to address a read.
 */
export function gutterLabel(
  offset: number,
  base: number | null | undefined,
  digits: number = OFFSET_DIGITS_DEFAULT,
): string {
  const relative = base === null || base === undefined || !Number.isSafeInteger(base + offset);
  const shown = relative ? offset : base + offset;
  return shown.toString(16).padStart(digits, "0");
}

/** Whether `gutterLabel` would print an absolute address for these arguments. */
export function isAbsoluteGutter(offset: number, base: number | null | undefined): boolean {
  return base !== null && base !== undefined && Number.isSafeInteger(base + offset);
}
