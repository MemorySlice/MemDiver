/**
 * Shared hex-string helpers used by the key-verification panel and the NSS
 * key-log composer. Extracted from KeyVerificationPanel so the same
 * normalisation/validation rules apply everywhere hex is entered by hand.
 */

/** Strip whitespace and an optional `0x`/`0X` prefix. */
export function normalizeHex(value: string): string {
  return value.replace(/\s+/g, "").replace(/^0x/i, "");
}

/** True when the string contains only hex digits (empty string included). */
export function isHex(value: string): boolean {
  return /^[0-9a-fA-F]*$/.test(value);
}

/** True when the string is a non-empty, even-length run of hex digits. */
export function isEvenHex(value: string): boolean {
  return value.length > 0 && value.length % 2 === 0 && isHex(value);
}
