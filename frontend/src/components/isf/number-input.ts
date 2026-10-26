/** `0x...` or decimal text as an exact integer, else `null`. */
export function parseInteger(text: string): bigint | null {
  const s = text.trim();
  if (/^0x[0-9a-f]+$/i.test(s) || /^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

export const toHex = (value: bigint): string => `0x${value.toString(16)}`;
