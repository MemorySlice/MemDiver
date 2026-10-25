/** The exact integer of a cell, or `null` (absent, non-numeric, or already rounded). */
export function cellToBigInt(cell: unknown): bigint | null {
  if (typeof cell === "number") return Number.isSafeInteger(cell) ? BigInt(cell) : null;
  if (typeof cell === "string" && /^-?\d+$/.test(cell)) return BigInt(cell);
  return null;
}

/** `0x...` text of an address cell; `approximate` when the value was already rounded. */
export function formatAddress(cell: unknown): { text: string; approximate: boolean } | null {
  const exact = cellToBigInt(cell);
  if (exact !== null) return { text: `0x${exact.toString(16)}`, approximate: false };
  if (typeof cell === "number" && Number.isFinite(cell)) {
    return { text: `0x${BigInt(Math.trunc(cell)).toString(16)}`, approximate: true };
  }
  return null;
}
