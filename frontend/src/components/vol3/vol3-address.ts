import { wireIntToBigInt } from "@/api/lossless-json";

/** The exact integer of a cell, or `null` (absent, non-numeric, or already rounded). */
export const cellToBigInt = wireIntToBigInt;

/** `0x...` text of an address cell; `approximate` when the value was already rounded. */
export function formatAddress(cell: unknown): { text: string; approximate: boolean } | null {
  const exact = cellToBigInt(cell);
  if (exact !== null) return { text: `0x${exact.toString(16)}`, approximate: false };
  if (typeof cell === "number" && Number.isFinite(cell)) {
    return { text: `0x${BigInt(Math.trunc(cell)).toString(16)}`, approximate: true };
  }
  return null;
}
