/**
 * Display helpers shared by the heap panels. Pure, locale-independent
 * spellings only (addresses, hex offsets); anything worded goes through i18n.
 */

import { HEAP_ALLOCATORS } from "@/api/heap";
import type { HeapAllocatorChoice } from "@/api/types";

/** What the allocator selector offers: detection plus every concrete parser. */
export const HEAP_ALLOCATOR_CHOICES: readonly HeapAllocatorChoice[] = [
  "auto",
  ...HEAP_ALLOCATORS.filter((k) => k !== "unknown"),
];

/** `0x7f3a1c002010` — the spelling the hex toolbar's goto field accepts. */
export function formatAddress(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "--";
  return `0x${value.toString(16)}`;
}

/** A confidence in `[0, 1]` as a whole percentage. */
export function confidencePercent(confidence: number): number {
  if (!Number.isFinite(confidence)) return 0;
  return Math.round(Math.min(1, Math.max(0, confidence)) * 100);
}

/** One `extra`/`flags` value as text: hex for addresses-ish ints, JSON otherwise. */
export function formatFieldValue(key: string, value: unknown): string {
  if (value === null || value === undefined) return "--";
  if (typeof value === "number") {
    return looksLikeAddressField(key) && Number.isInteger(value)
      ? formatAddress(value)
      : String(value);
  }
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  return JSON.stringify(value);
}

const ADDRESS_FIELD = /(^|_)(va|addr|address|ptr|fd|bk|next|prev|key|checksum|head)(_|$)/i;

function looksLikeAddressField(key: string): boolean {
  return ADDRESS_FIELD.test(key) && !/size|idx|index|count|class/i.test(key);
}

/** `flags` as one short string, whatever shape the allocator emitted. */
export function formatFlags(flags: unknown): string {
  if (flags === null || flags === undefined) return "";
  if (Array.isArray(flags)) return flags.join(" ");
  if (typeof flags === "number") return formatAddress(flags);
  if (typeof flags === "object") {
    return Object.entries(flags as Record<string, unknown>)
      .filter(([, v]) => v !== false && v !== null && v !== undefined && v !== 0)
      .map(([k, v]) => (v === true ? k : `${k}=${String(v)}`))
      .join(" ");
  }
  return String(flags);
}
