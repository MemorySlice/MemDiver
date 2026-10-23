/**
 * Which allocator-specific header fields the chunk inspector lists first, and
 * how ptmalloc's packed size-word flags decode. Every remaining `extra` key
 * still shows (the generic fallback), after these.
 */

import type { HeapAllocatorKind, HeapChunk } from "@/api/types";

const PREFERRED_FIELDS: Readonly<Partial<Record<HeapAllocatorKind, readonly string[]>>> = {
  ptmalloc2: ["prev_size", "fd", "bk", "fd_nextsize", "bk_nextsize", "next", "key", "struct"],
  dlmalloc: ["prev_size", "fd", "bk", "fd_nextsize", "bk_nextsize"],
  scudo: ["class_id", "state", "origin", "size_or_unused", "offset", "checksum"],
  mallocng: ["slot_idx", "sizeclass", "meta_va", "group_va", "header_ok"],
  jemalloc: ["stride_score"],
};

/** ptmalloc/dlmalloc low size-word bits. */
const PTMALLOC_FLAG_BITS: ReadonlyArray<readonly [number, string]> = [
  [1, "PREV_INUSE"],
  [2, "IS_MMAPPED"],
  [4, "NON_MAIN_ARENA"],
];

/** `extra` as ordered `[key, value]` pairs: the allocator's header fields first. */
export function orderedExtraFields(
  allocator: HeapAllocatorKind | null | undefined,
  chunk: HeapChunk,
): Array<[string, unknown]> {
  const extra = chunk.extra ?? {};
  const preferred = (allocator && PREFERRED_FIELDS[allocator]) || [];
  const head = preferred.filter((k) => k in extra).map((k): [string, unknown] => [k, extra[k]]);
  const rest = Object.keys(extra)
    .filter((k) => !preferred.includes(k))
    .sort()
    .map((k): [string, unknown] => [k, extra[k]]);
  return [...head, ...rest];
}

/** Integer ptmalloc flags as their names; other shapes pass through untouched. */
export function decodeChunkFlags(
  allocator: HeapAllocatorKind | null | undefined,
  flags: HeapChunk["flags"],
): unknown {
  if (typeof flags !== "number" || (allocator !== "ptmalloc2" && allocator !== "dlmalloc")) {
    return flags;
  }
  const names = PTMALLOC_FLAG_BITS.filter(([bit]) => flags & bit).map(([, name]) => name);
  return names.length > 0 ? names : flags;
}
