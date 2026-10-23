import type {
  HeapChunk,
  HeapChunksResponse,
  HeapDetectResponse,
  HeapFreeListsResponse,
  HeapSummaryResponse,
} from "@/api/types";
import { EMPTY_HEAP_DUMP, type HeapDumpEntry, useHeapStore } from "@/stores/heap-store";

export const DUMP = "/dumps/heap.msl";

export const DETECTION: HeapDetectResponse = {
  best: "jemalloc",
  confidence: 0.62,
  hinted: false,
  platform: { os: "linux", arch: "x86_64", pointer_size: 8, endianness: "little", source: "msl" },
  candidates: [
    { kind: "jemalloc", score: 0.62, evidence: [{ source: "module", detail: "libjemalloc.so.2", weight: 0.5 }] },
    { kind: "ptmalloc2", score: 0.2, evidence: [] },
  ],
  format: "msl",
};

export const SUMMARY: HeapSummaryResponse = {
  allocator: "jemalloc",
  confidence: 0.62,
  version_hint: "5.3.0",
  partial: true,
  heuristic: false,
  levels: ["chunks"],
  platform: DETECTION.platform,
  regions: [{ va: 0x7f0000000000, size: 0x200000, name: "[anon:jemalloc]", kind: "arena" }],
  chunk_count: 3,
  counts_by_state: { in_use: 2, free: 1 },
  bytes_by_state: { in_use: 96, free: 32 },
  size_histogram: [{ min_size: 32, max_size: 32, count: 2 }, { min_size: 64, max_size: 64, count: 1 }],
  role_bytes: {},
  metadata_bytes: 16,
  free_list_count: 1,
  evidence: [{ source: "region", detail: "[anon:jemalloc] present", weight: 0.4 }],
  coverage: {},
  diagnostics: ["stride guessed for 1 region"],
  format: "msl",
};

export function chunk(over: Partial<HeapChunk> = {}): HeapChunk {
  return {
    va: 0x5555_0000_1000,
    size: 32,
    state: "in_use",
    header_len: 16,
    user_va: 0x5555_0000_1010,
    user_len: 16,
    flags: 1,
    bin: null,
    extra: {},
    confidence: 0.9,
    view_offset: 0x1000,
    ...over,
  };
}

export function chunksPage(chunks: HeapChunk[]): HeapChunksResponse {
  return {
    allocator: "ptmalloc2",
    view: "vas",
    total: chunks.length,
    chunk_count: chunks.length,
    page: 0,
    page_size: 200,
    pages: 1,
    chunks,
    diagnostics: [],
    filters: {},
  };
}

export const FREE_LISTS: HeapFreeListsResponse = {
  allocator: "ptmalloc2",
  kinds: ["tcache"],
  list_count: 1,
  cycle_count: 1,
  corrupt_count: 0,
  lists: [{
    kind: "tcache", index: 3, head_va: 0x1000, length: 2,
    chunk_vas: [0x1000, 0x2000], decoded: true, cycle: true, corrupt: false, unresolved_vas: [],
  }],
};

/** Seed one dump's entry directly (the API is mocked by each test file). */
export function seedDump(patch: Partial<HeapDumpEntry>): void {
  useHeapStore.setState({
    dumps: { [DUMP]: { ...EMPTY_HEAP_DUMP, ...patch } },
    roleWindows: {},
    roleWindowsVersion: 0,
  });
}
