/**
 * Per-dump byte cache backing the N-pane (multi-dump) hex viewer.
 *
 * ONE store keyed by dump path — not a store per pane. Dedupe, the in-flight
 * set and the byte budget are therefore global and bounded: with a store per
 * pane each of those would be replicated N times, and the memory ceiling would
 * grow linearly with the number of dumps the user happens to have selected.
 *
 * ── Invariant W1 ─────────────────────────────────────────────────────────────
 * `/api/analysis/consensus/aligned-window` returns every dump's bytes ALREADY
 * re-indexed into the anchor's window index space (see `@/api/aligned-window`).
 * This store therefore stores and serves bytes by window index and NEVER does
 * coordinate arithmetic on `va` / `offset` to place them. Two real bugs in this
 * repo came from client-side coordinate math; `segments[].dumps[].va/offset`
 * are provenance for display only.
 *
 * Absence is carried by a separate presence mask (`valid`), because a byte the
 * dump does not hold arrives as `0` — indistinguishable from a real `0x00`
 * without the mask. `getByteAt` reports what the window holds; `isPresentAt` is
 * the sole authority on whether that byte exists at all, and every caller that
 * renders or compares bytes must consult it.
 *
 * ── Why there is no byte ──────────────────────────────────────────────────────
 * `isPresentAt` answers "is there a byte"; `absenceAt` answers "WHY not", and
 * the four answers are different findings that must never be painted alike:
 * the window has not arrived yet, the request for it failed, the alignment put
 * nothing at this index for ANY dump, or this one dump does not hold it. Only
 * the last two are analysis results; the first two are the UI's own problems,
 * and showing them in the same grey `--` is how a transport failure gets read
 * as evidence about memory.
 */

import { create } from "zustand";
import { decodeBase64 } from "@/utils/hex-codec";
import { fetchAlignedWindow, keysForPaths } from "@/api/aligned-window";
import type { AlignedWindowResponse } from "@/api/aligned-window";
import { readableFailure } from "@/api/client";
import { selectionKey } from "@/stores/consensus-store";
import type { HexViewMode } from "@/stores/hex-store";
import {
  CHUNK_SIZE,
  chunkRangeForRows,
  decodeRunsToMask,
  offsetToChunkStart,
  prefetchChunksForPaneCount,
} from "@/components/hex/multi-window-utils";

/**
 * The byte ceiling for the WHOLE cache, side maps included.
 *
 * "Included" is the correction, not decoration: `chunkCost` used to sum only
 * `data + valid`, so the per-offset window arrays (`classes`, `variants`) were
 * held but never counted. At N=2 that was 16,384 uncounted bytes per retained
 * offset on top of the 16,384 counted ones — a documented 24 MiB that really
 * peaked well past it. `evictToBudget` now charges them, so this figure is
 * what the tab actually holds.
 */
const DEFAULT_BUDGET_BYTES = 24 * 1024 * 1024;

/**
 * How many times a failed chunk is re-requested WITHOUT a user gesture.
 *
 * The latch this bounds is not paranoia: `ensureLoaded` re-runs on every
 * virtualizer row change, so an unretried-but-unlatched failure turned one
 * unreachable dump into a dozen identical POSTs per scroll. Two retries on an
 * exponential backoff recover the transient case (a restarted backend, a
 * momentarily locked file) and still bound the total at 1 + 2 requests per
 * chunk per identity.
 */
export const MAX_CHUNK_RETRIES = 2;

/** Backoff before retry number `attempts` (0-based): 1s, then 4s. */
function retryDelayMs(attempts: number): number {
  return 1000 * 4 ** attempts;
}

/** A chunk fetch that failed, and how much of its retry budget is left. */
export interface ChunkFailure {
  /** The readable sentence, already unwrapped from the error envelope. */
  message: string;
  /**
   * Retries ALREADY SPENT on this chunk under this identity — 0 for the first
   * failure, so `attempts >= MAX_CHUNK_RETRIES` means "budget exhausted, only
   * a user gesture gets us back".
   */
  attempts: number;
  /** Epoch ms before which `ensureLoaded` must not re-request this chunk. */
  nextRetryAt: number;
}

/** One failed chunk inside a queried range. */
export interface ChunkErrorInRange {
  /** Chunk START offset, which is what `retryChunkAt` expects. */
  offset: number;
  message: string;
}

/**
 * WHY there is no byte at an offset — never merely THAT there is none.
 *
 * `loading` and `error` are facts about this client's requests; `no-correspondence`
 * and `not-in-dump` are facts about the dumps. Folding them together (a single
 * grey `--`) makes a failed fetch look like evidence that memory was empty.
 */
export type ByteAbsence = "loading" | "error" | "no-correspondence" | "not-in-dump";

export interface PaneChunk {
  offset: number;
  data: Uint8Array;
  /** Per-byte 0/1 presence mask, same length as `data`. */
  valid: Uint8Array;
  fetchedAt: number;
}

export interface PaneCache {
  chunks: Map<number, PaneChunk>;
  /**
   * A fact about THIS DUMP, not about a request: the locked-key hint the
   * backend sends when it could not decrypt this pane's bytes.
   *
   * A failed CHUNK fetch is deliberately NOT recorded here. One aligned-window
   * request carries every selected pane, so writing its failure into every
   * pane's cache made a single out-of-range prefetch blank out panes whose
   * bytes were on screen and correct. Chunk failures live in `chunkErrors`,
   * keyed by the chunk they actually belong to.
   */
  error: string | null;
}

export interface MultiHexState {
  byPath: Map<string, PaneCache>;

  /**
   * Window-index consensus classes, one array per chunk. `-1` = gap.
   *
   * `Int8Array`, not `Int16Array`: the domain is the four `ByteClass` codes
   * plus the `-1` gap sentinel, so one signed byte holds it exactly — and the
   * sentinel is why this cannot be a `Uint8Array` like `variantChunks`. Halves
   * 16,384 B per retained chunk offset to 8,192 B with no change in value.
   */
  classChunks: Map<number, Int8Array>;

  /**
   * Distinct present byte values per window index, one array per chunk.
   *
   * Decoded here, beside `classes`, so the per-chunk shape lives in ONE place
   * — the `Variants` render mode that will read it is a later task, and a
   * decoder bolted on next to a renderer is how the two drift apart.
   *
   * ALSO the server's cross-dump disagreement answer: `differsAt` is
   * `variants[i] >= 2`. The response used to carry a redundant boolean
   * `differs` run list beside this one and the store decoded it into a second
   * map; both are gone, because two structures that must always agree are two
   * structures that can drift.
   *
   * Present only for chunks whose response actually carried the field, because
   * "the server did not say" and "the server said one value here" are
   * different facts and `differsAt` falls back differently for each.
   *
   * `Uint8Array`: a distinct-value count over at most `MAX_PANES` (6) dumps
   * cannot exceed 6, and unlike `classChunks` there is no negative sentinel —
   * `0` already means "nobody is present here".
   */
  variantChunks: Map<number, Uint8Array>;

  /**
   * Repaint counter PER PATH, not one global counter.
   *
   * A single global counter would rotate the memoization identity of EVERY
   * pane's rows whenever ANY pane's chunk arrived. With N panes scrolling, that
   * is an O(N) repaint storm on every one of the N responses — O(N^2) work per
   * window. Bumping only the paths a response actually filled keeps each pane's
   * rows still while its neighbours load.
   */
  chunkVersionByPath: Map<string, number>;

  /** In-flight CACHE KEYS (see `cacheKeyFor`), for dedupe. */
  pending: Set<string>;

  /**
   * Failed chunk fetches, keyed by CACHE KEY (`identity|offset`) — the same key
   * `pending` uses.
   *
   * Keyed by chunk, not by pane, so a failure is scoped to the window it was
   * asked for; keyed by identity as well, so a failure recorded under one
   * anchor/view/selection can never be shown under the next one. An entry is
   * dropped the moment that chunk is re-requested or lands successfully, which
   * is what stops a stale error outliving the condition that caused it.
   */
  chunkErrors: Map<string, ChunkFailure>;

  /**
   * The cache identity the loaded chunks belong to: anchor path, view and the
   * WHOLE selected set. Chunks whose recorded identity differs are invisible to
   * the getters and are refetched — see `chunkIdentity`.
   */
  identity: string | null;

  /** Identity under which each chunk offset was stored. */
  chunkIdentity: Map<number, string>;

  alignment: AlignedWindowResponse["alignment"] | null;
  truncated: boolean;
  budgetBytes: number;

  /**
   * The last window request, so `retryChunkAt` can re-issue a failed chunk
   * without waiting for a React render to hand it the arguments again.
   * Cleared by `reset()`.
   */
  lastRequest: {
    anchorPath: string;
    view: HexViewMode;
    paths: string[];
    consensusId: string | null;
  } | null;

  ensureLoaded(args: {
    anchorPath: string;
    view: HexViewMode;
    paths: string[];
    startRow: number;
    endRow: number;
    consensusId: string | null;
    /**
     * The anchor's addressable size IN `view` (`hex-store.fileSize`). Omit only
     * while it is genuinely unknown — see `chunkRangeForRows`.
     */
    anchorSize?: number;
  }): void;
  getByteAt(path: string, offset: number): number | undefined;
  isPresentAt(path: string, offset: number): boolean;
  /**
   * WHY `path` has no byte at `offset`, or `null` when it HAS one.
   *
   * The single authority for the absence vocabulary, beside `isPresentAt` and
   * for the same reason: every surface that paints a missing byte must agree
   * about what it is looking at. See `ByteAbsence`.
   */
  absenceAt(path: string, offset: number): ByteAbsence | null;
  getClassAt(offset: number): number | undefined;
  /**
   * How many DISTINCT byte values the present dumps hold at `offset`.
   *
   * `0` = no dump is present there, `1` = every present dump agrees.
   * `undefined` when the chunk is not loaded under the live identity.
   */
  variantsAt(offset: number): number | undefined;
  /** The failure message (if any) recorded for the chunk holding `offset`. */
  getChunkError(offset: number): string | null;
  /** The full failure record for the chunk holding `offset`, retry budget included. */
  getChunkFailure(offset: number): ChunkFailure | null;
  /**
   * Every failed chunk covering `[startOffset, endOffset]`, in offset order.
   *
   * The banner logic lives HERE rather than in the viewers because the viewers
   * only ever looked at the first and last visible row — a chunk failing in
   * the MIDDLE of a tall window showed no banner at all, just a band of `--`
   * with no way to retry it.
   */
  getChunkErrorsInRange(startOffset: number, endOffset: number): ChunkErrorInRange[];
  /**
   * Re-request the chunk holding `offset` after a failure.
   *
   * `ensureLoaded` retries on its own only within `MAX_CHUNK_RETRIES` and only
   * after the backoff, so once that budget is spent this gesture is the only
   * way back. It RESETS the budget: a human asking again is not a retry.
   */
  retryChunkAt(offset: number): void;
  /** `retryChunkAt` for every failed chunk covering the range. */
  retryChunksInRange(startOffset: number, endOffset: number): void;
  differsAt(offset: number): boolean;
  releasePaths(keep: string[]): void;
  reset(): void;
}

/**
 * The cache key for one chunk.
 *
 * `selectionKey` — the sorted, joined selected paths — is load bearing and NOT
 * decoration. `classes` and therefore `differsAt` are computed by the backend
 * across the WHOLE selected set: add or remove one dump and every class in the
 * window can change, even though the anchor, the view and the offset did not.
 * Omitting `selectionKey` here would serve the previous selection's classes
 * under the new one — the single most likely bug in this file, and the reason
 * `tests/frontend/stores/multi-hex-store.test.ts` pins it explicitly.
 */
function identityFor(anchorPath: string, view: HexViewMode, paths: string[]): string {
  return `${anchorPath}|${view}|${selectionKey(paths)}`;
}

function cacheKeyFor(identity: string, chunkOffset: number): string {
  return `${identity}|${chunkOffset}`;
}

/** Every chunk START covering `[startOffset, endOffset]`, inclusive of both. */
function chunkStartsInRange(startOffset: number, endOffset: number): number[] {
  if (endOffset < startOffset) return [];
  const starts: number[] = [];
  const first = offsetToChunkStart(Math.max(0, startOffset), CHUNK_SIZE);
  for (let offset = first; offset <= endOffset; offset += CHUNK_SIZE) {
    starts.push(offset);
  }
  return starts;
}

/**
 * Scheduled auto-retries, keyed by CACHE KEY.
 *
 * A nudge is needed because `ensureLoaded` only re-runs when the visible rows
 * change: a user who stops scrolling on a failed window would otherwise sit in
 * front of a chunk whose backoff expired and which nothing ever re-requests.
 * Module scope rather than store state because these are handles, not data —
 * nothing renders them, and `reset()` is the one place they must all die.
 */
const retryTimers = new Map<string, ReturnType<typeof setTimeout>>();

function cancelRetryTimer(key: string): void {
  const handle = retryTimers.get(key);
  if (handle === undefined) return;
  clearTimeout(handle);
  retryTimers.delete(key);
}

function cancelAllRetryTimers(): void {
  for (const handle of retryTimers.values()) clearTimeout(handle);
  retryTimers.clear();
}

/** Bytes a PANE chunk costs: the window bytes plus its same-length presence mask. */
function chunkCost(chunk: PaneChunk): number {
  return chunk.data.byteLength + chunk.valid.byteLength;
}

/**
 * The per-chunk-offset window arrays, which are shared by every pane and
 * therefore cost their bytes ONCE per offset rather than once per pane.
 */
interface SideChunks {
  classChunks: Map<number, Int8Array>;
  variantChunks: Map<number, Uint8Array>;
}

/** Bytes the window arrays for ONE chunk offset cost. */
function sideCostAt(offset: number, side: SideChunks): number {
  return (
    (side.classChunks.get(offset)?.byteLength ?? 0) +
    (side.variantChunks.get(offset)?.byteLength ?? 0)
  );
}

/**
 * Bytes ALL the window arrays cost.
 *
 * Summing the maps wholesale is exact rather than approximate because
 * `pruneOrphanChunkState` keeps them a subset of the held chunk offsets: an
 * entry that survives is an entry some pane still holds bytes for.
 */
function sideTotal(side: SideChunks): number {
  let total = 0;
  for (const array of side.classChunks.values()) total += array.byteLength;
  for (const array of side.variantChunks.values()) total += array.byteLength;
  return total;
}

/**
 * Evict oldest-first across ALL panes until the total fits `budgetBytes`.
 *
 * Deliberately NOT the single-dump store's per-dump `MAX_CHUNKS = 12`: a
 * per-pane cap multiplies the memory ceiling by the pane count, so six panes
 * would hold six times as much as the single-dump viewer ever did. A shared
 * byte budget makes the ceiling independent of N, and evicting by global
 * `fetchedAt` lets a pane the user is actively scrolling keep its chunks at the
 * expense of one they scrolled past.
 */
function evictToBudget(
  byPath: Map<string, PaneCache>,
  budgetBytes: number,
  side: SideChunks,
): Map<string, PaneCache> {
  // The under-budget answer is the common one, and it needs only a sum — so it
  // is reached before the ~1,536-entry sort list is built. Building that list
  // first meant allocating it on every single response.
  let total = sideTotal(side);
  for (const cache of byPath.values()) {
    for (const chunk of cache.chunks.values()) total += chunkCost(chunk);
  }
  if (total <= budgetBytes) return byPath;

  const entries: { path: string; offset: number; fetchedAt: number; cost: number }[] = [];
  // How many panes still hold each offset: the window arrays are shared, so
  // their bytes are only reclaimed when the LAST pane holding the offset goes.
  const holders = new Map<number, number>();
  for (const [path, cache] of byPath) {
    for (const [offset, chunk] of cache.chunks) {
      entries.push({ path, offset, fetchedAt: chunk.fetchedAt, cost: chunkCost(chunk) });
      holders.set(offset, (holders.get(offset) ?? 0) + 1);
    }
  }

  entries.sort((a, b) => a.fetchedAt - b.fetchedAt || a.offset - b.offset);
  const next = new Map(byPath);
  for (const entry of entries) {
    if (total <= budgetBytes) break;
    const cache = next.get(entry.path);
    if (!cache) continue;
    const chunks = new Map(cache.chunks);
    chunks.delete(entry.offset);
    next.set(entry.path, { ...cache, chunks });
    total -= entry.cost;
    const remaining = (holders.get(entry.offset) ?? 1) - 1;
    holders.set(entry.offset, remaining);
    if (remaining === 0) total -= sideCostAt(entry.offset, side);
  }
  return next;
}

/** Drop per-chunk window data (and identities) no pane holds bytes for. */
function pruneOrphanChunkState(
  byPath: Map<string, PaneCache>,
  classChunks: Map<number, Int8Array>,
  variantChunks: Map<number, Uint8Array>,
  chunkIdentity: Map<number, string>,
): {
  classChunks: Map<number, Int8Array>;
  variantChunks: Map<number, Uint8Array>;
  chunkIdentity: Map<number, string>;
} {
  const held = new Set<number>();
  for (const cache of byPath.values()) {
    for (const offset of cache.chunks.keys()) held.add(offset);
  }
  const keepByOffset = <T>(source: Map<number, T>): Map<number, T> => {
    const next = new Map<number, T>();
    for (const [offset, value] of source) {
      if (held.has(offset)) next.set(offset, value);
    }
    return next;
  };
  return {
    classChunks: keepByOffset(classChunks),
    variantChunks: keepByOffset(variantChunks),
    chunkIdentity: keepByOffset(chunkIdentity),
  };
}

function emptyCache(): PaneCache {
  return { chunks: new Map(), error: null };
}

/**
 * ── The chunk-resolution memos ───────────────────────────────────────────────
 *
 * `8192 % 16 === 0`, so a 16-byte hex row can never straddle a chunk boundary:
 * every cell in a row — and in the 512 rows after it — resolves to the SAME
 * chunk. The grid nevertheless asked five separate getters per cell, and each
 * of them re-walked `chunkIdentity` -> `byPath` -> `chunks` from scratch.
 * Counted over the ~65 rows a frame actually renders: 31,200 `Map.get` calls
 * per frame at N=2 and 81,120 at N=6, for a handful of distinct chunks.
 *
 * These two memos collapse that to one resolution per chunk. They are correct
 * for the same reason the stale-response guard is: every mutation goes through
 * zustand's `set`, which yields a NEW state object, so `state !== memoState` is
 * an exact invalidation test — there is no way to change a chunk, an identity
 * or an error without also changing the object the memo was keyed on.
 */

/** Everything about ONE chunk that does not depend on a dump path. */
export interface ChunkWindow {
  /** The chunk START this describes. */
  chunkOffset: number;
  /** Whether the chunk is held under the store's LIVE identity. */
  live: boolean;
  /** Consensus classes, or `undefined` when the chunk is stale/absent. */
  classes: Int8Array | undefined;
  /**
   * Distinct-value counts, or `undefined` when the chunk is stale/absent.
   *
   * The disagreement verdict too: `>= 2` is a differ. See `variantChunks`.
   */
  variants: Uint8Array | undefined;
  /** The recorded failure for this chunk under the live identity. */
  failure: ChunkFailure | null;
}

let windowMemoState: MultiHexState | null = null;
let windowMemo: ChunkWindow | null = null;

/**
 * The path-independent view of the chunk holding `offset`, resolved ONCE.
 *
 * Shared by `getClassAt`, `variantsAt`, `differsAt`, `getChunkFailure` and
 * `absenceAt` so that a row's 16 cells pay for one resolution between them.
 */
export function chunkWindowAt(state: MultiHexState, offset: number): ChunkWindow {
  const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
  const memo = windowMemo;
  if (memo !== null && windowMemoState === state && memo.chunkOffset === chunkOffset) {
    return memo;
  }
  const identity = state.identity;
  const live = identity !== null && state.chunkIdentity.get(chunkOffset) === identity;
  const view: ChunkWindow = {
    chunkOffset,
    live,
    classes: live ? state.classChunks.get(chunkOffset) : undefined,
    variants: live ? state.variantChunks.get(chunkOffset) : undefined,
    failure:
      identity === null
        ? null
        : (state.chunkErrors.get(cacheKeyFor(identity, chunkOffset)) ?? null),
  };
  windowMemoState = state;
  windowMemo = view;
  return view;
}

let paneMemoState: MultiHexState | null = null;
let paneMemoChunkOffset = -1;
let paneMemoPaths: string[] = [];
let paneMemoChunks: (PaneChunk | undefined)[] = [];

let pathMemoState: MultiHexState | null = null;
let pathMemoChunkOffset = -1;
let pathMemoPath: string | null = null;
let pathMemoChunk: PaneChunk | undefined;

/**
 * Drop both memos.
 *
 * A new state object already invalidates them, so this is not needed for
 * correctness — it is needed so a torn-down viewer's last state snapshot (and
 * with it every chunk it held) is not pinned alive by a module-level field.
 */
export function clearChunkMemos(): void {
  windowMemoState = null;
  windowMemo = null;
  paneMemoState = null;
  paneMemoChunkOffset = -1;
  paneMemoPaths = [];
  paneMemoChunks = [];
  pathMemoState = null;
  pathMemoChunkOffset = -1;
  pathMemoPath = null;
  pathMemoChunk = undefined;
}

function samePaths(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * The N pane chunks holding `offset`, aligned to `paths`, resolved ONCE.
 *
 * Indexed by position rather than keyed by path so the caller's per-cell loop
 * is an array read. The stored key is a COPY of `paths`, because a caller that
 * mutates its array in place must not silently keep a stale answer.
 */
export function paneChunksAt(
  state: MultiHexState,
  paths: readonly string[],
  offset: number,
): readonly (PaneChunk | undefined)[] {
  const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
  if (
    paneMemoState === state &&
    paneMemoChunkOffset === chunkOffset &&
    samePaths(paneMemoPaths, paths)
  ) {
    return paneMemoChunks;
  }
  const live = state.identity !== null && state.chunkIdentity.get(chunkOffset) === state.identity;
  const chunks: (PaneChunk | undefined)[] = new Array(paths.length);
  for (let i = 0; i < paths.length; i++) {
    chunks[i] = live ? state.byPath.get(paths[i])?.chunks.get(chunkOffset) : undefined;
  }
  paneMemoState = state;
  paneMemoChunkOffset = chunkOffset;
  paneMemoPaths = [...paths];
  paneMemoChunks = chunks;
  return chunks;
}

/**
 * The cross-dump disagreement mask for ONE chunk, as a dense array.
 *
 * Derived from the server's `variants` where there is one (`>= 2` is a
 * differ); otherwise the client fallback computed for the WHOLE chunk in one
 * typed-array pass instead of per offset. That fallback is why this exists:
 * walking a chunk through `differsAt` cost 8,192 x N x (3 `Map.get` + a chunk
 * walk), which is how a single "Differs" chip click reached ~75 M lookups and
 * froze the tab for seconds.
 *
 * `null` when the chunk is not held under the live identity — no dump's bytes
 * are readable there, so there is nothing to compare.
 */
export function differsMaskForChunk(
  state: MultiHexState,
  chunkStart: number,
): Uint8Array | null {
  const window = chunkWindowAt(state, chunkStart);
  if (!window.live) return null;
  const variants = window.variants;
  if (variants) {
    // One typed-array pass, not a per-offset `variantsAt` sweep: the caller
    // walks the whole chunk, and the threshold is the same at every index.
    const server = new Uint8Array(CHUNK_SIZE);
    const limit = Math.min(CHUNK_SIZE, variants.length);
    for (let i = 0; i < limit; i++) server[i] = variants[i] >= 2 ? 1 : 0;
    return server;
  }

  // Same scoping rule as `differsAt`'s fallback: the dumps the last request
  // actually asked about, never every path the cache happens to still hold.
  const paths = state.lastRequest?.paths ?? [...state.byPath.keys()];
  const chunks = paneChunksAt(state, paths, chunkStart);
  const mask = new Uint8Array(CHUNK_SIZE);
  const first = new Uint8Array(CHUNK_SIZE);
  const present = new Uint8Array(CHUNK_SIZE);
  for (let p = 0; p < chunks.length; p++) {
    const chunk = chunks[p];
    if (!chunk) continue;
    const { data, valid } = chunk;
    const limit = Math.min(CHUNK_SIZE, data.length, valid.length);
    for (let i = 0; i < limit; i++) {
      if (valid[i] !== 1) continue;
      const value = data[i];
      if (present[i] === 0) first[i] = value;
      else if (value !== first[i]) mask[i] = 1;
      if (present[i] < 255) present[i] += 1;
    }
  }
  // An absent byte is not a difference, and neither is a lone present one.
  for (let i = 0; i < CHUNK_SIZE; i++) if (present[i] < 2) mask[i] = 0;
  return mask;
}

export const useMultiHexStore = create<MultiHexState>((set, get) => ({
  byPath: new Map(),
  classChunks: new Map(),
  variantChunks: new Map(),
  chunkVersionByPath: new Map(),
  pending: new Set(),
  chunkErrors: new Map(),
  lastRequest: null,
  identity: null,
  chunkIdentity: new Map(),
  alignment: null,
  truncated: false,
  budgetBytes: DEFAULT_BUDGET_BYTES,

  ensureLoaded: ({ anchorPath, view, paths, startRow, endRow, consensusId, anchorSize }) => {
    if (!anchorPath || paths.length === 0) return;

    const identity = identityFor(anchorPath, view, paths);
    if (get().identity !== identity) {
      // Only the identity moves here; the chunks stay put and simply stop
      // matching, so a flip back to the previous selection can still hit
      // whatever survived the byte budget. Chunk failures DO go, because they
      // described the previous anchor/view/selection — and so do the nudges
      // scheduled for them, which now name windows nobody is looking at.
      cancelAllRetryTimers();
      set({ identity, chunkErrors: new Map() });
    }

    const prefetch = prefetchChunksForPaneCount(paths.length);
    // `anchorSize` bounds the prefetch: without it the look-ahead runs off the
    // end of the dump and the backend rejects the window (400, "anchor offset
    // does not name an addressable byte") for bytes nobody is looking at.
    const chunkStarts = chunkRangeForRows(
      startRow,
      endRow,
      CHUNK_SIZE,
      prefetch,
      anchorSize,
    );

    // Only when it actually CHANGED. This `set` is unconditional and sits above
    // the `needed.length === 0` early return, while `ensureLoaded` re-runs on
    // every virtualizer row change — so a fresh object here rotated
    // `lastRequest`'s identity on every scroll tick, and every subscriber of it
    // (`useVarianceRegions`, and through it `VarianceClassBrowser` and
    // `VarianceClassChips`) re-rendered and re-ran its effect with it. It stays
    // ABOVE the early return, because `differsAt`'s fallback and `retryChunkAt`
    // both read it even when every chunk was already cached.
    if (!sameRequest(get().lastRequest, anchorPath, view, paths, consensusId)) {
      set({ lastRequest: { anchorPath, view, paths, consensusId } });
    }

    const state = get();
    const needed = chunkStarts.filter((offset) => {
      const key = cacheKeyFor(identity, offset);
      if (state.pending.has(key)) return false;
      // A chunk that already FAILED under this identity is retried here only
      // within its budget, and only once its backoff has expired.
      //
      // This check must come before the `chunkIdentity` one: a failed chunk
      // holds no bytes, so no identity is ever recorded for it, so that check
      // would answer "refetch" forever. `ensureLoaded` re-runs on every
      // virtualizer row change, which turned one unreachable dump into a
      // dozen identical POSTs per scroll. Budget + backoff keep that bounded
      // at 1 + MAX_CHUNK_RETRIES requests; past it only `retryChunkAt` gets
      // back. Identity changes still clear `chunkErrors` wholesale above, so
      // a new selection refetches normally.
      const failure = state.chunkErrors.get(key);
      if (failure) {
        if (failure.attempts >= MAX_CHUNK_RETRIES) return false;
        return failure.nextRetryAt <= Date.now();
      }
      if (state.chunkIdentity.get(offset) !== identity) return true;
      // Held under this identity — only refetch if some selected pane is
      // missing it (a pane joined after the chunk landed, or it was evicted).
      return paths.some((path) => !state.byPath.get(path)?.chunks.has(offset));
    });
    if (needed.length === 0) return;

    fetchChunks(set, { identity, offsets: needed, anchorPath, view, paths, consensusId });
  },

  retryChunkAt: (offset) => {
    const state = get();
    const req = state.lastRequest;
    if (!state.identity || !req) return;
    const identity = state.identity;
    const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
    const key = cacheKeyFor(identity, chunkOffset);
    if (!state.chunkErrors.has(key) || state.pending.has(key)) return;
    // A pending nudge for this chunk is now redundant, and letting it fire
    // would issue a second request for a window already in flight.
    cancelRetryTimer(key);
    // Drop the verdict first so the banner clears while the retry is in
    // flight, so the chunk is eligible again, and — because `fetchChunks`
    // reads the surviving `attempts` to decide how much budget is left —
    // so the budget starts over. A human asking again is not a retry.
    set((prev) => {
      const chunkErrors = new Map(prev.chunkErrors);
      chunkErrors.delete(key);
      return { chunkErrors };
    });
    fetchChunks(set, { identity, offsets: [chunkOffset], ...req });
  },

  retryChunksInRange: (startOffset, endOffset) => {
    const retry = get().retryChunkAt;
    for (const { offset } of get().getChunkErrorsInRange(startOffset, endOffset)) {
      retry(offset);
    }
  },


  getByteAt: (path, offset) => {
    const chunk = currentChunk(get(), path, offset);
    if (!chunk) return undefined;
    const index = offset - chunk.offset;
    if (index < 0 || index >= chunk.data.length) return undefined;
    // NOTE: an absent byte reads as 0 here, exactly as the backend sends it.
    // `isPresentAt` is the only authority on whether it exists.
    return chunk.data[index];
  },

  isPresentAt: (path, offset) => {
    const chunk = currentChunk(get(), path, offset);
    if (!chunk) return false;
    const index = offset - chunk.offset;
    if (index < 0 || index >= chunk.valid.length) return false;
    return chunk.valid[index] === 1;
  },

  /**
   * The check ORDER is the contract, and each step answers a different question:
   *
   *   1. `error`             — the request for this window failed. Nothing below
   *                            can be known, so it is asked first.
   *   2. `loading`           — no chunk under the LIVE identity: either it has
   *                            not arrived or it belongs to a previous anchor /
   *                            view / selection, which is the same thing here.
   *   3. `no-correspondence` — the window landed but the alignment put nothing
   *                            at this index. True for EVERY pane alike, so it
   *                            is a fact about the alignment, not about a dump.
   *   4. `not-in-dump`       — the alignment holds this index, but THIS dump does
   *                            not: the page was never captured or never mapped.
   *
   * A genuine `0x00` inside a `bytes_valid` run falls through all four and
   * returns `null` — that byte exists, and saying otherwise is the bug this
   * whole presence mask exists to prevent.
   */
  absenceAt: (path, offset) => {
    const state = get();
    const window = chunkWindowAt(state, offset);
    if (window.failure) return "error";
    const chunk = currentChunk(state, path, offset);
    if (!chunk) return "loading";
    if (classAt(window, offset) === undefined) return "no-correspondence";
    const index = offset - chunk.offset;
    if (index < 0 || index >= chunk.valid.length) return "no-correspondence";
    return chunk.valid[index] === 1 ? null : "not-in-dump";
  },

  getClassAt: (offset) => classAt(chunkWindowAt(get(), offset), offset),

  getChunkError: (offset) => get().getChunkFailure(offset)?.message ?? null,

  getChunkFailure: (offset) => chunkWindowAt(get(), offset).failure,

  getChunkErrorsInRange: (startOffset, endOffset) => {
    const state = get();
    if (!state.identity) return [];
    const found: ChunkErrorInRange[] = [];
    for (const offset of chunkStartsInRange(startOffset, endOffset)) {
      const failure = state.chunkErrors.get(cacheKeyFor(state.identity, offset));
      if (failure) found.push({ offset, message: failure.message });
    }
    return found;
  },

  variantsAt: (offset) => {
    const window = chunkWindowAt(get(), offset);
    const variants = window.variants;
    if (!variants) return undefined;
    const index = offset - window.chunkOffset;
    if (index < 0 || index >= variants.length) return undefined;
    return variants[index];
  },

  /**
   * The SERVER's answer where there is one; the client's only as a fallback.
   *
   * The server's answer is `variants >= 2` — the same predicate the producer
   * used to ship a second time as a boolean `differs` run list, and the reason
   * that field is gone. It computes over exactly the dumps the request asked
   * for. The client reducer below cannot: `byPath` keeps the chunks of dumps
   * that have since LEFT the selection (deliberately — a flip back to a
   * previous selection should hit the cache), so folding it over
   * `byPath.keys()` reported disagreement between a pane on screen and a dump
   * nobody selected. The fallback is therefore scoped to `lastRequest.paths`,
   * and exists only for a backend that does not send `variants` at all.
   */
  differsAt: (offset) => {
    const state = get();
    const window = chunkWindowAt(state, offset);
    const variants = window.variants;
    if (variants) {
      const index = offset - window.chunkOffset;
      return index >= 0 && index < variants.length && variants[index] >= 2;
    }

    const paths = state.lastRequest?.paths ?? [...state.byPath.keys()];
    let first: number | undefined;
    let present = 0;
    let differs = false;
    for (const path of paths) {
      if (!state.isPresentAt(path, offset)) continue;
      const value = state.getByteAt(path, offset);
      if (value === undefined) continue;
      present += 1;
      if (first === undefined) first = value;
      else if (value !== first) differs = true;
    }
    // An absent byte is not a difference. Counting it would flag every unmapped
    // hole in every dump and fill the screen with false positives.
    return present >= 2 && differs;
  },

  releasePaths: (keep) => {
    const keepSet = new Set(keep);
    set((prev) => {
      const byPath = new Map<string, PaneCache>();
      for (const [path, cache] of prev.byPath) {
        if (keepSet.has(path)) byPath.set(path, cache);
      }
      const chunkVersionByPath = new Map<string, number>();
      for (const [path, version] of prev.chunkVersionByPath) {
        if (keepSet.has(path)) chunkVersionByPath.set(path, version);
      }
      const pruned = pruneOrphanChunkState(
        byPath,
        prev.classChunks,
        prev.variantChunks,
        prev.chunkIdentity,
      );
      return { byPath, chunkVersionByPath, ...pruned };
    });
  },

  reset: () => {
    // Every scheduled nudge names a chunk that no longer exists; leaving one
    // alive would re-issue a request for the viewer we have just torn down.
    cancelAllRetryTimers();
    clearChunkMemos();
    set({
      byPath: new Map(),
      classChunks: new Map(),
      variantChunks: new Map(),
      chunkVersionByPath: new Map(),
      pending: new Set(),
      chunkErrors: new Map(),
      lastRequest: null,
      identity: null,
      chunkIdentity: new Map(),
      alignment: null,
      truncated: false,
      // The byte budget too: it is a tuning knob, not accumulated data, and a
      // reset that leaves a previously narrowed ceiling in place hands the next
      // window a cache that silently evicts the chunk it just fetched.
      budgetBytes: DEFAULT_BUDGET_BYTES,
    });
  },
}));

/**
 * The consensus class at `offset` inside an already-resolved chunk window.
 *
 * `-1` means gap / unclassified. Returning 0 (INVARIANT) for it would be a
 * silent lie: "every dump agrees here" about a byte no dump holds.
 */
function classAt(window: ChunkWindow, offset: number): number | undefined {
  const classes = window.classes;
  if (!classes) return undefined;
  const index = offset - window.chunkOffset;
  if (index < 0 || index >= classes.length) return undefined;
  const value = classes[index];
  return value === -1 ? undefined : value;
}

/** Does `request` already describe exactly this window request? */
function sameRequest(
  request: MultiHexState["lastRequest"],
  anchorPath: string,
  view: HexViewMode,
  paths: string[],
  consensusId: string | null,
): boolean {
  if (!request) return false;
  return (
    request.anchorPath === anchorPath &&
    request.view === view &&
    request.consensusId === consensusId &&
    samePaths(request.paths, paths)
  );
}

/**
 * The chunk holding `offset` for `path`, or undefined if stale/absent.
 *
 * Two memos deep, because this is the single hottest read in the grid: the
 * identity/staleness half comes from `chunkWindowAt`, and the one-entry memo
 * below catches the SECOND of the two calls the overlay makes per dump per
 * cell (`isPresentAt` immediately followed by `getByteAt`, which resolve the
 * very same chunk). Together that turns the six `Map.get`s a dump's byte used
 * to cost into two.
 */
function currentChunk(
  state: MultiHexState,
  path: string,
  offset: number,
): PaneChunk | undefined {
  const window = chunkWindowAt(state, offset);
  if (!window.live) return undefined;
  const chunkOffset = window.chunkOffset;
  if (
    pathMemoState === state &&
    pathMemoChunkOffset === chunkOffset &&
    pathMemoPath === path
  ) {
    return pathMemoChunk;
  }
  const chunk = state.byPath.get(path)?.chunks.get(chunkOffset);
  pathMemoState = state;
  pathMemoChunkOffset = chunkOffset;
  pathMemoPath = path;
  pathMemoChunk = chunk;
  return chunk;
}

/**
 * Issue one aligned-window request per chunk offset and fold the answers in.
 *
 * Shared by `ensureLoaded` (the automatic path) and `retryChunkAt` (the user
 * gesture) so the request shape, the stale-response guard and the failure
 * bookkeeping exist exactly once.
 */
function fetchChunks(
  set: (
    partial:
      | Partial<MultiHexState>
      | ((prev: MultiHexState) => Partial<MultiHexState>),
  ) => void,
  args: {
    identity: string;
    offsets: number[];
    anchorPath: string;
    view: HexViewMode;
    paths: string[];
    consensusId: string | null;
  },
): void {
  const { identity, offsets, anchorPath, view, paths, consensusId } = args;
  if (offsets.length === 0) return;

  /**
   * The `attempts` each of these requests must record IF it fails, read BEFORE
   * the verdicts are cleared below: 0 when nothing failed here yet, otherwise
   * one more retry spent.
   *
   * It cannot live in `chunkErrors` across the in-flight window, because that
   * entry is deliberately removed while the request is running (a request in
   * flight is not a failure, and the banner must clear). Carrying the count in
   * the closure of the very request that will report the next failure is what
   * makes `retryChunkAt` — which deletes the entry first — start over at zero.
   */
  const attemptsOnFailure = new Map<string, number>();
  const before = useMultiHexStore.getState().chunkErrors;
  for (const offset of offsets) {
    const key = cacheKeyFor(identity, offset);
    const prior = before.get(key);
    attemptsOnFailure.set(key, prior ? prior.attempts + 1 : 0);
    cancelRetryTimer(key);
  }

  set((prev) => {
    const pending = new Set(prev.pending);
    const chunkErrors = new Map(prev.chunkErrors);
    for (const offset of offsets) {
      const key = cacheKeyFor(identity, offset);
      pending.add(key);
      // A request in flight is not a failure; drop any previous verdict now
      // rather than leaving it on screen until the answer comes back.
      chunkErrors.delete(key);
    }
    return { pending, chunkErrors };
  });

  const keys = keysForPaths(paths);
  for (const chunkOffset of offsets) {
    const key = cacheKeyFor(identity, chunkOffset);
    fetchAlignedWindow({
      ...(consensusId ? { consensus_id: consensusId } : { dump_paths: paths }),
      anchor: "dump",
      anchor_path: anchorPath,
      offset: chunkOffset,
      view,
      length: CHUNK_SIZE,
      dumps: paths,
      include_bytes: true,
      ...(keys.length > 0 ? { keys } : {}),
    })
      .then((response) => {
        // Stale-response guard, mirroring `hex-store.ensureChunksLoaded`:
        // if the anchor, the view or the SELECTION changed while this was in
        // flight, the window it describes no longer corresponds to what the
        // panes are showing. Landing it anyway would paint the previous
        // selection's alignment under the current one — plausible bytes in
        // the wrong place, which nothing downstream can detect.
        if (useMultiHexStore.getState().identity !== identity) {
          set((prev) => {
            const pending = new Set(prev.pending);
            pending.delete(key);
            return { pending };
          });
          return;
        }
        set((prev) => applyResponse(prev, chunkOffset, identity, key, response));
      })
      .catch((err: unknown) => {
        // The SAME stale guard the `.then` above applies, and for a sharper
        // reason: a rejection landing after a reset (or an identity change)
        // used to write a key into the freshly-cleared `chunkErrors` and
        // re-register a handle in the just-cleared `retryTimers`, resurrecting
        // both maps — and the retry — for a viewer nobody is looking at.
        if (useMultiHexStore.getState().identity !== identity) {
          set((prev) => {
            const pending = new Set(prev.pending);
            pending.delete(key);
            return { pending };
          });
          return;
        }
        const message = readableFailure(err);
        const attempts = attemptsOnFailure.get(key) ?? 0;
        set((prev) => {
          const pending = new Set(prev.pending);
          pending.delete(key);
          // Scope the failure to the CHUNK, not to the panes.
          //
          // One request carries every selected pane, so attributing its
          // failure to each pane made a single failed look-ahead chunk paint
          // an error over panes whose visible bytes had already arrived and
          // were correct. A chunk-keyed entry says what actually happened:
          // "this window did not load", and it disappears as soon as that
          // window is re-requested or lands.
          const chunkErrors = new Map(prev.chunkErrors);
          chunkErrors.set(key, {
            message,
            attempts,
            nextRetryAt: Date.now() + retryDelayMs(attempts),
          });
          return { pending, chunkErrors };
        });
        if (attempts < MAX_CHUNK_RETRIES) {
          scheduleRetry(set, { key, identity, chunkOffset, delayMs: retryDelayMs(attempts) });
        }
      });
  }
}

/**
 * Re-issue one failed chunk once its backoff expires, if it still exists.
 *
 * Self-cancelling in both directions: the handle removes itself from
 * `retryTimers` before doing anything, and the callback re-issues NOTHING
 * unless the world it was scheduled in is still the world it wakes up in —
 * same cache identity, same request, the failure still recorded and not
 * already in flight. Any other outcome means the chunk has been superseded,
 * and a retry would be a request for a window nobody is looking at.
 */
function scheduleRetry(
  set: (
    partial:
      | Partial<MultiHexState>
      | ((prev: MultiHexState) => Partial<MultiHexState>),
  ) => void,
  args: { key: string; identity: string; chunkOffset: number; delayMs: number },
): void {
  const { key, identity, chunkOffset, delayMs } = args;
  cancelRetryTimer(key);
  const handle = setTimeout(() => {
    retryTimers.delete(key);
    const state = useMultiHexStore.getState();
    if (state.identity !== identity) return;
    const failure = state.chunkErrors.get(key);
    if (!failure || failure.attempts >= MAX_CHUNK_RETRIES) return;
    if (state.pending.has(key)) return;
    const req = state.lastRequest;
    if (!req || identityFor(req.anchorPath, req.view, req.paths) !== identity) return;
    fetchChunks(set, { identity, offsets: [chunkOffset], ...req });
  }, delayMs);
  retryTimers.set(key, handle);
}


/**
 * Fold one aligned-window response into the cache.
 *
 * Panes are filled BY `dump_path`, never by array position: the backend is free
 * to order or omit `dumps[]` as it likes, and indexing it positionally is how a
 * response for dump A ends up rendered as dump B.
 */
function applyResponse(
  prev: MultiHexState,
  chunkOffset: number,
  identity: string,
  key: string,
  response: AlignedWindowResponse,
): Partial<MultiHexState> {
  const fetchedAt = Date.now();
  const byPath = new Map(prev.byPath);
  const chunkVersionByPath = new Map(prev.chunkVersionByPath);

  for (const dump of response.dumps) {
    const data = dump.bytes ? decodeBase64(dump.bytes) : new Uint8Array(response.length);
    // A locked dump sends `bytes: null`; nothing in it is present, so the mask
    // is all zeros and every cell renders as absent rather than as 0x00.
    const valid = dump.bytes
      ? decodeRunsToMask(dump.bytes_valid, data.length)
      : new Uint8Array(response.length);
    const cache = byPath.get(dump.dump_path) ?? emptyCache();
    const chunks = new Map(cache.chunks);
    chunks.set(chunkOffset, { offset: chunkOffset, data, valid, fetchedAt });
    const lockedHint = dump.bytes === null ? dump.key_status.hint : null;
    // A successful chunk REPLACES this pane's error rather than merging with
    // it: a pane that has just handed us bytes is not in a failed state, so a
    // stale hint from an earlier response must not survive here.
    byPath.set(dump.dump_path, { chunks, error: lockedHint });
    chunkVersionByPath.set(dump.dump_path, (chunkVersionByPath.get(dump.dump_path) ?? 0) + 1);
  }

  const classChunks = new Map(prev.classChunks);
  // `new Int8Array(array)` rather than `Int8Array.from(array)`: `from` runs the
  // iterator protocol over all 8,192 elements per response, the constructor
  // does a fast array copy.
  classChunks.set(chunkOffset, new Int8Array(response.classes));

  // The server's own cross-dump findings, decoded exactly once per chunk —
  // the distinct-value counts AND, through `>= 2`, the disagreement verdict.
  //
  // Recorded only when the response really carried them: an older backend that
  // omits `variants` must fall through to the client-side comparison in
  // `differsAt`, and an all-zero array synthesised from a missing field would
  // instead assert "nobody is present anywhere" — a confident answer nobody
  // computed.
  // A response REPLACES this chunk's findings, and a response that carries
  // none removes them: these are statements about a particular set of dumps,
  // so leaving the previous selection's counts in place under a new identity
  // would answer a question nobody asked — the same failure the identity guard
  // exists to prevent, one map along.
  const variantChunks = new Map(prev.variantChunks);
  if (Array.isArray(response.variants)) {
    variantChunks.set(chunkOffset, new Uint8Array(response.variants));
  } else {
    variantChunks.delete(chunkOffset);
  }

  const chunkIdentity = new Map(prev.chunkIdentity);
  chunkIdentity.set(chunkOffset, identity);

  const side = { classChunks, variantChunks };
  const evicted = evictToBudget(byPath, prev.budgetBytes, side);
  // Nothing can be orphaned when nothing was evicted: this response only ADDED
  // chunks, and the side maps were already a subset of the held offsets before
  // it. Running the prune anyway rebuilt four Maps (~3,800 inserts) per
  // response for a result identical to its input.
  const pruned =
    evicted === byPath
      ? { classChunks, variantChunks, chunkIdentity }
      : pruneOrphanChunkState(evicted, classChunks, variantChunks, chunkIdentity);

  const pending = new Set(prev.pending);
  pending.delete(key);

  // This chunk answered; whatever it failed with last time is history.
  const chunkErrors = new Map(prev.chunkErrors);
  chunkErrors.delete(key);

  return {
    byPath: evicted,
    chunkVersionByPath,
    pending,
    chunkErrors,
    alignment: response.alignment,
    truncated: response.truncated,
    ...pruned,
  };
}
