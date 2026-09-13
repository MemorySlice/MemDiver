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
 */

import { create } from "zustand";
import { decodeBase64 } from "@/utils/hex-codec";
import { fetchAlignedWindow } from "@/api/aligned-window";
import type {
  AlignedWindowKey,
  AlignedWindowResponse,
} from "@/api/aligned-window";
import { useDumpStore } from "@/stores/dump-store";
import type { HexViewMode } from "@/stores/hex-store";
import {
  CHUNK_SIZE,
  chunkRangeForRows,
  decodeRunsToMask,
  offsetToChunkStart,
  prefetchChunksForPaneCount,
} from "@/components/hex/multi-window-utils";

const DEFAULT_BUDGET_BYTES = 24 * 1024 * 1024;

interface PaneChunk {
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

  /** Window-index consensus classes, one Int16Array per chunk. `-1` = gap. */
  classChunks: Map<number, Int16Array>;

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
  chunkErrors: Map<string, string>;

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
  getClassAt(offset: number): number | undefined;
  /** The failure (if any) recorded for the chunk holding `offset`. */
  getChunkError(offset: number): string | null;
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
  const selectionKey = [...paths].sort().join(",");
  return `${anchorPath}|${view}|${selectionKey}`;
}

function cacheKeyFor(identity: string, chunkOffset: number): string {
  return `${identity}|${chunkOffset}`;
}

/** Bytes a chunk costs: the window bytes plus its same-length presence mask. */
function chunkCost(chunk: PaneChunk): number {
  return chunk.data.byteLength + chunk.valid.byteLength;
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
): Map<string, PaneCache> {
  const entries: { path: string; offset: number; fetchedAt: number; cost: number }[] = [];
  let total = 0;
  for (const [path, cache] of byPath) {
    for (const [offset, chunk] of cache.chunks) {
      const cost = chunkCost(chunk);
      total += cost;
      entries.push({ path, offset, fetchedAt: chunk.fetchedAt, cost });
    }
  }
  if (total <= budgetBytes) return byPath;

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
  }
  return next;
}

/** Drop class chunks (and identities) no pane holds bytes for any more. */
function pruneOrphanChunkState(
  byPath: Map<string, PaneCache>,
  classChunks: Map<number, Int16Array>,
  chunkIdentity: Map<number, string>,
): { classChunks: Map<number, Int16Array>; chunkIdentity: Map<number, string> } {
  const held = new Set<number>();
  for (const cache of byPath.values()) {
    for (const offset of cache.chunks.keys()) held.add(offset);
  }
  const nextClasses = new Map<number, Int16Array>();
  for (const [offset, classes] of classChunks) {
    if (held.has(offset)) nextClasses.set(offset, classes);
  }
  const nextIdentity = new Map<number, string>();
  for (const [offset, id] of chunkIdentity) {
    if (held.has(offset)) nextIdentity.set(offset, id);
  }
  return { classChunks: nextClasses, chunkIdentity: nextIdentity };
}

/** Key material for the selected paths, with secret-less dumps left out. */
function keysForPaths(paths: string[]): AlignedWindowKey[] {
  const lookup = useDumpStore.getState().getKeyMaterialByPath;
  const keys: AlignedWindowKey[] = [];
  for (const dump_path of paths) {
    const material = lookup(dump_path);
    if (!material) continue;
    if (!material.passphrase && !material.key_hex && !material.kem_key_hex) continue;
    keys.push({
      dump_path,
      ...(material.passphrase ? { passphrase: material.passphrase } : {}),
      ...(material.key_hex ? { key_hex: material.key_hex } : {}),
      ...(material.kem_key_hex ? { kem_key_hex: material.kem_key_hex } : {}),
    });
  }
  return keys;
}

function emptyCache(): PaneCache {
  return { chunks: new Map(), error: null };
}

/**
 * A sentence a human can read, out of whatever `fetchAlignedWindow` rejected with.
 *
 * `api/client.request` throws `ApiError` carrying the RAW response body, so an
 * error surfaced verbatim reads
 * `{"error":"anchor offset does not name an addressable byte","category":…}`.
 * Unwrapping the envelope's own message is the difference between a note the
 * analyst can act on and a JSON blob in the middle of the UI.
 */
export function readableFailure(err: unknown): string {
  const raw = (err instanceof Error ? err.message : String(err)).trim();
  if (!raw.startsWith("{")) return raw;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      const envelope = parsed as { error?: unknown; detail?: unknown; message?: unknown };
      for (const field of [envelope.error, envelope.detail, envelope.message]) {
        if (typeof field === "string" && field.trim() !== "") return field.trim();
      }
    }
  } catch {
    // Not JSON after all — the raw text is the best we have.
  }
  return raw;
}

export const useMultiHexStore = create<MultiHexState>((set, get) => ({
  byPath: new Map(),
  classChunks: new Map(),
  chunkVersionByPath: new Map(),
  pending: new Set(),
  chunkErrors: new Map(),
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
      // described the previous anchor/view/selection.
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

    const state = get();
    const needed = chunkStarts.filter((offset) => {
      const key = cacheKeyFor(identity, offset);
      if (state.pending.has(key)) return false;
      if (state.chunkIdentity.get(offset) !== identity) return true;
      // Held under this identity — only refetch if some selected pane is
      // missing it (a pane joined after the chunk landed, or it was evicted).
      return paths.some((path) => !state.byPath.get(path)?.chunks.has(offset));
    });
    if (needed.length === 0) return;

    const nextPending = new Set(state.pending);
    const nextErrors = new Map(get().chunkErrors);
    for (const offset of needed) {
      const key = cacheKeyFor(identity, offset);
      nextPending.add(key);
      // A retry in flight is not a failure; drop the previous verdict now
      // rather than leaving it on screen until the answer comes back.
      nextErrors.delete(key);
    }
    set({ pending: nextPending, chunkErrors: nextErrors });

    const keys = keysForPaths(paths);
    for (const chunkOffset of needed) {
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
          const message = readableFailure(err);
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
            chunkErrors.set(key, message);
            return { pending, chunkErrors };
          });
        });
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

  getClassAt: (offset) => {
    const state = get();
    const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
    if (!state.identity) return undefined;
    if (state.chunkIdentity.get(chunkOffset) !== state.identity) return undefined;
    const classes = state.classChunks.get(chunkOffset);
    if (!classes) return undefined;
    const index = offset - chunkOffset;
    if (index < 0 || index >= classes.length) return undefined;
    const value = classes[index];
    // `-1` means gap / unclassified. Returning 0 (INVARIANT) for it would be a
    // silent lie: "every dump agrees here" about a byte no dump holds.
    return value === -1 ? undefined : value;
  },

  getChunkError: (offset) => {
    const state = get();
    if (!state.identity) return null;
    const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
    return state.chunkErrors.get(cacheKeyFor(state.identity, chunkOffset)) ?? null;
  },

  differsAt: (offset) => {
    const state = get();
    let first: number | undefined;
    let present = 0;
    let differs = false;
    for (const path of state.byPath.keys()) {
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
      const pruned = pruneOrphanChunkState(byPath, prev.classChunks, prev.chunkIdentity);
      return { byPath, chunkVersionByPath, ...pruned };
    });
  },

  reset: () =>
    set({
      byPath: new Map(),
      classChunks: new Map(),
      chunkVersionByPath: new Map(),
      pending: new Set(),
      chunkErrors: new Map(),
      identity: null,
      chunkIdentity: new Map(),
      alignment: null,
      truncated: false,
    }),
}));

/** The chunk holding `offset` for `path`, or undefined if stale/absent. */
function currentChunk(
  state: MultiHexState,
  path: string,
  offset: number,
): PaneChunk | undefined {
  if (!state.identity) return undefined;
  const chunkOffset = offsetToChunkStart(offset, CHUNK_SIZE);
  if (state.chunkIdentity.get(chunkOffset) !== state.identity) return undefined;
  return state.byPath.get(path)?.chunks.get(chunkOffset);
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
  classChunks.set(chunkOffset, Int16Array.from(response.classes));
  const chunkIdentity = new Map(prev.chunkIdentity);
  chunkIdentity.set(chunkOffset, identity);

  const evicted = evictToBudget(byPath, prev.budgetBytes);
  const pruned = pruneOrphanChunkState(evicted, classChunks, chunkIdentity);

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
