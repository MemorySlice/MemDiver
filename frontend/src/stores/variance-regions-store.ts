/**
 * The consensus-REGIONS BROWSER: "show me every key candidate", one page at a
 * time, with a jump.
 *
 *   category chip -> selectCategory -> loadMore
 *     -> POST /api/analysis/consensus/regions
 *       -> regions[] -> jumpToIndex -> hex-store.scrollToOffset
 *
 * ── Why a dedicated slice ───────────────────────────────────────────────────
 * NOT an extension of `consensus-store`, which already does four jobs (the
 * build handle, the page-classification cache, the VA overview, the
 * incremental adoption) and is shared with the SINGLE-dump viewer. NOT an
 * extension of `multi-hex-store`, which is a byte cache. This is a third
 * thing — a paginated, identity-keyed list with a cursor — and
 * `multi-hex-store` is itself the precedent for giving that its own store.
 *
 * ── The invalidation rule this file exists to enforce ───────────────────────
 * `requestKey` includes the LIVE `hex-store.viewMode`, alongside the consensus
 * id, the anchor path, the category and `min_length`. A `"vas"` <-> `"va"`
 * switch changes the coordinate `anchor_offset` is expressed in, so without
 * that term in the key the list keeps serving offsets in the PREVIOUS
 * coordinate: every jump lands on plausible bytes in the wrong place, which is
 * precisely the class of bug that produced this session's `---` bands. It is
 * the single most likely way this feature ships broken, and
 * `tests/frontend/stores/variance-regions-store.test.ts` pins it.
 *
 * ── The coordinate rule ─────────────────────────────────────────────────────
 * `region.anchor_offset` goes to `scrollToOffset` UNMODIFIED. The server did
 * the slab -> VA -> navigable conversion so that nothing here has to. No store
 * and no component may touch `recenterWindow` / `setWindowStart`: the mounted
 * `useHexScrollTarget` honours `scrollTarget` and slides the bounded window
 * itself, so there is exactly ONE implementation of "jump to this row".
 */

import { create } from "zustand";

import {
  DEFAULT_REGION_MIN_LENGTH,
  DEFAULT_REGIONS_PER_PAGE,
  NO_HONEST_ANSWER,
  NON_INVARIANT_UNION,
  REGION_CURSOR_START,
  buildConsensusRegionsRequest,
  fetchConsensusRegions,
  type ClassRegion,
  type ConsensusRegionsQuery,
  type ConsensusRegionsSource,
  type RegionClassSpec,
} from "@/api/consensus-regions";
import { keysForPaths } from "@/api/aligned-window";
import { BYTE_CLASSES, type ByteClassName } from "@/api/candidates";
import { readableFailure } from "@/api/client";
import { CHUNK_SIZE, offsetToChunkStart } from "@/components/hex/multi-window-utils";
import { selectionKey, useConsensusStore } from "@/stores/consensus-store";
import { useHexStore, type HexViewMode } from "@/stores/hex-store";
import {
  chunkWindowAt,
  differsMaskForChunk,
  useMultiHexStore,
  type MultiHexState,
} from "@/stores/multi-hex-store";

/**
 * What the browser can list.
 *
 * The four `ByteClassName`s, plus two aliases that are NOT classes:
 *   - `"non_invariant"` — the server-side UNION. The default, and the only
 *     category that finds a real key: a planted 48-byte TLS secret classifies
 *     as 27 key_candidate + 18 pointer + 3 structural, and
 *     `classes=["key_candidate"], min_length=8` returns total 0.
 *   - `"differs"` — cross-dump disagreement, which has NO server-side
 *     whole-dump enumeration. See `windowScoped`.
 */
export type VarianceBrowseCategory = ByteClassName | "non_invariant" | "differs";

/** The category that actually finds key material. See the type doc. */
export const DEFAULT_BROWSE_CATEGORY: VarianceBrowseCategory = NON_INVARIANT_UNION;

/**
 * A row in the browser list.
 *
 * Server rows are a `ClassRegion` verbatim. Window-derived `"differs"` rows are
 * the same shape with every field the loaded window cannot honestly answer set
 * to `-1` — including `classification`, which is `null` rather than a guess
 * when the window carries no class for the run.
 *
 * The widening is one-directional: a `ClassRegion` IS a `VarianceRegion`, so a
 * consumer that only ever sees server rows loses nothing, while a consumer that
 * renders the `"differs"` list is forced by the type to handle the one case
 * where there is no class to render.
 */
export interface VarianceRegion extends Omit<ClassRegion, "classification"> {
  classification: ByteClassName | null;
}

interface VarianceRegionsState {
  /** `null` = idle: nothing selected, nothing loaded, no request in flight. */
  category: VarianceBrowseCategory | null;
  minLength: number;

  /** Offset-ordered; `loadMore` APPENDS, it never replaces. */
  regions: VarianceRegion[];
  /**
   * Size of the WHOLE result set.
   *
   * Honest for every server-backed category. For `"differs"` it is the count
   * of occurrences in the LOADED WINDOW and `windowScoped` says so — see that
   * field; a UI that prints this as a whole-dump total while `windowScoped` is
   * set is lying on the store's behalf.
   */
  total: number;
  /** The next page's cursor; `-1` = END OF LIST (never "offset zero"). */
  nextAfter: number;
  /** Index into `regions` of the row the user is on; `-1` = none yet. */
  activeIndex: number;
  loading: boolean;
  error: string | null;
  /**
   * The identity the loaded rows belong to. A page whose key differs from the
   * live one is expressed in a coordinate the viewer is no longer in and is
   * discarded rather than shown. See the module doc.
   */
  requestKey: string | null;

  // ---- additions beyond the minimum shape, each earning its place ----

  /**
   * TRUE only for `"differs"`: these rows were derived from the bytes currently
   * loaded in `multi-hex-store`, not enumerated over the whole dump.
   *
   * There is deliberately no server-side whole-dump `differs` enumeration:
   * it would cost O(size x N) UNCACHED disk I/O on a synchronous route. So the
   * store reports what it can actually see and flags it, rather than fabricating
   * a total. The UI must label it ("in view", not "12 of 4,201").
   */
  windowScoped: boolean;
  /** The WHOLE-BUILD class histogram, for the chip counts beside the list. */
  counts: Partial<Record<ByteClassName, number>>;
  /**
   * The page-level `anchor.jumpable`: `false` means every row's `anchor_offset`
   * is `-1` and the jump affordance should be HIDDEN, not attempted.
   */
  anchorJumpable: boolean;

  selectCategory(category: VarianceBrowseCategory | null): void;
  setMinLength(minLength: number): void;
  loadMore(): Promise<void>;
  jumpToIndex(index: number): void;
  jumpNext(): void;
  jumpPrev(): void;
  reset(): void;
}

/** What the rest of the app currently says the browser is looking at. */
interface BrowseContext {
  consensusId: string | null;
  anchorPath: string | null;
  /** The LIVE view mode. The term that makes `requestKey` correct. */
  viewMode: HexViewMode;
  /** The selected set, for the no-consensus `dump_paths` fallback. */
  paths: string[];
}

function liveContext(): BrowseContext {
  const hex = useHexStore.getState();
  return {
    consensusId: useConsensusStore.getState().consensusId,
    anchorPath: hex.dumpPath,
    viewMode: hex.viewMode,
    paths: useMultiHexStore.getState().lastRequest?.paths ?? [],
  };
}

/**
 * The cache identity of one query.
 *
 * `viewMode` is the load-bearing term — see the module doc. The other four are
 * the obvious ones: a different build, a different anchor, a different category
 * or a different `min_length` is a different list, and the cursor from one is
 * meaningless in another.
 */
function requestKeyFor(
  context: BrowseContext,
  category: VarianceBrowseCategory,
  minLength: number,
): string {
  return [
    context.consensusId ?? selectionKey(context.paths),
    context.anchorPath ?? "-",
    context.viewMode,
    category,
    minLength,
  ].join("|");
}

/**
 * The key the store WOULD use for this query RIGHT NOW.
 *
 * Exported so a mounted loader effect can ask "is page one for this query
 * already in the store?" without re-deriving the identity — a second copy of
 * `requestKeyFor` in a component is exactly the drift that lets a list survive
 * a `"vas"` <-> `"va"` switch and serve offsets in the previous coordinate.
 * Read-only: it computes nothing the store does not already compute, and
 * changes nothing.
 */
export function liveRequestKey(
  category: VarianceBrowseCategory,
  minLength: number,
): string {
  return requestKeyFor(liveContext(), category, minLength);
}

/**
 * The `classes` filter for a category.
 *
 * `"non_invariant"` and `"differs"` both resolve to the union alias rather than
 * to a class list: it is the server's own name for "every non-invariant band",
 * and spelling it out here would be a second copy of `core.variance`'s bands
 * waiting to drift.
 */
function classesFor(category: VarianceBrowseCategory): RegionClassSpec[] {
  if (category === "differs" || category === NON_INVARIANT_UNION) {
    return [NON_INVARIANT_UNION];
  }
  return [category];
}

/** The chunk starts `multi-hex-store` holds under its LIVE identity, in order. */
function loadedChunkStarts(cache: MultiHexState): number[] {
  if (!cache.identity) return [];
  const starts: number[] = [];
  for (const [offset, identity] of cache.chunkIdentity) {
    if (identity === cache.identity) starts.push(offset);
  }
  return starts.sort((a, b) => a - b);
}

/**
 * The dominant class over `[start, end)` of the loaded window, or `null`.
 *
 * Walks the `classes` array of each covered chunk directly rather than calling
 * `getClassAt` per offset: the run can be the whole loaded window, and at ~768
 * loaded chunks the getter version was a second multi-million `Map.get` sweep
 * on top of the `differs` one, for data already sitting in a typed array.
 */
function dominantWindowClass(
  cache: MultiHexState,
  start: number,
  end: number,
): ByteClassName | null {
  const tally = new Array<number>(BYTE_CLASSES.length).fill(0);
  let offset = start;
  while (offset < end) {
    const chunkStart = offsetToChunkStart(offset, CHUNK_SIZE);
    const classes = chunkWindowAt(cache, chunkStart).classes;
    const chunkEnd = Math.min(end, chunkStart + CHUNK_SIZE);
    if (classes) {
      const limit = Math.min(chunkEnd, chunkStart + classes.length);
      for (let o = offset; o < limit; o++) {
        // `-1` (gap) and any code outside the vocabulary are not findings.
        const code = classes[o - chunkStart];
        if (code < 0 || code >= tally.length) continue;
        tally[code] += 1;
      }
    }
    offset = chunkEnd;
  }
  let best: ByteClassName | null = null;
  let bestCount = 0;
  // Ties break toward the HIGHER-variance class, the `dominantClass` convention:
  // under-calling a half-pointer/half-key run is the costlier mistake.
  for (let code = 0; code < tally.length; code++) {
    if (tally[code] > 0 && tally[code] >= bestCount) {
      best = BYTE_CLASSES[code];
      bestCount = tally[code];
    }
  }
  return best;
}

/**
 * One window-derived `"differs"` row.
 *
 * `slab_start` / `slab_end` / `anchor_va` / `mean_variance` are `-1`: the byte
 * cache is indexed in the ANCHOR's coordinate and knows none of them, and `0`
 * would be a plausible-looking lie in all four. `length` here is the
 * ANCHOR-space run length, which is legitimate precisely because
 * `anchor_contiguous` is true by construction — the run was walked offset by
 * consecutive offset.
 */
function differsRow(
  cache: MultiHexState,
  start: number,
  end: number,
): VarianceRegion {
  return {
    slab_start: NO_HONEST_ANSWER,
    slab_end: NO_HONEST_ANSWER,
    length: end - start,
    classification: dominantWindowClass(cache, start, end),
    mean_variance: NO_HONEST_ANSWER,
    class_counts: {},
    anchor_va: NO_HONEST_ANSWER,
    anchor_offset: start,
    anchor_offset_end: end,
    anchor_contiguous: true,
  };
}

/**
 * Every cross-dump disagreement run of at least `minLength` bytes that is
 * VISIBLE IN THE LOADED WINDOW.
 *
 * Walks only the chunks `multi-hex-store` holds under its live identity, and
 * carries a run across a chunk boundary only when the next chunk is actually
 * adjacent — a gap in the loaded set is a gap in knowledge, not a run of
 * agreement.
 */
function differsRegionsInWindow(minLength: number): VarianceRegion[] {
  const cache = useMultiHexStore.getState();
  const rows: VarianceRegion[] = [];
  let runStart = -1;
  let previousEnd = -1;

  const close = (end: number) => {
    if (runStart >= 0 && end - runStart >= minLength) {
      rows.push(differsRow(cache, runStart, end));
    }
    runStart = -1;
  };

  for (const chunkStart of loadedChunkStarts(cache)) {
    if (chunkStart !== previousEnd) close(previousEnd);
    // The mask ONCE per chunk, then a typed-array scan. Asking `differsAt` per
    // offset meant ~6.3 M getter calls (~19 M `Map.get`) for a budget-bounded
    // window, and many times that when the response carried no `differs` field
    // and every offset fell through to the N-path client reducer.
    const mask = differsMaskForChunk(cache, chunkStart);
    const chunkEnd = chunkStart + CHUNK_SIZE;
    if (mask) {
      const limit = Math.min(CHUNK_SIZE, mask.length);
      for (let i = 0; i < CHUNK_SIZE; i++) {
        if (i < limit && mask[i] === 1) {
          if (runStart < 0) runStart = chunkStart + i;
        } else {
          close(chunkStart + i);
        }
      }
    } else {
      // No readable bytes here at all. `close` is a no-op once the run is shut,
      // so one call says the same thing as 8,192 of them.
      close(chunkStart);
    }
    previousEnd = chunkEnd;
  }
  close(previousEnd);
  return rows;
}

const IDLE = {
  category: null,
  minLength: DEFAULT_REGION_MIN_LENGTH,
  regions: [] as VarianceRegion[],
  total: 0,
  nextAfter: REGION_CURSOR_START,
  activeIndex: -1,
  loading: false,
  error: null,
  requestKey: null,
  windowScoped: false,
  counts: {} as Partial<Record<ByteClassName, number>>,
  anchorJumpable: false,
} satisfies Partial<VarianceRegionsState>;

/** The list-only half of a fresh query: keeps `category` / `minLength`. */
function clearedPage() {
  return {
    regions: [] as VarianceRegion[],
    total: 0,
    nextAfter: REGION_CURSOR_START,
    activeIndex: -1,
    error: null,
    counts: {} as Partial<Record<ByteClassName, number>>,
    anchorJumpable: false,
  };
}

export const useVarianceRegionsStore = create<VarianceRegionsState>((set, get) => ({
  ...IDLE,

  /**
   * Pick a category. Deliberately does NOT fetch.
   *
   * The interface is synchronous because selection is a state change and the
   * fetch is a side effect of it; the mounted effect calls `loadMore`, which is
   * also the ONE place that resolves the live context. Re-selecting the current
   * category is a no-op rather than a reload, so a stray re-render cannot
   * discard a loaded page.
   */
  selectCategory: (category) => {
    if (get().category === category) return;
    if (category === null) {
      set({ ...IDLE, minLength: get().minLength });
      return;
    }
    set({
      ...clearedPage(),
      category,
      loading: false,
      requestKey: null,
      windowScoped: category === "differs",
    });
  },

  setMinLength: (minLength) => {
    const next = Math.max(1, Math.floor(minLength));
    if (get().minLength === next) return;
    // The page is dropped, not kept: `min_length` is part of `requestKey`, so
    // rows loaded under the old one belong to a different list.
    set({ ...clearedPage(), minLength: next, requestKey: null });
  },

  loadMore: async () => {
    const { category, minLength, loading } = get();
    if (category === null || loading) return;

    const context = liveContext();
    const key = requestKeyFor(context, category, minLength);

    // `"differs"` never reaches the endpoint. There is no server-side
    // whole-dump enumeration to page through, so "more" means "recompute over
    // whatever the byte cache now holds" — which is also why it is idempotent
    // and cheap to call again on every window move.
    if (category === "differs") {
      const regions = differsRegionsInWindow(minLength);
      set({
        ...clearedPage(),
        regions,
        total: regions.length,
        nextAfter: NO_HONEST_ANSWER,
        requestKey: key,
        windowScoped: true,
        anchorJumpable: regions.length > 0,
      });
      return;
    }

    const source: ConsensusRegionsSource | null = context.consensusId
      ? { consensusId: context.consensusId }
      : context.paths.length >= 2
        ? { dumpPaths: context.paths }
        : null;
    // No build and fewer than two dumps is not an error, it is "nothing to ask
    // yet" — surfacing it as a failure banner would fire on every fresh mount.
    if (source === null) return;

    const fresh = get().requestKey !== key;
    const after = fresh ? REGION_CURSOR_START : get().nextAfter;
    // END OF LIST. `-1` here is the cursor sentinel, never offset zero.
    if (!fresh && after === NO_HONEST_ANSWER) return;

    // Cleared NOW, not when the answer lands: a key change means the loaded
    // rows are expressed in a coordinate the viewer has already left, and
    // showing them for one more round trip is the bug this store guards.
    set({
      ...(fresh ? clearedPage() : {}),
      loading: true,
      error: null,
      requestKey: key,
      windowScoped: false,
    });

    const query: ConsensusRegionsQuery = {
      classes: classesFor(category),
      minLength,
      after,
      limit: DEFAULT_REGIONS_PER_PAGE,
      anchorPath: context.anchorPath,
      anchorView: context.viewMode,
      includeAnchorOffsets: true,
      keys: keysForPaths([
        ...(context.anchorPath ? [context.anchorPath] : []),
        ...context.paths,
      ]),
    };

    try {
      const response = await fetchConsensusRegions(
        buildConsensusRegionsRequest(source, query),
      );
      // Stale-response guard, mirroring `multi-hex-store.fetchChunks`: if the
      // view, the anchor, the build or the query changed while this was in
      // flight, the offsets it carries are in the wrong coordinate.
      if (get().requestKey !== key) return;
      set((prev) => ({
        // `concat` rather than a spread literal: the page is appended in one
        // bulk copy instead of element-by-element through the spread, which
        // matters because every page re-copies every row loaded so far.
        regions: prev.regions.concat(response.regions),
        total: response.total,
        nextAfter: response.next_after,
        counts: response.counts,
        anchorJumpable: response.anchor.jumpable,
        loading: false,
      }));
    } catch (err) {
      if (get().requestKey !== key) return;
      set({ loading: false, error: readableFailure(err) });
    }
  },

  /**
   * Move the list selection to `index` and scroll the viewer to that region.
   *
   * `region.anchor_offset` is handed to `scrollToOffset` UNMODIFIED — the
   * server already converted slab -> VA -> navigable offset, and any arithmetic
   * here would be the coordinate bug this whole surface exists to delete.
   * `scrollToOffset` also sets `cursorOffset`, and the mounted
   * `useHexScrollTarget` slides the bounded window when the target is outside
   * it, so nothing here touches `recenterWindow` / `setWindowStart`.
   *
   * The cursor finishes on the region's FIRST byte — the byte the analyst
   * navigated to and the only one the jump guarantees is on screen — whether or
   * not the run also takes a selection. That is what makes the status footer's
   * `Agreement k/N` and the byte inspector describe the right byte, and it is
   * why the selection is applied with `selectRange` rather than the drag pair.
   *
   * A row with `anchor_offset < 0` REFUSES THE JUMP: the cursor, the selection
   * and the scroll target are all left exactly as they were. The list selection
   * still moves, because the user's cursor through the list is a different
   * thing from the viewer's cursor through the bytes, and freezing the former
   * would strand them on an unjumpable row with no way past it.
   */
  jumpToIndex: (index) => {
    const { regions } = get();
    if (index < 0 || index >= regions.length) return;
    const region = regions[index];
    set({ activeIndex: index });
    if (region.anchor_offset < 0) return;

    const hex = useHexStore.getState();
    hex.scrollToOffset(region.anchor_offset);
    // Selected only when the run really IS `[offset, offset_end)` in the
    // anchor's coordinate. A region that crossed an `msl_layout` page boundary
    // is contiguous in SLAB space only, so that range would be a superset and
    // highlighting it would claim bytes the region does not contain.
    if (region.anchor_contiguous && region.anchor_offset_end > region.anchor_offset) {
      // `selectRange`, NOT `startSelection` + `extendSelection`: the latter pair
      // is the drag gesture and drags `cursorOffset` to the run's LAST byte,
      // which on a multi-KiB region is hundreds of rows below the row the jump
      // just scrolled to. See `hex-store.selectRange`.
      hex.selectRange(region.anchor_offset, region.anchor_offset_end - 1);
    }
  },

  /** Next row, clamped at the end. Loading the next PAGE stays explicit. */
  jumpNext: () => {
    const { regions, activeIndex } = get();
    if (regions.length === 0) return;
    get().jumpToIndex(Math.min(activeIndex + 1, regions.length - 1));
  },

  /** Previous row, clamped at the start. */
  jumpPrev: () => {
    const { regions, activeIndex } = get();
    if (regions.length === 0) return;
    get().jumpToIndex(Math.max(activeIndex - 1, 0));
  },

  reset: () => set({ ...IDLE }),
}));
