import { create } from "zustand";
import i18n from "@/i18n";
import { decodeBase64 } from "@/utils/hex-codec";
import { getPageStates } from "@/api/client";
import type { PageState } from "@/api/types";
import { useDumpStore } from "@/stores/dump-store";

const CHUNK_SIZE = 8192; // 512 rows of 16 bytes
const MAX_CHUNKS = 12;
const BYTES_PER_ROW = 16;

interface HexChunk {
  offset: number;
  data: Uint8Array;
  fetchedAt: number;
}

export interface HighlightRegion {
  offset: number;
  length: number;
  type: "exact-match" | "entropy" | "change-point" | "pattern" | "structure" | "neighborhood" | "search" | "differential" | "constraint" | "strings";
  label: string;
  colorIndex?: number;
  /**
   * The byte view `offset` addresses. Unset = whatever view is on screen (the
   * historical contract, still right for search hits and flat dumps). Set,
   * on a dump with several distinct views, the region only paints in THAT
   * view — in any other it would mark unrelated bytes.
   */
  view?: HexViewMode;
  /**
   * Open-ended highlight kind (free slug, e.g. "vol3:task_struct", "key_hit",
   * "annotation"). When set, the region paints one of the 8 generic palette
   * slots chosen by a stable hash of this string (`kindSlot`) INSTEAD of the
   * closed `type` colour; `type` is still required and acts as the fallback.
   */
  kind?: string;
  /**
   * The dump this region belongs to. When set, a pane showing a different dump
   * does not paint it. Unset = every pane (the historical contract).
   */
  dumpPath?: string;
}

export interface Bookmark {
  offset: number;
  length: number;
  label: string;
  /**
   * The byte view `offset` addresses (the view the bookmark was taken in).
   * Unset on bookmarks saved before views were recorded: those keep the
   * historical behaviour of addressing whatever view is on screen.
   */
  view?: HexViewMode;
}

export interface NeighborhoodOverlay {
  hitOffset: number;
  hitSize: number;
  neighborhoodStart: number;
  variance: number[];
  fields: Array<{
    offset: number;
    length: number;
    type: "static" | "key_material" | "dynamic";
    label: string;
    mean_variance: number;
  }>;
}

export interface StructureOverlay {
  structureName: string;
  baseOffset: number;
  totalSize: number;
  /** The view `baseOffset`/field offsets address; unset = the view on screen. */
  view?: HexViewMode;
  fields: Array<{
    name: string;
    offset: number;
    length: number;
    display: string;
    valid: boolean;
  }>;
}

interface ByteSelection {
  anchor: number;
  active: number;
}

export type HexViewMode = "raw" | "vas" | "va";

/**
 * Flattened, va-sorted page-state interval used by getPageStateAt for an
 * RLE lookup over the "va" byte stream. `end` is the exclusive VA bound
 * (`va + length`), precomputed so lookups stay branch-cheap.
 */
interface FlatPageInterval {
  va: number;
  end: number;
  state: PageState;
}

interface HexState {
  dumpPath: string | null;
  fileSize: number;
  format: string;

  // Only meaningful for .msl dumps; .dump files ignore this.
  viewMode: HexViewMode;
  rawSize: number;  // size of the .msl container
  vasSize: number;  // size of the flat VAS projection
  vaSize: number;   // size of the sparse full virtual-address view
  // Views of the current dump that show DIFFERENT bytes, as the backend
  // detected them (`/api/inspect/hex-raw` `distinct_views`); `[]` until the
  // probe answers. More than one => the toolbar offers a view switch, for any
  // format (.msl, gcore, gdb_raw/lldb_raw), not just a `.msl` extension.
  availableViews: HexViewMode[];
  // The backend's `format_name` for the dump ("msl", "gcore", "raw", …);
  // "" until probed. Display-only: `format` stays the caller's key.
  detectedFormat: string;
  // A view asked for (by `showView`) before `availableViews` was known;
  // applied when the probe lands if the dump has it.
  requestedView: HexViewMode | null;

  // Page-state slice (three-state page model). Only fetched for .msl dumps,
  // lazily, the first time the "va" view is selected. `pageStateIntervals`
  // is sorted by `va` so getPageStateAt can binary-search it. `vaSpanStart`
  // is the base VA that "va"-view offset 0 maps to.
  pageStateIntervals: FlatPageInterval[];
  pageStatesLoaded: boolean;
  vaSpanStart: number;
  // Bumped when page-states resolve so HexRow's memoized callback rotates
  // its identity and visible rows repaint. Mirrors chunkVersion.
  pageStateVersion: number;

  chunks: Map<number, HexChunk>;
  pendingFetches: Set<number>;

  // Bumped whenever `chunks` content changes. HexViewer subscribes to
  // this to force a re-render on chunk arrivals (no other selector
  // moves when chunks load in the background).
  chunkVersion: number;

  // Last byte-fetch failure, or null when the most recent chunk load
  // succeeded. Without this a 4xx/5xx from /api/inspect/hex-raw is visually
  // identical to "not loaded yet" (both render the "--" placeholder), which
  // makes an entire class of viewer bug undiagnosable. Surfaced as a short
  // inline note in HexStatusBar — deliberately NOT a toast or a retry, since
  // rapid scrolling can legitimately abort in-flight fetches.
  chunkError: string | null;

  cursorOffset: number | null;
  selection: ByteSelection | null;
  focusColumn: "hex" | "ascii";

  highlightedRegions: HighlightRegion[];
  scrollTarget: number | null;

  // First absolute row of the bounded virtualization window. The viewer only
  // ever hands the virtualizer MAX_WINDOW_ROWS rows starting here, sliding the
  // window across the file so the spacer height stays within browser limits.
  windowStartRow: number;

  // Byte-pattern search hits (absolute offsets). Shared between the
  // toolbar search box (writer) and the viewer's SearchMinimap (reader)
  // so the two stay decoupled.
  searchOffsets: number[];

  bookmarks: Bookmark[];
  activeStructureOverlay: StructureOverlay | null;
  activeNeighborhoodOverlay: NeighborhoodOverlay | null;
  neighborhoodVarianceMap: Map<number, number>;
  activeFieldOffset: number | null;

  // Actions
  setDumpPath: (path: string, fileSize: number, format: string) => void;
  setViewSizes: (rawSize: number, vasSize: number, vaSize?: number) => void;
  setViewMode: (mode: HexViewMode) => void;
  /** Record what the backend detected; clamps a view the dump lacks. */
  setAvailableViews: (views: HexViewMode[], detectedFormat: string) => void;
  /**
   * Switch to `mode` because DATA lives there (e.g. analysis hits), without
   * persisting it as the user's preference. No-op on a single-view dump.
   */
  showView: (mode: HexViewMode) => void;
  fetchPageStates: () => void;
  getPageStateAt: (offset: number) => PageState | undefined;
  reset: () => void;
  ensureChunksLoaded: (startRow: number, endRow: number) => void;
  getByteAt: (offset: number) => number | undefined;

  setCursor: (offset: number) => void;
  startSelection: (offset: number) => void;
  extendSelection: (offset: number) => void;
  /**
   * Select `[start, endInclusive]` WITHOUT moving `cursorOffset`.
   *
   * `startSelection` + `extendSelection` is the DRAG gesture, and there the
   * cursor rightly tracks the selection's active end — that is where the
   * pointer (or the shift-arrow) is. A programmatic JUMP is the other gesture:
   * the analyst navigated TO a region, so the cursor belongs on the byte they
   * navigated to. Composing the drag pair for a jump dragged the cursor to the
   * region's LAST byte, which on an 8 KiB region is 511 rows below anything on
   * screen — and every cursor-driven readout (`Agreement k/N`, the byte
   * inspector) then described a byte the analyst could not see. Hence a
   * separate action: `extendSelection`'s contract is left exactly as the grid's
   * drag handling needs it.
   */
  selectRange: (start: number, endInclusive: number) => void;
  clearSelection: () => void;
  setFocusColumn: (col: "hex" | "ascii") => void;

  scrollToOffset: (offset: number) => void;
  clearScrollTarget: () => void;
  setWindowStart: (row: number) => void;

  setHighlightedRegions: (regions: HighlightRegion[]) => void;
  setSearchOffsets: (offsets: number[]) => void;

  addBookmark: (b: Bookmark) => void;
  removeBookmark: (offset: number, length: number) => void;
  /** Remove exactly this bookmark (offset, length AND view). */
  removeBookmarkEntry: (b: Bookmark) => void;
  /**
   * Scroll the cursor to a bookmark, first switching (non-persisted) to the
   * view it was taken in so the same byte is shown.
   */
  jumpToBookmark: (b: Bookmark) => void;
  setActiveStructureOverlay: (overlay: StructureOverlay | null) => void;
  setActiveNeighborhoodOverlay: (overlay: NeighborhoodOverlay | null) => void;
  setActiveFieldOffset: (offset: number | null) => void;
}

function evictLruChunks(chunks: Map<number, HexChunk>): Map<number, HexChunk> {
  if (chunks.size <= MAX_CHUNKS) return chunks;
  const sorted = [...chunks.entries()].sort(
    (a, b) => a[1].fetchedAt - b[1].fetchedAt,
  );
  const evictCount = chunks.size - MAX_CHUNKS;
  const next = new Map(chunks);
  for (let i = 0; i < evictCount; i++) {
    next.delete(sorted[i][0]);
  }
  return next;
}

function chunkAlignedOffset(offset: number): number {
  return Math.floor(offset / CHUNK_SIZE) * CHUNK_SIZE;
}

async function fetchChunkData(
  dumpPath: string,
  offset: number,
  length: number,
  view: HexViewMode,
): Promise<Uint8Array> {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
    view,
  });
  const key = useDumpStore.getState().getKeyMaterialByPath(dumpPath);
  if (key?.passphrase) qs.set("passphrase", key.passphrase);
  if (key?.key_hex) qs.set("key_hex", key.key_hex);
  if (key?.kem_key_hex) qs.set("kem_key_hex", key.kem_key_hex);
  const res = await fetch(`/api/inspect/hex-raw?${qs.toString()}`);
  if (!res.ok) {
    throw new Error(i18n.t("hex:fetchErrors.hex", { status: res.status }));
  }
  const json = await res.json();
  if (json.error) {
    throw new Error(json.error);
  }
  return decodeBase64(json.bytes);
}

/** The backend `format_name` of an `.mdview` image view (a process / kernel / physical layer). */
export const IMAGE_VIEW_FORMAT = "image_view";

/**
 * Whether the backend can answer `/api/inspect/page-states` for this dump: an
 * `.msl` (by the caller's key) or an image view (by what the backend detected —
 * an `.mdview` is a plain "raw" dump as far as the extension goes).
 */
export function servesPageStates(format: string, detectedFormat: string): boolean {
  return format === "msl" || detectedFormat === IMAGE_VIEW_FORMAT;
}

/** An image view that has a "vas" projection opens on it instead of "raw". */
function opensOnVas(detectedFormat: string, views: readonly HexViewMode[]): boolean {
  return detectedFormat === IMAGE_VIEW_FORMAT && views.includes("vas");
}

const VIEW_MODE_KEY = "memdiver:hex:viewMode";
const BOOKMARKS_KEY_PREFIX = "memdiver:hex:bookmarks:";

function loadInitialViewMode(): HexViewMode {
  if (typeof localStorage === "undefined") return "raw";
  const stored = localStorage.getItem(VIEW_MODE_KEY);
  if (stored === "vas") return "vas";
  if (stored === "va") return "va";
  return "raw";
}

function persistViewMode(mode: HexViewMode): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(VIEW_MODE_KEY, mode);
  } catch {
    /* ignore quota errors */
  }
}

function bookmarksKey(dumpPath: string): string {
  return `${BOOKMARKS_KEY_PREFIX}${dumpPath}`;
}

function loadBookmarksFor(dumpPath: string | null): Bookmark[] {
  if (!dumpPath || typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(bookmarksKey(dumpPath));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (b): b is Bookmark =>
        b &&
        typeof b.offset === "number" &&
        typeof b.length === "number" &&
        typeof b.label === "string" &&
        (b.view === undefined || isHexViewMode(b.view)),
    );
  } catch {
    return [];
  }
}

function isHexViewMode(value: unknown): value is HexViewMode {
  return value === "raw" || value === "vas" || value === "va";
}

/** Same bookmarked region: same offset, length and view. */
function isSameBookmark(a: Bookmark, b: Bookmark): boolean {
  return a.offset === b.offset && a.length === b.length && a.view === b.view;
}

function persistBookmarksFor(
  dumpPath: string | null,
  bookmarks: Bookmark[],
): void {
  if (!dumpPath || typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(bookmarksKey(dumpPath), JSON.stringify(bookmarks));
  } catch {
    /* ignore quota errors */
  }
}

export const useHexStore = create<HexState>((set, get) => ({
  dumpPath: null,
  fileSize: 0,
  format: "",
  viewMode: loadInitialViewMode(),
  rawSize: 0,
  vasSize: 0,
  vaSize: 0,
  availableViews: [],
  detectedFormat: "",
  requestedView: null,

  pageStateIntervals: [],
  pageStatesLoaded: false,
  vaSpanStart: 0,
  pageStateVersion: 0,

  chunks: new Map(),
  pendingFetches: new Set(),
  chunkVersion: 0,
  chunkError: null,

  cursorOffset: null,
  selection: null,
  focusColumn: "hex",

  highlightedRegions: [],
  scrollTarget: null,
  windowStartRow: 0,
  searchOffsets: [],
  bookmarks: [],
  activeStructureOverlay: null,
  activeNeighborhoodOverlay: null,
  neighborhoodVarianceMap: new Map(),
  activeFieldOffset: null,

  setDumpPath: (path, fileSize, format) =>
    set((state) => {
      // Only fully reset when the dump actually changes. Re-firing on
      // the same path with a new fileSize (e.g. pathInfo settling from
      // 0 to the real size) would otherwise nuke in-flight chunks.
      if (state.dumpPath === path && state.format === format) {
        // File size may have just become known — update sizes without
        // clobbering chunks or cursor state.
        const nextRaw = state.rawSize || fileSize;
        const nextVas = state.vasSize || fileSize;
        const nextVa = state.vaSize || fileSize;
        const nextFile =
          state.viewMode === "vas"
            ? nextVas
            : state.viewMode === "va"
              ? nextVa
              : nextRaw;
        if (
          state.fileSize === nextFile &&
          state.rawSize === nextRaw &&
          state.vasSize === nextVas &&
          state.vaSize === nextVa
        ) {
          return {};
        }
        return { fileSize: nextFile, rawSize: nextRaw, vasSize: nextVas, vaSize: nextVa };
      }
      return {
        dumpPath: path,
        fileSize,
        format,
        // For raw .dump files the sizes collapse; MSL callers overwrite
        // these via setViewSizes once /hex-raw returns.
        rawSize: fileSize,
        vasSize: fileSize,
        vaSize: fileSize,
        // Re-probed for the new dump (useMslViewSizes).
        availableViews: [],
        detectedFormat: "",
        requestedView: null,
        // Page states belong to the previous dump — clear them so the
        // "va" view re-fetches for the new file.
        pageStateIntervals: [],
        pageStatesLoaded: false,
        vaSpanStart: 0,
        pageStateVersion: 0,
        chunks: new Map(),
        pendingFetches: new Set(),
        chunkVersion: 0,
        // A failure belonged to the previous dump; the new one starts clean.
        chunkError: null,
        cursorOffset: null,
        selection: null,
        highlightedRegions: [],
        scrollTarget: null,
        windowStartRow: 0,
        searchOffsets: [],
        bookmarks: loadBookmarksFor(path),
        activeStructureOverlay: null,
        activeNeighborhoodOverlay: null,
        neighborhoodVarianceMap: new Map(),
        activeFieldOffset: null,
      };
    }),

  setViewSizes: (rawSize, vasSize, vaSize) =>
    set((state) => {
      const nextVa = vaSize ?? state.vaSize;
      const size =
        state.viewMode === "vas"
          ? vasSize
          : state.viewMode === "va"
            ? nextVa
            : rawSize;
      if (
        state.rawSize === rawSize &&
        state.vasSize === vasSize &&
        state.vaSize === nextVa &&
        state.fileSize === size
      ) {
        return {};
      }
      return { rawSize, vasSize, vaSize: nextVa, fileSize: size };
    }),

  setViewMode: (mode) => applyViewMode(mode, true),

  setAvailableViews: (views, detectedFormat) => {
    const { requestedView, viewMode } = get();
    set({ availableViews: views, detectedFormat, requestedView: null });
    if (views.length <= 1) return;
    if (requestedView && views.includes(requestedView)) {
      applyViewMode(requestedView, false);
    } else if (!views.includes(viewMode)) {
      // e.g. a persisted "va" (an .msl-only view) on a gcore core: the
      // backend would refuse every chunk. Fall back without persisting.
      applyViewMode(views[0], false);
    } else if (viewMode === "raw" && opensOnVas(detectedFormat, views)) {
      // An image view's "raw" is the multi-GB image file it was cut from, not
      // the view. Open on the view's own bytes, as an `.msl` leaves "raw".
      applyViewMode("vas", false);
    }
  },

  showView: (mode) => {
    const { availableViews } = get();
    if (availableViews.length === 0) {
      set({ requestedView: mode });
      return;
    }
    if (availableViews.length > 1 && availableViews.includes(mode)) {
      applyViewMode(mode, false);
    }
  },

  fetchPageStates: () => {
    const { dumpPath, pageStatesLoaded, format, detectedFormat } = get();
    if (!dumpPath || pageStatesLoaded || !servesPageStates(format, detectedFormat)) return;
    const key = useDumpStore.getState().getKeyMaterialByPath(dumpPath);
    getPageStates(dumpPath, key)
      .then((data) => {
        // Ignore a stale response if the dump changed mid-flight.
        if (useHexStore.getState().dumpPath !== dumpPath) return;
        const flat: FlatPageInterval[] = [];
        let spanStart = Infinity;
        for (const region of data.regions) {
          if (region.base_addr < spanStart) spanStart = region.base_addr;
          for (const iv of region.intervals) {
            flat.push({ va: iv.va, end: iv.va + iv.length, state: iv.state });
          }
        }
        flat.sort((a, b) => a.va - b.va);
        set((prev) => ({
          pageStateIntervals: flat,
          pageStatesLoaded: true,
          vaSpanStart: Number.isFinite(spanStart) ? spanStart : 0,
          pageStateVersion: prev.pageStateVersion + 1,
        }));
      })
      .catch(() => {
        // Leave pageStatesLoaded false; the "va" view simply renders
        // uncolored (bytes only) until a retry succeeds.
      });
  },

  getPageStateAt: (offset: number): PageState | undefined => {
    const { pageStatesLoaded, pageStateIntervals, vaSpanStart } = get();
    if (!pageStatesLoaded) return undefined;
    const va = vaSpanStart + offset;
    let lo = 0;
    let hi = pageStateIntervals.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const iv = pageStateIntervals[mid];
      if (va < iv.va) hi = mid - 1;
      else if (va >= iv.end) lo = mid + 1;
      else return iv.state;
    }
    // A VA that falls in an inter-region gap of the sparse "va" span is
    // genuinely unmapped memory.
    return "UNMAPPED";
  },

  reset: () =>
    set({
      dumpPath: null,
      fileSize: 0,
      format: "",
      rawSize: 0,
      vasSize: 0,
      vaSize: 0,
      availableViews: [],
      detectedFormat: "",
      requestedView: null,
      pageStateIntervals: [],
      pageStatesLoaded: false,
      vaSpanStart: 0,
      pageStateVersion: 0,
      chunks: new Map(),
      pendingFetches: new Set(),
      chunkVersion: 0,
      chunkError: null,
      cursorOffset: null,
      selection: null,
      focusColumn: "hex",
      highlightedRegions: [],
      scrollTarget: null,
      windowStartRow: 0,
      searchOffsets: [],
      bookmarks: [],
      activeStructureOverlay: null,
      activeNeighborhoodOverlay: null,
      neighborhoodVarianceMap: new Map(),
      activeFieldOffset: null,
    }),

  ensureChunksLoaded: (startRow: number, endRow: number) => {
    const state = get();
    if (!state.dumpPath) return;

    const prefetchMargin = 2 * CHUNK_SIZE;
    const startOffset = Math.max(
      0,
      chunkAlignedOffset(startRow * BYTES_PER_ROW) - prefetchMargin,
    );
    const endOffset = Math.min(
      state.fileSize,
      chunkAlignedOffset(endRow * BYTES_PER_ROW) + CHUNK_SIZE + prefetchMargin,
    );

    const neededChunks: number[] = [];
    for (let off = startOffset; off < endOffset; off += CHUNK_SIZE) {
      const aligned = chunkAlignedOffset(off);
      if (!state.chunks.has(aligned) && !state.pendingFetches.has(aligned)) {
        neededChunks.push(aligned);
      }
    }

    if (neededChunks.length === 0) return;

    const dumpPath = state.dumpPath;
    const view = state.viewMode;
    const nextPending = new Set(state.pendingFetches);
    for (const off of neededChunks) {
      nextPending.add(off);
    }
    set({ pendingFetches: nextPending });

    for (const chunkOffset of neededChunks) {
      const length = Math.min(CHUNK_SIZE, state.fileSize - chunkOffset);
      fetchChunkData(dumpPath, chunkOffset, length, view)
        .then((data) => {
          // Ignore stale fetches from a previous view mode OR a previous
          // dump. Dropping the dumpPath half of this guard would let a
          // chunk requested for dump A land in dump B's freshly-cleared
          // chunk map after setDumpPath(B) — the viewer would then render
          // A's bytes while every label claims B. Mirrors the same-dump
          // guard in fetchPageStates.
          const live = useHexStore.getState();
          if (live.viewMode !== view || live.dumpPath !== dumpPath) {
            set((prev) => {
              const pending = new Set(prev.pendingFetches);
              pending.delete(chunkOffset);
              return { pendingFetches: pending };
            });
            return;
          }
          set((prev) => {
            const chunks = new Map(prev.chunks);
            chunks.set(chunkOffset, {
              offset: chunkOffset,
              data,
              fetchedAt: Date.now(),
            });
            const evicted = evictLruChunks(chunks);

            const pending = new Set(prev.pendingFetches);
            pending.delete(chunkOffset);

            return {
              chunks: evicted,
              pendingFetches: pending,
              chunkVersion: prev.chunkVersion + 1,
              // Bytes arrived, so whatever failed before is no longer the
              // current state of the viewer.
              chunkError: null,
            };
          });
        })
        .catch((err: unknown) => {
          const message = err instanceof Error ? err.message : String(err);
          set((prev) => {
            const pending = new Set(prev.pendingFetches);
            pending.delete(chunkOffset);
            return { pendingFetches: pending, chunkError: message };
          });
        });
    }
  },

  getByteAt: (offset: number): number | undefined => {
    const aligned = chunkAlignedOffset(offset);
    const chunk = get().chunks.get(aligned);
    if (!chunk) return undefined;
    const index = offset - chunk.offset;
    if (index < 0 || index >= chunk.data.length) return undefined;
    // Touch the chunk so LRU eviction treats on-screen chunks as the most
    // recently used. Every visible byte is read through getByteAt on each
    // render, so this keeps the current viewport from being evicted (which
    // would flash empty cells on a back-jump). Mutated in place to avoid
    // triggering a re-render.
    chunk.fetchedAt = Date.now();
    return chunk.data[index];
  },

  setCursor: (offset) =>
    set((state) => (state.cursorOffset === offset ? {} : { cursorOffset: offset })),

  startSelection: (offset) =>
    set({ selection: { anchor: offset, active: offset }, cursorOffset: offset }),

  extendSelection: (offset) =>
    set((state) => {
      if (!state.selection) return {};
      if (state.selection.active === offset && state.cursorOffset === offset) return {};
      return {
        selection: { ...state.selection, active: offset },
        cursorOffset: offset,
      };
    }),

  // Cursor-preserving by design — see the interface doc.
  selectRange: (start, endInclusive) =>
    set((state) =>
      state.selection &&
      state.selection.anchor === start &&
      state.selection.active === endInclusive
        ? {}
        : { selection: { anchor: start, active: endInclusive } },
    ),

  clearSelection: () =>
    set((state) => (state.selection === null ? {} : { selection: null })),

  setFocusColumn: (col) =>
    set((state) => (state.focusColumn === col ? {} : { focusColumn: col })),

  scrollToOffset: (offset) =>
    set({
      scrollTarget: Math.floor(offset / BYTES_PER_ROW),
      cursorOffset: offset,
    }),

  clearScrollTarget: () => set({ scrollTarget: null }),

  setWindowStart: (row) => set({ windowStartRow: row }),

  setHighlightedRegions: (regions) => set({ highlightedRegions: regions }),

  setSearchOffsets: (offsets) => set({ searchOffsets: offsets }),

  addBookmark: (input) =>
    set((state) => {
      // Record the view the offset addresses (the viewer's current view unless
      // the caller said otherwise), so jumping back lands on the same byte.
      const b: Bookmark = { ...input, view: input.view ?? state.viewMode };
      // Dedupe on (offset, length, view): a second bookmark at the same offset
      // but a different length — or in a different view, i.e. a different
      // byte — is a distinct region and must not be dropped. If an
      // identical-region bookmark exists, update its label in place rather than
      // silently no-op'ing.
      const existingIndex = state.bookmarks.findIndex((existing) => isSameBookmark(existing, b));
      let bookmarks: Bookmark[];
      if (existingIndex >= 0) {
        if (state.bookmarks[existingIndex].label === b.label) return {};
        bookmarks = state.bookmarks.map((existing, i) =>
          i === existingIndex ? { ...existing, label: b.label } : existing,
        );
      } else {
        bookmarks = [...state.bookmarks, b];
      }
      persistBookmarksFor(state.dumpPath, bookmarks);
      return { bookmarks };
    }),

  removeBookmark: (offset, length) =>
    set((state) => {
      const bookmarks = state.bookmarks.filter(
        (b) => b.offset !== offset || b.length !== length,
      );
      persistBookmarksFor(state.dumpPath, bookmarks);
      return { bookmarks };
    }),

  removeBookmarkEntry: (entry) =>
    set((state) => {
      const bookmarks = state.bookmarks.filter((b) => !isSameBookmark(b, entry));
      if (bookmarks.length === state.bookmarks.length) return {};
      persistBookmarksFor(state.dumpPath, bookmarks);
      return { bookmarks };
    }),

  jumpToBookmark: (b) => {
    // Switch first: a view switch clears the cursor and scroll target, so the
    // scroll below must come after it. `showView` is a no-op on a
    // single-view dump and does not overwrite the persisted preference.
    if (b.view && b.view !== get().viewMode) get().showView(b.view);
    get().scrollToOffset(b.offset);
  },

  setActiveStructureOverlay: (overlay) =>
    set((state) => {
      // Remove old structure highlights, add new ones
      const nonStructure = state.highlightedRegions.filter(
        (r) => r.type !== "structure",
      );
      if (!overlay) {
        return {
          activeStructureOverlay: null,
          highlightedRegions: nonStructure,
        };
      }
      const fieldRegions: HighlightRegion[] = overlay.fields.map((f, i) => ({
        offset: f.offset,
        length: f.length,
        type: "structure" as const,
        label: f.display || f.name,
        colorIndex: i,
        ...(overlay.view ? { view: overlay.view } : {}),
      }));
      return {
        activeStructureOverlay: overlay,
        highlightedRegions: [...nonStructure, ...fieldRegions],
        activeFieldOffset: null,
      };
    }),

  setActiveNeighborhoodOverlay: (overlay) =>
    set((state) => {
      // Remove old neighborhood highlights
      const withoutNeighborhood = state.highlightedRegions.filter(
        (r) => r.type !== "neighborhood",
      );
      if (!overlay) {
        return {
          activeNeighborhoodOverlay: null,
          neighborhoodVarianceMap: new Map(),
          highlightedRegions: withoutNeighborhood,
        };
      }
      // Build variance map: absolute offset -> variance value
      const varianceMap = new Map<number, number>();
      for (let i = 0; i < overlay.variance.length; i++) {
        varianceMap.set(overlay.neighborhoodStart + i, overlay.variance[i]);
      }
      // Create highlight regions from neighborhood fields
      const fieldRegions: HighlightRegion[] = overlay.fields.map((f, i) => ({
        offset: f.offset,
        length: f.length,
        type: "neighborhood" as const,
        label: `${f.label} (${f.type})`,
        colorIndex: i,
      }));
      return {
        activeNeighborhoodOverlay: overlay,
        activeStructureOverlay: null, // mutually exclusive
        neighborhoodVarianceMap: varianceMap,
        highlightedRegions: [...withoutNeighborhood, ...fieldRegions],
      };
    }),

  setActiveFieldOffset: (offset) =>
    set((state) => (state.activeFieldOffset === offset ? {} : { activeFieldOffset: offset })),
}));

// Shared by setViewMode (user choice, persisted) and the data-driven
// switches (showView / setAvailableViews), which must not overwrite the
// user's remembered preference.
function applyViewMode(mode: HexViewMode, persist: boolean): void {
  const get = useHexStore.getState;
  const set = useHexStore.setState;
  const changed = get().viewMode !== mode;
  set((state) => {
    if (state.viewMode === mode) return {};
    if (persist) persistViewMode(mode);
    const size =
      mode === "vas"
        ? state.vasSize
        : mode === "va"
          ? state.vaSize
          : state.rawSize;
    return {
      viewMode: mode,
      fileSize: size || state.fileSize,
      // Flipping views changes what every byte means — nuke chunks.
      //
      // NOTE: clearing `chunks` here is only half the job. Nothing in the
      // store re-fetches; the refill comes from HexViewer's visible-range
      // effect, which therefore MUST list `viewMode` in its dependency
      // array (see the comment there). Without it the viewer sits at
      // scrollTop 0 with an empty chunk map and every cell renders "--".
      chunks: new Map(),
      pendingFetches: new Set(),
      chunkVersion: state.chunkVersion + 1,
      // The failure (if any) described bytes in the outgoing view.
      chunkError: null,
      cursorOffset: null,
      selection: null,
      scrollTarget: null,
      windowStartRow: 0,
    };
  });
  // Page-state coloring is only needed in the "va" view; fetch lazily the
  // first time it is selected.
  if (changed && mode === "va") {
    get().fetchPageStates();
  }
}
