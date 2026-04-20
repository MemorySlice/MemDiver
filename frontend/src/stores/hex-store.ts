import { create } from "zustand";
import { decodeBase64 } from "@/utils/hex-codec";

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
}

export interface Bookmark {
  offset: number;
  length: number;
  label: string;
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

export type HexViewMode = "raw" | "vas";

interface HexState {
  dumpPath: string | null;
  fileSize: number;
  format: string;

  // Only meaningful for .msl dumps; .dump files ignore this.
  viewMode: HexViewMode;
  rawSize: number;  // size of the .msl container
  vasSize: number;  // size of the flat VAS projection

  chunks: Map<number, HexChunk>;
  pendingFetches: Set<number>;

  // Bumped whenever `chunks` content changes. HexViewer subscribes to
  // this to force a re-render on chunk arrivals (no other selector
  // moves when chunks load in the background).
  chunkVersion: number;

  cursorOffset: number | null;
  selection: ByteSelection | null;
  focusColumn: "hex" | "ascii";

  highlightedRegions: HighlightRegion[];
  scrollTarget: number | null;

  bookmarks: Bookmark[];
  activeStructureOverlay: StructureOverlay | null;
  activeNeighborhoodOverlay: NeighborhoodOverlay | null;
  neighborhoodVarianceMap: Map<number, number>;
  activeFieldOffset: number | null;

  // Actions
  setDumpPath: (path: string, fileSize: number, format: string) => void;
  setViewSizes: (rawSize: number, vasSize: number) => void;
  setViewMode: (mode: HexViewMode) => void;
  reset: () => void;
  ensureChunksLoaded: (startRow: number, endRow: number) => void;
  getByteAt: (offset: number) => number | undefined;

  setCursor: (offset: number) => void;
  startSelection: (offset: number) => void;
  extendSelection: (offset: number) => void;
  clearSelection: () => void;
  setFocusColumn: (col: "hex" | "ascii") => void;

  scrollToOffset: (offset: number) => void;
  clearScrollTarget: () => void;

  setHighlightedRegions: (regions: HighlightRegion[]) => void;

  addBookmark: (b: Bookmark) => void;
  removeBookmark: (offset: number) => void;
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
  const url =
    `/api/inspect/hex-raw?dump_path=${encodeURIComponent(dumpPath)}` +
    `&offset=${offset}&length=${length}&view=${view}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Hex fetch failed: ${res.status}`);
  }
  const json = await res.json();
  if (json.error) {
    throw new Error(json.error);
  }
  return decodeBase64(json.bytes);
}

const VIEW_MODE_KEY = "memdiver:hex:viewMode";
const BOOKMARKS_KEY_PREFIX = "memdiver:hex:bookmarks:";

function loadInitialViewMode(): HexViewMode {
  if (typeof localStorage === "undefined") return "raw";
  const stored = localStorage.getItem(VIEW_MODE_KEY);
  return stored === "vas" ? "vas" : "raw";
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
        typeof b.label === "string",
    );
  } catch {
    return [];
  }
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

  chunks: new Map(),
  pendingFetches: new Set(),
  chunkVersion: 0,

  cursorOffset: null,
  selection: null,
  focusColumn: "hex",

  highlightedRegions: [],
  scrollTarget: null,
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
        const nextFile = state.viewMode === "vas" ? nextVas : nextRaw;
        if (
          state.fileSize === nextFile &&
          state.rawSize === nextRaw &&
          state.vasSize === nextVas
        ) {
          return {};
        }
        return { fileSize: nextFile, rawSize: nextRaw, vasSize: nextVas };
      }
      return {
        dumpPath: path,
        fileSize,
        format,
        // For raw .dump files the two sizes collapse; MSL callers
        // overwrite these via setViewSizes once /hex-raw returns.
        rawSize: fileSize,
        vasSize: fileSize,
        chunks: new Map(),
        pendingFetches: new Set(),
        chunkVersion: 0,
        cursorOffset: null,
        selection: null,
        highlightedRegions: [],
        scrollTarget: null,
        bookmarks: loadBookmarksFor(path),
        activeStructureOverlay: null,
        activeNeighborhoodOverlay: null,
        neighborhoodVarianceMap: new Map(),
        activeFieldOffset: null,
      };
    }),

  setViewSizes: (rawSize, vasSize) =>
    set((state) => {
      const size = state.viewMode === "vas" ? vasSize : rawSize;
      if (
        state.rawSize === rawSize &&
        state.vasSize === vasSize &&
        state.fileSize === size
      ) {
        return {};
      }
      return { rawSize, vasSize, fileSize: size };
    }),

  setViewMode: (mode) =>
    set((state) => {
      if (state.viewMode === mode) return {};
      persistViewMode(mode);
      const size = mode === "vas" ? state.vasSize : state.rawSize;
      return {
        viewMode: mode,
        fileSize: size || state.fileSize,
        // Flipping views changes what every byte means — nuke chunks.
        chunks: new Map(),
        pendingFetches: new Set(),
        chunkVersion: state.chunkVersion + 1,
        cursorOffset: null,
        selection: null,
        scrollTarget: null,
      };
    }),

  reset: () =>
    set({
      dumpPath: null,
      fileSize: 0,
      format: "",
      rawSize: 0,
      vasSize: 0,
      chunks: new Map(),
      pendingFetches: new Set(),
      chunkVersion: 0,
      cursorOffset: null,
      selection: null,
      focusColumn: "hex",
      highlightedRegions: [],
      scrollTarget: null,
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
          // Ignore stale fetches from a previous view mode.
          if (useHexStore.getState().viewMode !== view) {
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
            };
          });
        })
        .catch(() => {
          set((prev) => {
            const pending = new Set(prev.pendingFetches);
            pending.delete(chunkOffset);
            return { pendingFetches: pending };
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

  setHighlightedRegions: (regions) => set({ highlightedRegions: regions }),

  addBookmark: (b) =>
    set((state) => {
      if (state.bookmarks.some((existing) => existing.offset === b.offset)) {
        return {};
      }
      const bookmarks = [...state.bookmarks, b];
      persistBookmarksFor(state.dumpPath, bookmarks);
      return { bookmarks };
    }),

  removeBookmark: (offset) =>
    set((state) => {
      const bookmarks = state.bookmarks.filter((b) => b.offset !== offset);
      persistBookmarksFor(state.dumpPath, bookmarks);
      return { bookmarks };
    }),

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
