/**
 * Heap analysis state, per dump path.
 *
 *   detection  -> GET /api/heap/detect
 *   summary    -> GET /api/heap/summary
 *   chunk pages-> GET /api/heap/chunks     (cached per filters/view/page)
 *   free lists -> GET /api/heap/free-lists
 *   role layer -> GET /api/heap/roles      (aligned 64 KiB windows)
 *
 * ── The hex layer ────────────────────────────────────────────────────────────
 * The role layer is deliberately NOT a set of `hex-store.highlightedRegions`:
 * the left-walk lookup in `highlight-utils` collapses on a 100 KiB top chunk.
 * Instead the store fetches role runs in windows aligned to
 * `HEAP_ROLE_WINDOW_SIZE`, keyed by (dumpPath, view, windowStart), indexes them
 * (`@/utils/heap-roles`) and answers per-byte lookups by binary search. Every
 * window arrival bumps `roleWindowsVersion`, which is the ONE value a viewer
 * subscribes to in order to rotate its getter identity and repaint.
 *
 * ── Staleness ────────────────────────────────────────────────────────────────
 * Changing a dump's allocator invalidates everything derived from it. A
 * per-dump generation counter makes a response that lands after such a change
 * a no-op instead of resurrecting the old allocator's answer.
 */

import { create } from "zustand";

import i18n from "@/i18n";
import { ApiError, readableFailure, type DumpViewMode } from "@/api/client";
import {
  DEFAULT_HEAP_ALLOCATOR,
  fetchHeapChunks,
  fetchHeapDetect,
  fetchHeapFreeLists,
  fetchHeapRoles,
  fetchHeapSummary,
  type HeapChunkFilters,
} from "@/api/heap";
import type {
  HeapAllocatorChoice,
  HeapChunk,
  HeapChunksResponse,
  HeapDetectResponse,
  HeapFreeListsResponse,
  HeapRoleRun,
  HeapSummaryResponse,
} from "@/api/types";
import { useDumpStore } from "@/stores/dump-store";
import {
  HEAP_ROLE_NAME_BY_CODE,
  HEAP_ROLE_NONE,
  buildRoleWindow,
  isChunkStartInWindow,
  packedCellInWindow,
  roleCodeInWindow,
  upperBound,
  type RoleWindow,
} from "@/utils/heap-roles";

/** Role windows are fetched aligned to this many bytes. */
export const HEAP_ROLE_WINDOW_SIZE = 64 * 1024;

/** How many role windows (across all dumps/views) stay cached. */
export const HEAP_MAX_ROLE_WINDOWS = 48;

/** Default page size of the chunk table. */
export const HEAP_DEFAULT_PAGE_SIZE = 200;

export type HeapLoadStatus = "idle" | "loading" | "ready" | "error";

/** Which request failed — selects the localized error message. */
export type HeapRequestKind = "detect" | "summary" | "chunks" | "freeLists" | "roles";

export interface HeapDumpEntry {
  allocator: HeapAllocatorChoice;
  layerEnabled: boolean;
  detection: HeapDetectResponse | null;
  detectionStatus: HeapLoadStatus;
  detectionError: string | null;
  summary: HeapSummaryResponse | null;
  summaryStatus: HeapLoadStatus;
  summaryError: string | null;
  /** Keyed by `chunkPageKey(filters, view, page, pageSize)`. */
  chunkPages: Record<string, HeapChunksResponse>;
  chunksStatus: HeapLoadStatus;
  chunksError: string | null;
  freeLists: HeapFreeListsResponse | null;
  freeListsStatus: HeapLoadStatus;
  freeListsError: string | null;
  filters: HeapChunkFilters;
  selectedChunk: HeapChunk | null;
  /** The last role-window failure, localized; cleared on the next success. */
  layerError: string | null;
}

export interface HeapChunkPageRequest {
  page?: number;
  pageSize?: number;
  view?: DumpViewMode;
}

interface CachedRoleWindow extends RoleWindow {
  fetchedAt: number;
}

export interface HeapState {
  dumps: Record<string, HeapDumpEntry>;
  roleWindows: Record<string, CachedRoleWindow>;
  /** Bumped on every role-window arrival or eviction; subscribe to repaint. */
  roleWindowsVersion: number;

  setAllocator: (dumpPath: string, allocator: HeapAllocatorChoice) => void;
  setLayerEnabled: (dumpPath: string, enabled: boolean) => void;
  toggleLayer: (dumpPath: string) => void;
  setFilters: (dumpPath: string, patch: Partial<HeapChunkFilters>) => void;
  resetFilters: (dumpPath: string) => void;
  selectChunk: (dumpPath: string, chunk: HeapChunk | null) => void;
  clearDump: (dumpPath: string) => void;

  loadDetection: (dumpPath: string) => Promise<void>;
  loadSummary: (dumpPath: string) => Promise<void>;
  loadChunkPage: (dumpPath: string, req?: HeapChunkPageRequest) => Promise<void>;
  loadFreeLists: (dumpPath: string) => Promise<void>;
  /** Fetch every missing aligned role window covering `[start, end)`. */
  ensureRoleWindows: (
    dumpPath: string,
    view: DumpViewMode,
    start: number,
    end: number,
  ) => Promise<void>;

  /** Role code at `offset` (see `HEAP_ROLE_CODE`), or `HEAP_ROLE_NONE`. */
  roleAt: (dumpPath: string, view: DumpViewMode, offset: number) => number;
  isChunkStart: (dumpPath: string, view: DumpViewMode, offset: number) => boolean;
  /** Packed `role | HEAP_CHUNK_START_BIT` — the hex row's per-byte primitive. */
  heapCellAt: (dumpPath: string, view: DumpViewMode, offset: number) => number;
  /** Cached runs overlapping `[start, end)`, clipped to it, in order. */
  roleRunsForWindow: (
    dumpPath: string,
    view: DumpViewMode,
    start: number,
    end: number,
  ) => HeapRoleRun[];
}

/** The filter set a fresh dump starts with: no constraint. */
export const EMPTY_HEAP_FILTERS: HeapChunkFilters = Object.freeze({});

function emptyEntry(): HeapDumpEntry {
  return {
    allocator: DEFAULT_HEAP_ALLOCATOR,
    layerEnabled: false,
    detection: null,
    detectionStatus: "idle",
    detectionError: null,
    summary: null,
    summaryStatus: "idle",
    summaryError: null,
    chunkPages: {},
    chunksStatus: "idle",
    chunksError: null,
    freeLists: null,
    freeListsStatus: "idle",
    freeListsError: null,
    filters: EMPTY_HEAP_FILTERS,
    selectedChunk: null,
    layerError: null,
  };
}

/** Shared, frozen stand-in for a dump the store has never seen. */
export const EMPTY_HEAP_DUMP: Readonly<HeapDumpEntry> = Object.freeze(emptyEntry());

/** Start of the aligned role window containing `offset`. */
export function roleWindowStart(offset: number): number {
  return Math.floor(offset / HEAP_ROLE_WINDOW_SIZE) * HEAP_ROLE_WINDOW_SIZE;
}

/** Cache key of one role window. */
export function roleWindowKey(dumpPath: string, view: DumpViewMode, start: number): string {
  return `${dumpPath}\u0000${view}\u0000${start}`;
}

/** Cache key of one chunk-table page. */
export function chunkPageKey(
  filters: HeapChunkFilters,
  view: DumpViewMode | undefined,
  page: number,
  pageSize: number,
): string {
  const f = filters;
  return [
    f.state ?? "",
    f.minSize ?? "",
    f.maxSize ?? "",
    f.vaStart ?? "",
    f.vaEnd ?? "",
    f.offset ?? "",
    f.length ?? "",
    view ?? "",
    page,
    pageSize,
  ].join("|");
}

/** A localized sentence for a failed heap request. */
export function heapErrorMessage(kind: HeapRequestKind, err: unknown): string {
  const detail = readableFailure(err);
  if (err instanceof ApiError && err.status === 404) {
    return i18n.t("heap:errors.notFound", { detail });
  }
  return i18n.t(`heap:errors.${kind}`, { detail });
}

// Module-level bookkeeping that never drives a render.
const generations = new Map<string, number>();
const inFlightWindows = new Set<string>();
const failedWindows = new Set<string>();

function generationOf(dumpPath: string): number {
  return generations.get(dumpPath) ?? 0;
}

function bumpGeneration(dumpPath: string): void {
  generations.set(dumpPath, generationOf(dumpPath) + 1);
}

function forgetWindowBookkeeping(dumpPath: string): void {
  const prefix = `${dumpPath}\u0000`;
  for (const set of [inFlightWindows, failedWindows]) {
    for (const key of [...set]) if (key.startsWith(prefix)) set.delete(key);
  }
}

function dropDumpWindows(
  windows: Record<string, CachedRoleWindow>,
  dumpPath: string,
): Record<string, CachedRoleWindow> {
  const prefix = `${dumpPath}\u0000`;
  const kept: Record<string, CachedRoleWindow> = {};
  for (const [key, win] of Object.entries(windows)) {
    if (!key.startsWith(prefix)) kept[key] = win;
  }
  return kept;
}

/** Drop the oldest windows until at most `HEAP_MAX_ROLE_WINDOWS` remain. */
function evictOldest(windows: Record<string, CachedRoleWindow>): Record<string, CachedRoleWindow> {
  const entries = Object.entries(windows);
  if (entries.length <= HEAP_MAX_ROLE_WINDOWS) return windows;
  entries.sort((a, b) => b[1].fetchedAt - a[1].fetchedAt);
  return Object.fromEntries(entries.slice(0, HEAP_MAX_ROLE_WINDOWS));
}

let fetchClock = 0;

export const useHeapStore = create<HeapState>((set, get) => {
  /** Immutable update of one dump's entry. */
  function patchDump(dumpPath: string, patch: Partial<HeapDumpEntry>): void {
    set((s) => ({
      dumps: {
        ...s.dumps,
        [dumpPath]: { ...(s.dumps[dumpPath] ?? emptyEntry()), ...patch },
      },
    }));
  }

  function entryOf(dumpPath: string): HeapDumpEntry {
    return get().dumps[dumpPath] ?? EMPTY_HEAP_DUMP;
  }

  function requestBase(dumpPath: string) {
    return {
      dumpPath,
      allocator: entryOf(dumpPath).allocator,
      key: useDumpStore.getState().getKeyMaterialByPath(dumpPath),
    };
  }

  function windowAt(dumpPath: string, view: DumpViewMode, offset: number) {
    return get().roleWindows[roleWindowKey(dumpPath, view, roleWindowStart(offset))];
  }

  /**
   * Run one load, guarding against a response from a superseded allocator.
   * `onOk` / `onFail` return the entry patch to apply.
   */
  async function guardedLoad<T>(
    dumpPath: string,
    kind: HeapRequestKind,
    loading: Partial<HeapDumpEntry>,
    fetcher: () => Promise<T>,
    onOk: (value: T) => Partial<HeapDumpEntry>,
    onFail: (message: string) => Partial<HeapDumpEntry>,
  ): Promise<void> {
    const generation = generationOf(dumpPath);
    patchDump(dumpPath, loading);
    try {
      const value = await fetcher();
      if (generation !== generationOf(dumpPath)) return;
      patchDump(dumpPath, onOk(value));
    } catch (err) {
      if (generation !== generationOf(dumpPath)) return;
      patchDump(dumpPath, onFail(heapErrorMessage(kind, err)));
    }
  }

  async function fetchOneWindow(
    dumpPath: string,
    view: DumpViewMode,
    start: number,
  ): Promise<void> {
    const key = roleWindowKey(dumpPath, view, start);
    const generation = generationOf(dumpPath);
    inFlightWindows.add(key);
    try {
      const response = await fetchHeapRoles({
        ...requestBase(dumpPath),
        view,
        offset: start,
        length: HEAP_ROLE_WINDOW_SIZE,
      });
      if (generation !== generationOf(dumpPath)) return;
      const indexed = buildRoleWindow(response, start, start + HEAP_ROLE_WINDOW_SIZE);
      set((s) => ({
        roleWindows: evictOldest({
          ...s.roleWindows,
          [key]: { ...indexed, fetchedAt: ++fetchClock },
        }),
        roleWindowsVersion: s.roleWindowsVersion + 1,
      }));
      if (entryOf(dumpPath).layerError !== null) patchDump(dumpPath, { layerError: null });
    } catch (err) {
      if (generation !== generationOf(dumpPath)) return;
      // Remembered so a scroll burst does not retry a failing window per frame;
      // toggling the layer or changing the allocator clears it.
      failedWindows.add(key);
      patchDump(dumpPath, { layerError: heapErrorMessage("roles", err) });
    } finally {
      inFlightWindows.delete(key);
    }
  }

  return {
    dumps: {},
    roleWindows: {},
    roleWindowsVersion: 0,

    setAllocator: (dumpPath, allocator) => {
      if (entryOf(dumpPath).allocator === allocator) return;
      bumpGeneration(dumpPath);
      forgetWindowBookkeeping(dumpPath);
      const previous = entryOf(dumpPath);
      set((s) => ({
        dumps: {
          ...s.dumps,
          [dumpPath]: {
            ...emptyEntry(),
            allocator,
            layerEnabled: previous.layerEnabled,
            filters: previous.filters,
          },
        },
        roleWindows: dropDumpWindows(s.roleWindows, dumpPath),
        roleWindowsVersion: s.roleWindowsVersion + 1,
      }));
    },

    setLayerEnabled: (dumpPath, enabled) => {
      if (entryOf(dumpPath).layerEnabled === enabled) return;
      if (enabled) forgetWindowBookkeeping(dumpPath);
      patchDump(dumpPath, { layerEnabled: enabled, layerError: null });
    },

    toggleLayer: (dumpPath) => {
      get().setLayerEnabled(dumpPath, !entryOf(dumpPath).layerEnabled);
    },

    setFilters: (dumpPath, patch) => {
      patchDump(dumpPath, {
        filters: { ...entryOf(dumpPath).filters, ...patch },
        chunkPages: {},
      });
    },

    resetFilters: (dumpPath) => {
      patchDump(dumpPath, { filters: EMPTY_HEAP_FILTERS, chunkPages: {} });
    },

    selectChunk: (dumpPath, chunk) => {
      patchDump(dumpPath, { selectedChunk: chunk });
    },

    clearDump: (dumpPath) => {
      bumpGeneration(dumpPath);
      forgetWindowBookkeeping(dumpPath);
      set((s) => {
        const dumps = { ...s.dumps };
        delete dumps[dumpPath];
        return {
          dumps,
          roleWindows: dropDumpWindows(s.roleWindows, dumpPath),
          roleWindowsVersion: s.roleWindowsVersion + 1,
        };
      });
    },

    loadDetection: (dumpPath) =>
      guardedLoad(
        dumpPath,
        "detect",
        { detectionStatus: "loading", detectionError: null },
        () => fetchHeapDetect(requestBase(dumpPath)),
        (detection) => ({ detection, detectionStatus: "ready" }),
        (message) => ({ detectionStatus: "error", detectionError: message }),
      ),

    loadSummary: (dumpPath) =>
      guardedLoad(
        dumpPath,
        "summary",
        { summaryStatus: "loading", summaryError: null },
        () => fetchHeapSummary(requestBase(dumpPath)),
        (summary) => ({ summary, summaryStatus: "ready" }),
        (message) => ({ summaryStatus: "error", summaryError: message }),
      ),

    loadChunkPage: (dumpPath, req = {}) => {
      const page = req.page ?? 0;
      const pageSize = req.pageSize ?? HEAP_DEFAULT_PAGE_SIZE;
      const filters = entryOf(dumpPath).filters;
      const key = chunkPageKey(filters, req.view, page, pageSize);
      if (entryOf(dumpPath).chunkPages[key]) return Promise.resolve();
      return guardedLoad(
        dumpPath,
        "chunks",
        { chunksStatus: "loading", chunksError: null },
        () => fetchHeapChunks({ ...requestBase(dumpPath), filters, view: req.view, page, pageSize }),
        (response) => ({
          chunkPages: { ...entryOf(dumpPath).chunkPages, [key]: response },
          chunksStatus: "ready",
        }),
        (message) => ({ chunksStatus: "error", chunksError: message }),
      );
    },

    loadFreeLists: (dumpPath) =>
      guardedLoad(
        dumpPath,
        "freeLists",
        { freeListsStatus: "loading", freeListsError: null },
        () => fetchHeapFreeLists(requestBase(dumpPath)),
        (freeLists) => ({ freeLists, freeListsStatus: "ready" }),
        (message) => ({ freeListsStatus: "error", freeListsError: message }),
      ),

    ensureRoleWindows: async (dumpPath, view, start, end) => {
      if (!entryOf(dumpPath).layerEnabled || end <= start) return;
      const pending: Promise<void>[] = [];
      const cached = get().roleWindows;
      for (let w = roleWindowStart(start); w < end; w += HEAP_ROLE_WINDOW_SIZE) {
        const key = roleWindowKey(dumpPath, view, w);
        if (cached[key] || inFlightWindows.has(key) || failedWindows.has(key)) continue;
        pending.push(fetchOneWindow(dumpPath, view, w));
      }
      await Promise.all(pending);
    },

    roleAt: (dumpPath, view, offset) => {
      const win = windowAt(dumpPath, view, offset);
      return win ? roleCodeInWindow(win, offset) : HEAP_ROLE_NONE;
    },

    isChunkStart: (dumpPath, view, offset) => {
      const win = windowAt(dumpPath, view, offset);
      return win ? isChunkStartInWindow(win, offset) : false;
    },

    heapCellAt: (dumpPath, view, offset) => {
      const win = windowAt(dumpPath, view, offset);
      return win ? packedCellInWindow(win, offset) : HEAP_ROLE_NONE;
    },

    roleRunsForWindow: (dumpPath, view, start, end) => {
      const runs: HeapRoleRun[] = [];
      const windows = get().roleWindows;
      for (let w = roleWindowStart(start); w < end; w += HEAP_ROLE_WINDOW_SIZE) {
        const win = windows[roleWindowKey(dumpPath, view, w)];
        if (!win) continue;
        // First run that could overlap `start`: the one containing it, or the
        // first that begins after it.
        let i = Math.max(0, upperBound(win.runStarts, start) - 1);
        for (; i < win.runStarts.length && win.runStarts[i] < end; i++) {
          const s = Math.max(win.runStarts[i], start);
          const e = Math.min(win.runEnds[i], end);
          const role = HEAP_ROLE_NAME_BY_CODE[win.runCodes[i]];
          if (e > s && role) runs.push({ offset: s, length: e - s, role });
        }
      }
      return runs;
    },
  };
});

/** Scoped selector: one dump's entry (stable `EMPTY_HEAP_DUMP` when unseen). */
export const selectHeapDump =
  (dumpPath: string | null | undefined) =>
  (s: HeapState): Readonly<HeapDumpEntry> =>
    (dumpPath ? s.dumps[dumpPath] : undefined) ?? EMPTY_HEAP_DUMP;

/** Scoped selector: whether the hex heap layer is on for `dumpPath`. */
export const selectHeapLayerEnabled =
  (dumpPath: string | null | undefined) =>
  (s: HeapState): boolean =>
    dumpPath ? (s.dumps[dumpPath]?.layerEnabled ?? false) : false;

/** Test-only: reset module bookkeeping alongside `useHeapStore.setState`. */
export function __resetHeapStoreBookkeeping(): void {
  generations.clear();
  inFlightWindows.clear();
  failedWindows.clear();
  fetchClock = 0;
}
