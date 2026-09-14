import { useCallback } from "react";
import { create } from "zustand";

import { useDumpStore } from "./dump-store";

// Cap on cached page-classification entries. Scrolling a large dump would
// otherwise grow pageClassifications without bound; once the cap is hit we
// drop the oldest entries (Map preserves insertion order).
const MAX_CACHED_PAGES = 256;

interface StaticRegion {
  start: number;
  end: number;
  length: number;
  mean_variance: number;
}

// Down-sampled change/variance heatmap over a dump's whole VA span, used by
// the ConsensusVarianceMinimap. `changing[i]`/`high[i]` are per-bin fractions
// (0..1); `level[i]` is the peak ByteClass code (0..3) in bin i.
interface VaOverview {
  va_start: number;
  va_end: number;
  bin_size: number;
  changing: number[];
  high: number[];
  level: number[];
}

/**
 * The three band boundaries this build's classes were actually cut at.
 *
 * Echoed by `POST /api/analysis/consensus` from `core.variance`'s resolved
 * `VarianceThresholds`, so a legend can state the numbers that produced the
 * classes on screen instead of a second, silently-drifting copy of
 * `0 / 200 / 3000` living in the frontend. `null` means "this build did not
 * report them" (an older backend, or an incremental fold) — which a legend must
 * render as "unknown", never as zero.
 */
export interface VarianceThresholds {
  /** `variance <= invariant_max` is INVARIANT. */
  invariant_max: number;
  /** ... and up to `structural_max` is STRUCTURAL. */
  structural_max: number;
  /** ... up to `pointer_max` is POINTER; above it is KEY_CANDIDATE. */
  pointer_max: number;
}

/** A finalized incremental session, as the consensus store sees it. */
export interface IncrementalAdoption {
  consensusId: string;
  size: number;
  numDumps: number;
  counts: Record<string, number> | null;
}

/**
 * Does a build made over `builtFrom` describe `paths`?
 *
 * Sorted-join equality, the SAME convention `multi-hex-store.identityFor` uses
 * to key its byte cache — and for the same reason: `classes`, the gaps and the
 * cross-dump "differs" verdict are computed across the WHOLE set, so add or
 * remove one dump and every one of them can change while the anchor, the view
 * and the offset did not. Order is not part of the question; membership is.
 *
 * An EMPTY `builtFrom` is permissive on purpose. It means "this build cannot
 * say which dumps it covers" (see `adoptIncremental`), and reporting that as a
 * mismatch would fence off a consensus that is very likely correct. Unknown is
 * not the same as wrong.
 */
export function consensusCoversSelection(
  builtFrom: readonly string[],
  paths: readonly string[],
): boolean {
  if (builtFrom.length === 0) return true;
  return selectionKey(builtFrom) === selectionKey(paths);
}

/**
 * The order-insensitive identity of a dump selection.
 *
 * ONE spelling of the convention described above, so a cache key, a consensus
 * coverage check and a memo dependency cannot drift apart by one `.sort()`.
 */
export function selectionKey(paths: readonly string[]): string {
  return [...paths].sort().join(",");
}

interface ConsensusState {
  available: boolean;
  loading: boolean;
  /**
   * Is a build REQUESTED FROM THE UI currently in flight?
   *
   * Distinct from `loading`, which only `runConsensus` itself maintains: this
   * one is owned by `useConsensusRun` and is what every re-run affordance
   * disables itself on. Four of them render at once in the overlay, so a
   * per-component `useState` meant clicking one left the other three live and
   * a second build could be issued over the first.
   */
  runInFlight: boolean;
  error: string | null;
  size: number;
  numDumps: number;
  counts: Record<string, number> | null;
  /** The bands `counts` was cut at; `null` when the build did not report them. */
  thresholds: VarianceThresholds | null;
  staticRegions: StaticRegion[];
  volatileRegions: StaticRegion[];
  overlayEnabled: boolean;

  // Server-assigned id of the most recent consensus build. Range queries are
  // scoped to this id so concurrent clients can't read each other's results.
  consensusId: string | null;
  /**
   * The dump paths THIS build was made over, as the server echoed them.
   *
   * Without it a `consensusId` is unattributable, and the aligned-window
   * overlay happily projects a build made over {X, Y} onto a later selection
   * {A, B}: wrong slab, wrong classes, wrong gaps, bogus "Differs" rings — all
   * of it plausible-looking. Empty means "not known" (an incremental fold), not
   * "no dumps"; `consensusCoversSelection` treats the two differently.
   */
  builtFrom: string[];
  /** Whether this build normalized ASLR — the other half of "which build". */
  builtNormalized: boolean;
  pageClassifications: Map<number, number[]>;

  // VA-keyed classifications for the hex viewer's "va" view of .msl dumps.
  // The container offset overlay (pageClassifications) is coordinate-wrong for
  // .msl because the classification array lives in an aligned-slab coordinate;
  // these are keyed by row-aligned ABSOLUTE virtual address instead.
  vaClassifications: Map<number, number[]>;
  vaOverview: VaOverview | null;

  runConsensus: (dumpPaths: string[], normalize: boolean) => Promise<void>;
  /**
   * Adopt a FINALIZED incremental session as the consensus the rest of the app
   * reads.
   *
   * `ConsensusSessionManager` is one process-wide singleton shared by
   * `api/routers/consensus.py` and `api/routers/analysis.py`, and
   * `/analysis/consensus/range` resolves its `consensus_id` through
   * `manager.get(...)`. So a finalized incremental `session_id` IS a valid
   * `consensus_id` — without this, Finalize was a dead end: the id landed in
   * `consensus-incremental-store.finalResult` and nothing ever read it.
   *
   * Note the fold is FLAT (offset-keyed Welford), so `staticRegions` /
   * `volatileRegions` / the VA caches stay empty: there is no alignment to
   * report and the VA endpoints reject a non-aligned build.
   */
  adoptIncremental: (adoption: IncrementalAdoption) => void;
  /**
   * Was this consensus built over exactly `paths`?
   *
   * Reads `builtFrom` live, so it is safe to hold as a stable selector value;
   * a component that must RE-RENDER when the answer changes has to subscribe
   * to `builtFrom` as well (or call `consensusCoversSelection` directly).
   */
  matchesSelection: (paths: string[]) => boolean;
  setOverlayEnabled: (enabled: boolean) => void;
  fetchRange: (offset: number, length: number) => Promise<number[]>;
  fetchVaRange: (dumpPath: string, va: number, length: number) => Promise<number[]>;
  fetchVaOverview: (dumpPath: string, bins: number) => Promise<void>;
  toggleOverlay: () => void;
  reset: () => void;
}

/**
 * Which build is the CURRENT one.
 *
 * `useConsensusRun`'s in-flight flag stops a second build being started from
 * the four affordances that offer one, but it is not — and cannot be — the
 * whole answer: `runConsensus` is a store action and anything holding the
 * store can call it directly, which is exactly how the dump list used to issue
 * a build the flag never saw. Two builds in flight then race, and because the
 * responses land in whatever order the server finishes them, the EARLIER one
 * could overwrite `consensusId` / `builtFrom` / `builtNormalized` and leave the
 * viewers projecting a superseded build onto the grid.
 *
 * A generation counter answers that at the only place it can be answered — the
 * moment a response is about to be written. Module scope rather than store
 * state because nothing renders it: it is bookkeeping about this client, the
 * same argument `multi-hex-store`'s retry timers make.
 */
let runGeneration = 0;

export const useConsensusStore = create<ConsensusState>((set, get) => ({
  available: false,
  loading: false,
  runInFlight: false,
  error: null,
  size: 0,
  numDumps: 0,
  counts: null,
  thresholds: null,
  staticRegions: [],
  volatileRegions: [],
  overlayEnabled: false,
  consensusId: null,
  builtFrom: [],
  builtNormalized: false,
  pageClassifications: new Map(),
  vaClassifications: new Map(),
  vaOverview: null,

  runConsensus: async (dumpPaths, normalize) => {
    // Claimed BEFORE the request goes out, compared after it lands: a run that
    // is no longer the newest writes nothing at all — not the build, not the
    // error, and not `loading`, which belongs to whichever run is still going.
    const generation = ++runGeneration;
    set({ loading: true, error: null });
    try {
      const res = await fetch("/api/analysis/consensus", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dump_paths: dumpPaths, normalize }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Consensus failed: ${res.status} ${detail}`);
      }
      const json = await res.json();
      if (generation !== runGeneration) return;
      set({
        available: true,
        loading: false,
        size: json.size ?? 0,
        numDumps: json.num_dumps ?? 0,
        counts: json.counts ?? null,
        // `null` rather than a client-side default: an older backend that does
        // not echo the bands has NOT told us they were 0/200/3000, and a legend
        // that prints them anyway is the drifting second copy this field
        // exists to delete.
        thresholds: json.thresholds ?? null,
        staticRegions: json.static_regions ?? [],
        volatileRegions: json.volatile_regions ?? [],
        consensusId: json.consensus_id ?? null,
        // The server echoes the set it built over; fall back to the paths we
        // asked for rather than to `[]`, so an older backend that does not
        // echo still yields a checkable build.
        builtFrom: json.dump_paths ?? [...dumpPaths],
        builtNormalized: json.normalize ?? normalize,
        pageClassifications: new Map(),
        vaClassifications: new Map(),
        vaOverview: null,
      });
    } catch (err) {
      if (generation !== runGeneration) return;
      /**
       * The PREVIOUS build is deliberately left standing.
       *
       * A failed rebuild says nothing about the build already in the store: it
       * was computed over real dumps and, where `builtFrom` still covers the
       * selection, it is still the correct answer for them. Clearing
       * `consensusId` here would drop the viewers behind `NoConsensusPrompt`
       * and throw away a usable alignment because a LATER request 500'd, and
       * where the selection has moved on `consensusCoversSelection` already
       * fences the stale build off without any help from this branch.
       *
       * What was missing is not the blanking, it is the SAYING SO: `error` is
       * the record that the rebuild failed and that the grid is therefore
       * still the older build, and `ConsensusErrorBanner` puts it on the hex
       * surface where the bytes it qualifies are.
       */
      set({
        loading: false,
        error: err instanceof Error ? err.message : String(err),
        // `available` describes the LAST request, not the data: an id still in
        // the store keeps `fetchRange` answering, exactly as before.
        available: false,
      });
    }
  },

  adoptIncremental: ({ consensusId, size, numDumps, counts }) => {
    // A finalized session is a NEWER build than anything still on the wire, so
    // it claims the generation too — otherwise a `runConsensus` started before
    // Finalize lands afterwards and quietly replaces the adopted id.
    runGeneration += 1;
    set({
      available: true,
      loading: false,
      error: null,
      size,
      numDumps,
      counts,
      // An incremental fold reports no bands, and inventing them here would
      // put numbers on a legend that never cut these classes.
      thresholds: null,
      staticRegions: [],
      volatileRegions: [],
      consensusId,
      // An incremental session CANNOT be selection-checked: it folds BYTES,
      // not files — `add-upload` hands it an uploaded blob that has no server
      // path at all — so `consensus-incremental-store` never learns a dump
      // path list to pass on here. `[]` records that honestly, and
      // `consensusCoversSelection` reads it as "unknown", not as "mismatch":
      // fencing off a build that is very likely correct would be a worse
      // answer than not checking it.
      builtFrom: [],
      builtNormalized: false,
      pageClassifications: new Map(),
      vaClassifications: new Map(),
      vaOverview: null,
    });
  },

  matchesSelection: (paths) => consensusCoversSelection(get().builtFrom, paths),

  setOverlayEnabled: (enabled) => set({ overlayEnabled: enabled }),

  fetchRange: async (offset, length) => {
    const state = get();
    const cached = state.pageClassifications.get(offset);
    if (cached && cached.length >= length) {
      return cached.slice(0, length);
    }
    if (!state.consensusId) {
      // No consensus built yet — nothing to range over.
      return [];
    }
    const url =
      `/api/analysis/consensus/range?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&offset=${offset}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus range fetch failed: ${res.status}`);
    }
    const json = await res.json();
    const classifications: number[] = json.classifications ?? [];
    set((prev) => {
      const next = new Map(prev.pageClassifications);
      next.set(offset, classifications);
      // Evict oldest entries once the cache exceeds its bound so scrolling a
      // large dump cannot grow the map unbounded.
      while (next.size > MAX_CACHED_PAGES) {
        const oldest = next.keys().next().value;
        if (oldest === undefined) break;
        next.delete(oldest);
      }
      return { pageClassifications: next };
    });
    return classifications;
  },

  fetchVaRange: async (dumpPath, va, length) => {
    const state = get();
    const cached = state.vaClassifications.get(va);
    if (cached && cached.length >= length) {
      return cached.slice(0, length);
    }
    if (!state.consensusId) {
      // No consensus built yet — nothing to range over.
      return [];
    }
    const url =
      `/api/analysis/consensus/va-range?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&dump_path=${encodeURIComponent(dumpPath)}&va=${va}&length=${length}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus VA range fetch failed: ${res.status}`);
    }
    const json = await res.json();
    const classes: number[] = json.classes ?? [];
    set((prev) => {
      const next = new Map(prev.vaClassifications);
      next.set(va, classes);
      // Evict oldest entries once the cache exceeds its bound so scrolling a
      // large VA span cannot grow the map unbounded.
      while (next.size > MAX_CACHED_PAGES) {
        const oldest = next.keys().next().value;
        if (oldest === undefined) break;
        next.delete(oldest);
      }
      return { vaClassifications: next };
    });
    return classes;
  },

  fetchVaOverview: async (dumpPath, bins) => {
    const state = get();
    if (!state.consensusId) return;
    const url =
      `/api/analysis/consensus/va-overview?consensus_id=${encodeURIComponent(state.consensusId)}` +
      `&dump_path=${encodeURIComponent(dumpPath)}&bins=${bins}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Consensus VA overview fetch failed: ${res.status}`);
    }
    const json = await res.json();
    set({
      vaOverview: {
        va_start: json.va_start ?? 0,
        va_end: json.va_end ?? 0,
        bin_size: json.bin_size ?? 0,
        changing: json.changing ?? [],
        high: json.high ?? [],
        level: json.level ?? [],
      },
    });
  },

  toggleOverlay: () =>
    set((state) => ({ overlayEnabled: !state.overlayEnabled })),

  reset: () => {
    // Nothing in flight may repopulate a store the app has just torn down.
    runGeneration += 1;
    set({
      available: false,
      loading: false,
      runInFlight: false,
      error: null,
      size: 0,
      numDumps: 0,
      counts: null,
      thresholds: null,
      staticRegions: [],
      volatileRegions: [],
      overlayEnabled: false,
      consensusId: null,
      builtFrom: [],
      builtNormalized: false,
      pageClassifications: new Map(),
      vaClassifications: new Map(),
      vaOverview: null,
    });
  },
}));

/** What `useConsensusRun` hands a re-run affordance. */
export interface ConsensusRun {
  /** A build is in flight; every affordance disables itself on this. */
  running: boolean;
  /** Rebuild over `paths` in the given coordinate. A no-op while `running`. */
  run: (paths: string[], normalize: boolean) => void;
}

/**
 * ONE in-flight flag for the ONE global operation four controls can start.
 *
 * `HexAlignmentChip`, `OverlayAlignSwitch`, `HexOverlayPane`'s raw-offset
 * banner and `NoConsensusPrompt` all offer "build a consensus over these
 * dumps", and the first three render SIMULTANEOUSLY in the overlay. With a
 * `useState` each, clicking one left the other two enabled and a second build
 * could be issued over the first — which mints a second `consensus_id` and
 * leaves whichever response lands last describing the grid.
 *
 * The `aslrNormalize` nudge folds in here too. It is the intent the dump list
 * and the re-run affordances share, it is a TOGGLE rather than a setter, and
 * it was hand-rolled in two different spellings; a caller now names the
 * coordinate it wants and this brings the shared intent along.
 */
export function useConsensusRun(): ConsensusRun {
  const running = useConsensusStore((s) => s.runInFlight);
  const runConsensus = useConsensusStore((s) => s.runConsensus);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  const toggleAslrNormalize = useDumpStore((s) => s.toggleAslrNormalize);

  const run = useCallback(
    (paths: string[], normalize: boolean) => {
      // Read live rather than through the subscribed value: two clicks inside
      // one render pass would both see the stale `false`.
      if (useConsensusStore.getState().runInFlight) return;
      if (aslrNormalize !== normalize) toggleAslrNormalize();
      useConsensusStore.setState({ runInFlight: true });
      void runConsensus(paths, normalize).finally(() =>
        useConsensusStore.setState({ runInFlight: false }),
      );
    },
    [aslrNormalize, runConsensus, toggleAslrNormalize],
  );

  return { running, run };
}
