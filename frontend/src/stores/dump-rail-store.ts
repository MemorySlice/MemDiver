import { create } from "zustand";

/**
 * WHICH dumps the aligned overlay reads, and HOW MUCH each one counts.
 *
 * ── Why this is its own store, and not a field on `overlay-render-store` ─────
 * The two look adjacent — both are overlay-scoped, both are view state — but
 * they answer opposite halves of the question and have opposite shapes:
 *
 *   - `overlay-render-store` says HOW one byte stream is COLOURED. It is one
 *     scalar, it never changes which byte is on screen, and every consumer
 *     reads it as a single field.
 *   - this store says WHICH BYTES the stream is made of. Membership, weight and
 *     solo are inputs to the plurality reducer, so changing any of them
 *     changes the DATA, not the paint. It is keyed BY DUMP PATH, so its state
 *     is two collections rather than a scalar.
 *
 * Folding the two together would mean every `renderMode` click rotated the
 * identity of a `Map` that the grid's byte getters depend on, and every weight
 * click re-rendered the render-mode switch. Keeping them apart keeps each
 * selector a single field, which is what `scripts/check-store-selectors.mjs`
 * asks for and what keeps the repaints proportional to what actually changed.
 *
 * It is also not part of `multi-hex-store` (a byte cache — a view preference
 * there would invalidate chunk-map subscribers) and not part of `dump-store`
 * (which answers "which dumps exist and which are selected"; this is a
 * narrower question asked only by the overlay, about a subset of those).
 *
 * ── Keyed by PATH, not by dump id ────────────────────────────────────────────
 * Every surface the weights feed — `multi-hex-store`, the aligned-window
 * request, the plurality reducer — addresses dumps by path. Keying by id would
 * put one translation step between the rail and every one of them, which is a
 * place for a weight to go missing silently.
 *
 * Absence is the default in BOTH collections: a path with no entry in
 * `weightByPath` weighs `1.0`, and a path not in `excludedPaths` is included.
 * So a freshly selected dump joins the consensus at equal weight without the
 * rail having to hear about the selection change at all.
 */

/**
 * The three legal weights, IN CYCLE ORDER.
 *
 * The design gives a button, not a slider, and this tuple is why: three named
 * positions — "as much as the others", "twice as much as a halved one", "half"
 * — are a vocabulary an analyst can state in a report, while a continuous
 * slider invites a 1.37 that means nothing and cannot be reproduced. They are
 * also exact binary fractions, which is what lets `weightedPlurality` compare
 * summed weights with `>` and no epsilon.
 */
export const DUMP_WEIGHTS = [1, 1.5, 0.5] as const;

export type DumpWeight = (typeof DUMP_WEIGHTS)[number];

/** What a dump weighs until somebody says otherwise. */
export const DEFAULT_DUMP_WEIGHT: DumpWeight = 1;

/** The next weight in the `1.0 → 1.5 → 0.5 → 1.0` cycle. */
export function nextWeight(weight: DumpWeight): DumpWeight {
  const index = DUMP_WEIGHTS.indexOf(weight);
  // An unknown weight (a value that pre-dates the vocabulary, say) returns to
  // the default rather than being carried forward: only three values are legal.
  if (index < 0) return DEFAULT_DUMP_WEIGHT;
  return DUMP_WEIGHTS[(index + 1) % DUMP_WEIGHTS.length];
}

/** Whether any dump weighs something other than `1.0` — the `weighted` badge. */
export function hasUnevenWeights(weightByPath: ReadonlyMap<string, DumpWeight>): boolean {
  for (const weight of weightByPath.values()) {
    if (weight !== DEFAULT_DUMP_WEIGHT) return true;
  }
  return false;
}

export interface DumpRailState {
  /** Per-path weight. A path with no entry weighs `DEFAULT_DUMP_WEIGHT`. */
  weightByPath: Map<string, DumpWeight>;
  /** Paths taken OUT of the consensus. Absence means "in". */
  excludedPaths: Set<string>;
  /**
   * The dump shown alone, or `null` for the `Σ Overlay` layer.
   *
   * Solo is a VIEW, not an exclusion: soloing a dump leaves the weights and the
   * membership exactly as they were, so clicking back to `Σ Overlay` restores
   * the same consensus the analyst was reading a moment ago.
   */
  soloPath: string | null;
  /** Whether the rail is folded away to give the grid its width back. */
  collapsed: boolean;

  weightAt(path: string): DumpWeight;
  isIncluded(path: string): boolean;
  cycleWeight(path: string): void;
  setWeight(path: string, weight: DumpWeight): void;
  toggleIncluded(path: string): void;
  setSolo(path: string | null): void;
  /** Solo `path`, or return to the overlay when it is already soloed. */
  toggleSolo(path: string): void;
  setCollapsed(collapsed: boolean): void;
  toggleCollapsed(): void;
  /**
   * Restores the rail from a saved session.
   *
   * Every weight is coerced to one of `DUMP_WEIGHTS`, and the default is
   * stored as ABSENCE — the store's documented contract. Writing an explicit
   * `1.0` instead would make `hasUnevenWeights` report "weighted" for a
   * workspace nobody ever weighted, i.e. the badge would start lying the
   * moment a session was restored.
   */
  hydrate(spec: DumpRailHydrationSpec): void;
  reset(): void;
}

/** The rail's persisted shape: already path-keyed, so no translation needed. */
export interface DumpRailHydrationSpec {
  weightByPath?: Record<string, number>;
  excludedPaths?: readonly string[];
  soloPath?: string | null;
  collapsed?: boolean;
}

/** Narrows an untrusted number to one of the three legal weights. */
export function coerceWeight(value: unknown): DumpWeight {
  const found = DUMP_WEIGHTS.find((w) => w === value);
  return found ?? DEFAULT_DUMP_WEIGHT;
}

const initial = () => ({
  weightByPath: new Map<string, DumpWeight>(),
  excludedPaths: new Set<string>(),
  soloPath: null,
  collapsed: false,
});

export const useDumpRailStore = create<DumpRailState>((set, get) => ({
  ...initial(),

  weightAt: (path) => get().weightByPath.get(path) ?? DEFAULT_DUMP_WEIGHT,

  isIncluded: (path) => !get().excludedPaths.has(path),

  cycleWeight: (path) =>
    set((state) => {
      const weightByPath = new Map(state.weightByPath);
      const next = nextWeight(weightByPath.get(path) ?? DEFAULT_DUMP_WEIGHT);
      // The default is stored as ABSENCE, so a dump cycled back round to 1.0 is
      // indistinguishable from one nobody ever touched — which is what makes
      // `hasUnevenWeights` an honest answer to "is this reading weighted?".
      if (next === DEFAULT_DUMP_WEIGHT) weightByPath.delete(path);
      else weightByPath.set(path, next);
      return { weightByPath };
    }),

  setWeight: (path, weight) =>
    set((state) => {
      const weightByPath = new Map(state.weightByPath);
      if (weight === DEFAULT_DUMP_WEIGHT) weightByPath.delete(path);
      else weightByPath.set(path, weight);
      return { weightByPath };
    }),

  toggleIncluded: (path) =>
    set((state) => {
      const excludedPaths = new Set(state.excludedPaths);
      if (excludedPaths.has(path)) excludedPaths.delete(path);
      else excludedPaths.add(path);
      return { excludedPaths };
    }),

  setSolo: (path) => set({ soloPath: path }),

  toggleSolo: (path) => set((state) => ({ soloPath: state.soloPath === path ? null : path })),

  setCollapsed: (collapsed) => set({ collapsed }),

  toggleCollapsed: () => set((state) => ({ collapsed: !state.collapsed })),

  hydrate: (spec) => {
    const weightByPath = new Map<string, DumpWeight>();
    for (const [path, raw] of Object.entries(spec.weightByPath ?? {})) {
      const weight = coerceWeight(raw);
      // Absence IS the default. See the contract note on `hydrate`.
      if (weight !== DEFAULT_DUMP_WEIGHT) weightByPath.set(path, weight);
    }
    set({
      weightByPath,
      excludedPaths: new Set(spec.excludedPaths ?? []),
      // "" is how "no solo" travels on the wire (the snapshot field is a plain
      // string), and it must come back as null -- an empty-string soloPath
      // would match no dump yet still read as "something is soloed".
      soloPath: spec.soloPath ? spec.soloPath : null,
      collapsed: spec.collapsed ?? false,
    });
  },

  reset: () => set(initial()),
}));
