import { create } from "zustand";
import type { RegionCategory } from "@/api/types";
import { DEFAULT_REGION_CATEGORIES } from "@/components/import/region-categories";

/**
 * Region selection state: what the import wizard has chosen, and the
 * session-level analysis-time filter that choice resolved to.
 *
 * Kept out of `app-store` on purpose: the API helpers that attach
 * `region_filter` to analysis requests read this store, and `app-store`
 * already imports several of those modules — a store with no imports of its
 * own cannot take part in an import cycle.
 */
/** A memory-map file chosen for one specific wizard input. */
export interface WizardMapsChoice {
  /** The dump the map describes (the wizard's input path). */
  input: string;
  /** Path of the `/proc/<pid>/maps`-style file. */
  mapsPath: string;
}

interface RegionSelectionState {
  /** Categories ticked in the wizard's Regions step. */
  wizardCategories: RegionCategory[];
  /** Wizard opt-in: write a filtered `.msl` copy instead of filtering at analysis time. */
  wizardMaterialize: boolean;
  /**
   * Memory map the user pointed the wizard at for a raw dump, tagged with the
   * input it belongs to (a later, different input must not inherit it).
   * `null` = none chosen (the server auto-detects a `.maps` sidecar).
   */
  wizardMaps: WizardMapsChoice | null;
  /**
   * Session `region_filter` (`"heap,stack"`), or `null` for "every region".
   * Persisted with the session and sent with `.msl` analysis requests.
   */
  regionFilter: string | null;

  setWizardCategories: (categories: RegionCategory[]) => void;
  setWizardMaterialize: (materialize: boolean) => void;
  setWizardMaps: (choice: WizardMapsChoice | null) => void;
  setRegionFilter: (filter: string | null) => void;
  reset: () => void;
}

const INITIAL = {
  wizardCategories: [...DEFAULT_REGION_CATEGORIES],
  wizardMaterialize: false,
  wizardMaps: null,
  regionFilter: null,
};

export const useRegionSelectionStore = create<RegionSelectionState>((set) => ({
  ...INITIAL,
  wizardCategories: [...INITIAL.wizardCategories],
  setWizardCategories: (categories) => set({ wizardCategories: [...categories] }),
  setWizardMaterialize: (materialize) => set({ wizardMaterialize: materialize }),
  setWizardMaps: (choice) => set({ wizardMaps: choice }),
  setRegionFilter: (filter) => set({ regionFilter: filter || null }),
  reset: () => set({ ...INITIAL, wizardCategories: [...INITIAL.wizardCategories] }),
}));

/**
 * `body` plus the session's `region_filter`, when one is set.
 *
 * Omitting the field (rather than sending `null`) keeps every request without
 * a filter byte-identical to what it was before region selection existed. The
 * backend honours the filter for `.msl` sources and ignores it for raw ones.
 */
export function withSessionRegionFilter<T extends object>(body: T): T & { region_filter?: string } {
  const filter = useRegionSelectionStore.getState().regionFilter;
  // A caller that chose a filter itself (even `null`) always wins.
  if (!filter || "region_filter" in body) return body;
  return { ...body, region_filter: filter };
}
