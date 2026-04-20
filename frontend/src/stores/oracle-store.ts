/**
 * Oracle-registry Zustand store.
 *
 * Mirrors the server-side state: list of bundled examples (read-only),
 * list of uploaded oracles, armed-flag bookkeeping, and the result of
 * the most recent dry-run. None of this is persisted — the server is
 * authoritative and a page reload refetches via ``refresh``.
 *
 * All async actions set a transient ``loading`` + ``error`` field so
 * UI consumers can show feedback without a separate loading state.
 */

import { create } from "zustand";

import {
  armOracle as armOracleApi,
  deleteOracle as deleteOracleApi,
  dryRunOracle as dryRunOracleApi,
  listOracleExamples,
  listOracles,
  uploadOracle as uploadOracleApi,
} from "@/api/oracles";
import type {
  DryRunResult,
  OracleEntry,
  OracleExample,
} from "@/api/oracles";

interface OracleState {
  examples: OracleExample[];
  uploaded: OracleEntry[];
  selectedOracleId: string | null;
  dryRun: DryRunResult | null;
  loading: boolean;
  error: string | null;

  refresh: () => Promise<void>;
  upload: (file: File, description?: string) => Promise<OracleEntry | null>;
  arm: (oracleId: string, sha256: string) => Promise<boolean>;
  runDry: (oracleId: string, samplesB64: string[]) => Promise<DryRunResult | null>;
  remove: (oracleId: string) => Promise<boolean>;
  selectOracle: (oracleId: string | null) => void;
  clearError: () => void;
}

async function guarded<T>(
  set: (patch: Partial<OracleState>) => void,
  fn: () => Promise<T>,
): Promise<T | null> {
  set({ loading: true, error: null });
  try {
    const result = await fn();
    set({ loading: false });
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    set({ loading: false, error: msg });
    return null;
  }
}

export const useOracleStore = create<OracleState>((set, get) => ({
  examples: [],
  uploaded: [],
  selectedOracleId: null,
  dryRun: null,
  loading: false,
  error: null,

  refresh: async () => {
    const result = await guarded(set, async () => {
      const [examples, oracles] = await Promise.all([
        listOracleExamples(),
        listOracles(),
      ]);
      return { examples: examples.examples, oracles: oracles.oracles };
    });
    if (result !== null) {
      set({ examples: result.examples, uploaded: result.oracles });
    }
  },

  upload: async (file, description) => {
    const entry = await guarded(set, () => uploadOracleApi(file, description));
    if (entry !== null) {
      set((prev) => ({
        uploaded: [...prev.uploaded, entry],
        selectedOracleId: entry.id,
      }));
    }
    return entry;
  },

  arm: async (oracleId, sha256) => {
    const entry = await guarded(set, () => armOracleApi(oracleId, sha256));
    if (entry !== null) {
      set((prev) => ({
        uploaded: prev.uploaded.map((o) =>
          o.id === entry.id ? entry : o,
        ),
      }));
      return true;
    }
    return false;
  },

  runDry: async (oracleId, samplesB64) => {
    const result = await guarded(set, () =>
      dryRunOracleApi(oracleId, samplesB64),
    );
    if (result !== null) {
      set({ dryRun: result });
    }
    return result;
  },

  remove: async (oracleId) => {
    const result = await guarded(set, () => deleteOracleApi(oracleId));
    if (result !== null) {
      set((prev) => ({
        uploaded: prev.uploaded.filter((o) => o.id !== oracleId),
        selectedOracleId:
          prev.selectedOracleId === oracleId ? null : prev.selectedOracleId,
      }));
      return true;
    }
    return false;
  },

  selectOracle: (oracleId) => set({ selectedOracleId: oracleId }),
  clearError: () => set({ error: null }),
}));
