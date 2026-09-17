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

import { readableFailure } from "@/api/client";
import {
  armOracle as armOracleApi,
  deleteOracle as deleteOracleApi,
  dryRunOracle as dryRunOracleApi,
  enableOracles as enableOraclesApi,
  getOracleStatus,
  listOracleExamples,
  loadOracleExample as loadOracleExampleApi,
  listOracles,
  smokeTestOracle as smokeTestOracleApi,
  suggestExampleConfig as suggestExampleConfigApi,
  uploadOracle as uploadOracleApi,
} from "@/api/oracles";
import type {
  ConfigSuggestion,
  DryRunResult,
  OracleEntry,
  OracleExample,
  OracleStatus,
  SmokeTestRequest,
  SmokeTestResult,
} from "@/api/oracles";

interface OracleState {
  examples: OracleExample[];
  uploaded: OracleEntry[];
  /**
   * Whether the server will accept oracle uploads at all, and from where the
   * directory was configured. ``null`` until the first ``refresh`` answers —
   * the UI must not decide between the consent panel and the dropzone on a
   * guess, so consumers treat ``null`` as "not known yet".
   */
  status: OracleStatus | null;
  selectedOracleId: string | null;
  dryRun: DryRunResult | null;
  /**
   * Result of the most recent server-composed smoke test.
   *
   * Kept beside ``dryRun`` rather than replacing it: the two endpoints grade
   * different bytes and the dry-run one still exists. ``null`` means "no smoke
   * test has succeeded for the oracle currently on screen" -- the FTUE tour
   * reads exactly that to know the user has run one.
   */
  smokeTest: SmokeTestResult | null;
  loading: boolean;
  error: string | null;

  refresh: () => Promise<void>;
  enable: (path?: string) => Promise<boolean>;
  upload: (file: File, description?: string) => Promise<OracleEntry | null>;
  /**
   * Register a bundled example server-side so it becomes a runnable oracle.
   *
   * Returns the new entry (already selected) or ``null`` when the request
   * failed, in which case ``error`` carries the decoded reason.
   */
  loadExample: (
    filename: string,
    config?: Record<string, unknown>,
    description?: string,
  ) => Promise<OracleEntry | null>;
  /**
   * Ask the server what a bundled example's config should be for these dumps.
   *
   * Advisory only: ``null`` means the request itself failed, and the caller is
   * expected to carry on with an unfilled form rather than block on it. An
   * example the server simply could not derive anything for answers with an
   * empty ``config``, which is a result, not a failure.
   */
  suggest: (
    filename: string,
    sourcePaths: string[],
  ) => Promise<ConfigSuggestion | null>;
  arm: (
    oracleId: string,
    sha256: string,
    config?: Record<string, unknown>,
  ) => Promise<boolean>;
  runDry: (oracleId: string, samplesB64: string[]) => Promise<DryRunResult | null>;
  /**
   * Smoke-test an oracle against samples the SERVER composes from the dumps.
   *
   * Unlike ``runDry``, a failure CLEARS ``smokeTest``. The dry-run path keeps
   * its stale result on purpose (see the note in OracleDryRunBar), but a smoke
   * test carries a verdict banner, and a stale "discriminates" sitting above a
   * fresh "the server refused the request" is an outright false statement about
   * the oracle -- not merely redundant dots.
   */
  runSmokeTest: (
    oracleId: string,
    body: SmokeTestRequest,
  ) => Promise<SmokeTestResult | null>;
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
    // The oracle endpoints reject with an ApiError carrying the RAW response
    // body, so surfacing `err.message` verbatim paints
    // `{"detail":"oracle execution disabled; ..."}` into the panel. One shared
    // decoder keeps upload, arm, dry-run, delete and the Examples tab honest.
    set({ loading: false, error: readableFailure(err) });
    return null;
  }
}

export const useOracleStore = create<OracleState>((set) => ({
  examples: [],
  uploaded: [],
  status: null,
  selectedOracleId: null,
  dryRun: null,
  smokeTest: null,
  loading: false,
  error: null,

  refresh: async () => {
    const result = await guarded(set, async () => {
      const [examples, oracles, status] = await Promise.all([
        listOracleExamples(),
        listOracles(),
        getOracleStatus(),
      ]);
      return {
        examples: examples.examples,
        oracles: oracles.oracles,
        status,
      };
    });
    if (result !== null) {
      set({
        examples: result.examples,
        uploaded: result.oracles,
        status: result.status,
      });
    }
  },

  /**
   * Record the user's consent to store and execute oracle code.
   *
   * The server re-points the live registry as part of the same call and
   * answers with the fresh status, so storing that response is enough to
   * reveal the dropzone — no refetch and no page reload.
   */
  enable: async (path) => {
    const status = await guarded(set, () => enableOraclesApi(path));
    if (status !== null) {
      set({ status });
      return true;
    }
    return false;
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

  /**
   * Same bookkeeping as ``upload``: the entry joins ``uploaded`` and becomes the
   * selection, so the Upload tab lists it and the wizard can arm or drop it
   * exactly like a file the user dropped themselves.
   */
  loadExample: async (filename, config, description) => {
    const entry = await guarded(set, () =>
      loadOracleExampleApi(filename, config, description),
    );
    if (entry !== null) {
      set((prev) => ({
        // A second load of the same example answers with a fresh id; replacing
        // by id keeps the list free of duplicates if it ever does not.
        uploaded: [...prev.uploaded.filter((o) => o.id !== entry.id), entry],
        selectedOracleId: entry.id,
      }));
    }
    return entry;
  },

  /**
   * No store state of its own: the suggestion belongs to the one config editor
   * that asked for it, and a second editor opened later must derive its own
   * rather than inherit values from a run it was never compared against.
   */
  suggest: async (filename, sourcePaths) =>
    guarded(set, () => suggestExampleConfigApi(filename, sourcePaths)),

  arm: async (oracleId, sha256, config) => {
    const entry = await guarded(set, () =>
      armOracleApi(oracleId, sha256, config),
    );
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

  runSmokeTest: async (oracleId, body) => {
    const result = await guarded(set, () =>
      smokeTestOracleApi(oracleId, body),
    );
    // Clear on failure, unlike ``runDry``. A verdict is an assertion about the
    // oracle; keeping the previous one alive beside an error would leave the
    // panel asserting something the server just declined to confirm.
    set({ smokeTest: result });
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
