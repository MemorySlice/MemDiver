import { create } from "zustand";
import type { PathInfo, SessionSnapshot } from "@/api/types";
import { apiToUiInputMode } from "@/utils/input-mode";
import { getPathInfo } from "@/api/client";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { useDumpStore } from "@/stores/dump-store";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import { useHexStore } from "@/stores/hex-store";
import { useStringsStore } from "@/stores/strings-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";
import { useVerificationStore } from "@/stores/verification-store";
import { useOverlayRenderStore } from "@/stores/overlay-render-store";
import { useOverlayDetailStore } from "@/stores/overlay-detail-store";

/** All algorithms that can run on a single dump file. */
export const SINGLE_FILE_ALGORITHMS = [
  "entropy_scan",
  "pattern_match",
  "change_point",
  "structure_scan",
  "user_regex",
] as const;

/** Algorithms that require ground truth / reference data. */
export const REFERENCE_ALGORITHMS = ["exact_match"] as const;

/** Algorithms that require multiple dumps (N>=2). */
export const MULTI_DUMP_ALGORITHMS = ["differential"] as const;

/** Algorithms that require protocol context. */
export const PROTOCOL_ALGORITHMS = ["constraint_validator"] as const;

export const ALL_ALGORITHMS = [
  ...SINGLE_FILE_ALGORITHMS,
  ...REFERENCE_ALGORITHMS,
  ...MULTI_DUMP_ALGORITHMS,
  ...PROTOCOL_ALGORITHMS,
] as const;

export type AlgorithmName = (typeof ALL_ALGORITHMS)[number];

/** Algorithms shown in verification mode (focused validation set). */
export const VERIFICATION_ALGORITHMS: readonly AlgorithmName[] = [
  "entropy_scan",
  "pattern_match",
  "change_point",
  "structure_scan",
  "user_regex",
  "exact_match",
] as const;

/** Exploration mode shows all algorithms. */
export const EXPLORATION_ALGORITHMS: readonly AlgorithmName[] = [
  ...ALL_ALGORITHMS,
] as const;

interface AppState {
  // Dataset config
  datasetRoot: string;
  keylogFilename: string;
  templateName: string;

  // Selections
  protocolVersion: string;
  protocolName: string;
  scenario: string;
  selectedLibraries: string[];
  selectedPhase: string;

  // UI mode (workspace toggle)
  mode: "verification" | "exploration";
  inputMode: "file" | "directory" | "dataset";
  inputPath: string;

  // App view routing
  appView: "landing" | "wizard" | "workspace";

  // Wizard
  wizardStep: number;
  wizardComplete: boolean;
  pathInfo: PathInfo | null;
  analysisApproach: "auto" | "inspect";
  selectedAlgorithms: AlgorithmName[];

  // Hex viewer focus
  hexFocus: { offset: number; length: number } | null;
  hasCandidateKeys: boolean;
  fullWidthHex: boolean;

  // Passthrough for SessionSnapshot fields the React UI does not model
  // itself (algorithm, max_runs, normalize_phases, single_file_format,
  // ground_truth_mode). Captured on restoreSession so that saving a
  // Marimo-authored session from the React workspace does not silently
  // drop values the React UI has no widgets for.
  lastLoadedSnapshot: SessionSnapshot | null;

  /**
   * Digest of the session as it was last persisted, or `null` when this
   * workspace has never been saved. Compared against the live snapshot to
   * answer "is there unsaved work?"; see `utils/session-digest.ts`.
   */
  lastSavedDigest: string | null;

  // Actions
  setDatasetRoot: (root: string) => void;
  setProtocol: (name: string, version: string) => void;
  setScenario: (scenario: string) => void;
  setLibraries: (libs: string[]) => void;
  setPhase: (phase: string) => void;
  setMode: (mode: "verification" | "exploration") => void;
  setInputMode: (mode: "file" | "directory" | "dataset") => void;
  setInputPath: (path: string) => void;
  setAppView: (view: "landing" | "wizard" | "workspace") => void;
  setWizardStep: (step: number) => void;
  setPathInfo: (info: PathInfo | null) => void;
  setAnalysisApproach: (approach: "auto" | "inspect") => void;
  setSelectedAlgorithms: (algos: AlgorithmName[]) => void;
  toggleAlgorithm: (algo: AlgorithmName) => void;
  completeWizard: () => void;
  resetWizard: () => void;
  /**
   * Load a saved session into the workspace. The returned promise settles once
   * every restored dump has been confirmed on disk, which is when the session
   * can honestly be called "as saved".
   */
  restoreSession: (snap: SessionSnapshot) => Promise<void>;
  setLastSavedDigest: (digest: string | null) => void;
  setHexFocus: (focus: { offset: number; length: number } | null) => void;
  setHasCandidateKeys: (has: boolean) => void;
  toggleFullWidthHex: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  datasetRoot: "",
  keylogFilename: "keylog.csv",
  templateName: "Auto-detect",
  protocolVersion: "",
  protocolName: "TLS",
  scenario: "",
  selectedLibraries: [],
  selectedPhase: "",
  mode: "verification",
  inputMode: "dataset",
  inputPath: "",
  appView: "landing",
  wizardStep: 0,
  wizardComplete: false,
  pathInfo: null,
  analysisApproach: "auto",
  selectedAlgorithms: [...VERIFICATION_ALGORITHMS],
  hexFocus: null,
  hasCandidateKeys: false,
  fullWidthHex: false,
  lastLoadedSnapshot: null,
  lastSavedDigest: null,

  setDatasetRoot: (root) => set({ datasetRoot: root }),
  setProtocol: (name, version) =>
    set({ protocolName: name, protocolVersion: version }),
  setScenario: (scenario) => set({ scenario }),
  setLibraries: (libs) => set({ selectedLibraries: libs }),
  setPhase: (phase) => set({ selectedPhase: phase }),
  setMode: (mode) =>
    set({
      mode,
      selectedAlgorithms:
        mode === "verification"
          ? [...VERIFICATION_ALGORITHMS]
          : [...EXPLORATION_ALGORITHMS],
    }),
  setInputMode: (mode) => set({ inputMode: mode }),
  setInputPath: (path) => set({ inputPath: path }),
  setAppView: (view) => set({ appView: view }),
  setWizardStep: (step) => set({ wizardStep: step }),
  setPathInfo: (info) => set({ pathInfo: info }),
  setAnalysisApproach: (approach) => set({ analysisApproach: approach }),
  setSelectedAlgorithms: (algos) => set({ selectedAlgorithms: algos }),
  toggleAlgorithm: (algo) =>
    set((state) => {
      const has = state.selectedAlgorithms.includes(algo);
      return {
        selectedAlgorithms: has
          ? state.selectedAlgorithms.filter((a) => a !== algo)
          : [...state.selectedAlgorithms, algo],
      };
    }),
  completeWizard: () => {
    set({ wizardComplete: true, appView: "workspace" });
    const { inputMode, inputPath, pathInfo } = get();
    if (inputMode === "file" && inputPath) {
      const store = useDumpStore.getState();
      // `if (…) return` here used to exit completeWizard ITSELF — not a loop,
      // not a callback — so anything added after it would silently be skipped
      // for an already-loaded path. Expressed as a positive condition instead,
      // so nothing in this function sits behind a bare return.
      const alreadyLoaded = store.dumps.some((d) => d.path === inputPath);
      if (!alreadyLoaded) {
        const name = inputPath.split("/").pop() ?? inputPath;
        // Extension-based detection, case-insensitive — kept consistent
        // with AddDumpButton (name.toLowerCase().endsWith(".msl")).
        const format = name.toLowerCase().endsWith(".msl") ? "msl" : "raw";
        store.addDump({
          path: inputPath,
          name,
          // pathInfo is populated earlier in the wizard; fall back to 0
          // intentionally if it is missing rather than blocking the add.
          size: pathInfo?.file_size ?? 0,
          format,
        });
      }
    }
  },
  restoreSession: async (snap) => {
    const resolvedMode = apiToUiInputMode(snap.input_mode);
    set({
      datasetRoot: snap.dataset_root,
      keylogFilename: snap.keylog_filename,
      templateName: snap.template_name,
      protocolName: snap.protocol_name,
      protocolVersion: snap.protocol_version,
      scenario: snap.scenario,
      selectedLibraries: snap.selected_libraries,
      selectedPhase: snap.selected_phase,
      mode: snap.mode === "exploration" ? "exploration" : "verification",
      inputMode: resolvedMode,
      inputPath: snap.input_path,
      selectedAlgorithms: (snap.selected_algorithms ?? []) as AlgorithmName[],
      wizardComplete: true,
      appView: "workspace",
      lastLoadedSnapshot: snap,
    });
    // Clear BEFORE hydrating. The previous implementation appended, so
    // restoring session B while A was open merged the two dump lists into one
    // workspace that matched neither saved file.
    useDumpStore.getState().clearAll();
    useDumpRailStore.getState().reset();

    // Branch on the dump list, NEVER on `schema_version`: a v2 file saved from
    // the wizard before any dump was added carries an empty list and still
    // has to take the legacy single-`input_path` path.
    const savedDumps = snap.dumps ?? [];
    if (savedDumps.length > 0) {
      useDumpStore.getState().hydrateDumps({
        dumps: savedDumps,
        activeDumpPath: snap.active_dump_path,
        selectedDumpPaths: snap.selected_dump_paths,
        collapsedDumpPaths: snap.collapsed_dump_paths,
        originDumpPath: snap.origin_dump_path,
        mainView: snap.main_view,
        aslrNormalize: snap.aslr_normalize,
      });
      useDumpRailStore.getState().hydrate({
        weightByPath: snap.dump_weights,
        excludedPaths: snap.excluded_dump_paths,
        soloPath: snap.solo_dump_path,
        collapsed: snap.rail_collapsed,
      });
    } else if (resolvedMode === "file" && snap.input_path) {
      const filePath = snap.input_path;
      const name = filePath.split("/").pop() ?? filePath;
      // Extension-based detection, case-insensitive — kept consistent
      // with AddDumpButton (name.toLowerCase().endsWith(".msl")).
      const format = name.toLowerCase().endsWith(".msl") ? "msl" : "raw";
      // The old "already loaded? then `return`" guard exited restoreSession
      // itself, which would now skip the resolution pass below. It is also no
      // longer needed: `clearAll` above plus `hydrateDumps`' dedupe-by-path
      // make a duplicate impossible. The recorded size is 0 until the
      // resolution pass answers.
      useDumpStore
        .getState()
        .hydrateDumps({ dumps: [{ path: filePath, name, size: 0, format }] });
    }

    // One fire-and-forget resolution pass for BOTH branches: confirm each file
    // still exists and refresh its size.
    const loaded = useDumpStore.getState().dumps;
    if (loaded.length > 0) {
      const targets = loaded.map((d) => ({ id: d.id, path: d.path }));
      // Awaited rather than fired and forgotten: the caller marks the restored
      // workspace "saved" once this settles, and doing that before the sizes
      // land would bake a pre-resolution snapshot into the digest and leave the
      // session looking dirty the moment the real sizes arrived.
      await (async () => {
        const settled = await Promise.allSettled(
          targets.map((t) => getPathInfo(t.path)),
        );
        const patches = settled.map((outcome, i) => {
          const id = targets[i].id;
          // TRAP: getPathInfo does NOT throw for a deleted file. The endpoint
          // answers HTTP 200 with `exists: false`, so a `catch` alone never
          // fires for a moved dump. "Rejected OR !exists OR !is_file" is the
          // only honest test.
          if (outcome.status === "rejected") return { id, missing: true };
          const info = outcome.value;
          if (!info.exists || !info.is_file) return { id, missing: true };
          return { id, size: info.file_size ?? 0, missing: false };
        });
        // Missing dumps are MARKED, never dropped or deselected: the next
        // Ctrl+S autosave would otherwise quietly rewrite the analyst's
        // workspace to exclude a dump they only unplugged a drive for. Their
        // recorded size is kept for the same reason.
        useDumpStore.getState().markDumpResolution(patches);
      })();
    }
  },
  setLastSavedDigest: (digest) => set({ lastSavedDigest: digest }),
  setHexFocus: (focus) => set({ hexFocus: focus }),
  setHasCandidateKeys: (has) => set({ hasCandidateKeys: has }),
  toggleFullWidthHex: () =>
    set((state) => ({ fullWidthHex: !state.fullWidthHex })),
  resetWizard: () => {
    set({
      appView: "landing",
      wizardStep: 0,
      wizardComplete: false,
      inputPath: "",
      inputMode: "dataset",
      pathInfo: null,
      datasetRoot: "",
      keylogFilename: "keylog.csv",
      protocolVersion: "",
      protocolName: "TLS",
      scenario: "",
      selectedLibraries: [],
      selectedPhase: "",
      analysisApproach: "auto",
      selectedAlgorithms: [...VERIFICATION_ALGORITHMS],
      hasCandidateKeys: false,
      hexFocus: null,
      templateName: "Auto-detect",
      fullWidthHex: false,
      mode: "verification",
      lastLoadedSnapshot: null,
      // A fresh workspace has nothing saved. Leaving the previous session's
      // digest here would make the next dirty-check compare against work that
      // is no longer loaded.
      lastSavedDigest: null,
    });
    // Clear sibling stores. These are plain runtime getState() calls; no
    // sibling store references app-store at module-eval time, so static
    // imports introduce no circular-init hazard and keep the resets
    // synchronous (they must complete within resetWizard).
    useAnalysisStore.getState().reset();
    useResultsStore.getState().clearResults();
    useDumpStore.getState().clearAll();
    useHexStore.getState().reset();
    useStringsStore.getState().clear();
    // The overlay/consensus family. These were omitted when the list above was
    // written, so a new session used to open holding the PREVIOUS session's
    // consensus, panes, variance regions, rail weights and -- worst of the set
    // -- whatever ciphertext and key bytes had been typed into the key
    // verification form.
    useMultiHexStore.getState().reset();
    useConsensusStore.getState().reset();
    useConsensusIncrementalStore.getState().reset();
    useVarianceRegionsStore.getState().reset();
    useDumpRailStore.getState().reset();
    useVerificationStore.getState().reset();
    useOverlayRenderStore.getState().reset();
    useOverlayDetailStore.getState().reset();
  },
}));
