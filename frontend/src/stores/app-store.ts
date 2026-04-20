import { create } from "zustand";
import type { PathInfo, SessionSnapshot } from "@/api/types";
import { apiToUiInputMode } from "@/utils/input-mode";

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
  restoreSession: (snap: SessionSnapshot) => void;
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
      import("@/stores/dump-store").then((m) => {
        const store = m.useDumpStore.getState();
        if (store.dumps.some((d) => d.path === inputPath)) return;
        const name = inputPath.split("/").pop() ?? inputPath;
        const ext = inputPath.split(".").pop()?.toLowerCase();
        store.addDump({
          path: inputPath,
          name,
          size: pathInfo?.file_size ?? 0,
          format: ext === "msl" ? "msl" : "raw",
        });
      });
    }
  },
  restoreSession: (snap) => {
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
    if (resolvedMode === "file" && snap.input_path) {
      const filePath = snap.input_path;
      import("@/stores/dump-store").then(async (m) => {
        const store = m.useDumpStore.getState();
        if (store.dumps.some((d) => d.path === filePath)) return;
        const name = filePath.split("/").pop() ?? filePath;
        const ext = filePath.split(".").pop()?.toLowerCase();
        // Fetch file size from API
        let fileSize = 0;
        try {
          const { getPathInfo } = await import("@/api/client");
          const info = await getPathInfo(filePath);
          fileSize = info.file_size ?? 0;
        } catch {
          // silently use 0
        }
        store.addDump({
          path: filePath,
          name,
          size: fileSize,
          format: ext === "msl" ? "msl" : "raw",
        });
      });
    }
  },
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
    });
    // Clear sibling stores (lazy dynamic imports to avoid circular deps at init time)
    import("@/stores/analysis-store").then((m) => m.useAnalysisStore.getState().reset());
    import("@/stores/results-store").then((m) => m.useResultsStore.getState().clearResults());
    import("@/stores/dump-store").then((m) => m.useDumpStore.getState().clearAll());
    import("@/stores/hex-store").then((m) => m.useHexStore.getState().reset());
    import("@/stores/strings-store").then((m) => m.useStringsStore.getState().clear());
  },
}));
