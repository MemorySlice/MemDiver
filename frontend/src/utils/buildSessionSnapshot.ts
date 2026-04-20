import type { SessionSnapshot } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useHexStore } from "@/stores/hex-store";
import { uiToApiInputMode, type UiInputMode } from "@/utils/input-mode";

/**
 * Build the saveSession() payload from the live stores. Single source of
 * truth shared by Workspace autosave (Ctrl+S) and SessionManager manual save
 * so the field set can't drift between the two sites.
 */
export function buildSessionSnapshot(
  sessionName: string,
): Partial<SessionSnapshot> {
  const state = useAppStore.getState();
  const result = useAnalysisStore.getState().result;
  const bookmarks = useHexStore.getState().bookmarks;

  // Fields the React UI does not model. Forwarded from the last loaded
  // snapshot so that opening a Marimo-authored session and re-saving it
  // from the React workspace does not silently drop values.
  const preserved = state.lastLoadedSnapshot;

  return {
    session_name: sessionName,
    input_mode: uiToApiInputMode(state.inputMode as UiInputMode),
    input_path: state.inputPath,
    dataset_root: state.datasetRoot,
    keylog_filename: state.keylogFilename,
    template_name: state.templateName,
    protocol_name: state.protocolName,
    protocol_version: state.protocolVersion,
    scenario: state.scenario,
    selected_libraries: state.selectedLibraries,
    selected_phase: state.selectedPhase,
    mode: state.mode,
    selected_algorithms: [...state.selectedAlgorithms],
    algorithm: preserved?.algorithm ?? "",
    max_runs: preserved?.max_runs ?? 10,
    normalize_phases: preserved?.normalize_phases ?? false,
    single_file_format: preserved?.single_file_format ?? "",
    ground_truth_mode: preserved?.ground_truth_mode ?? "auto",
    analysis_result: result
      ? (result as unknown as Record<string, unknown>)
      : null,
    bookmarks,
    investigation_offset: null,
  } as Partial<SessionSnapshot>;
}
