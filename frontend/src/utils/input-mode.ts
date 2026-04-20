export type UiInputMode = "file" | "directory" | "dataset";
export type ApiInputMode = "single_file" | "run_directory" | "dataset";

const UI_TO_API: Record<UiInputMode, ApiInputMode> = {
  file: "single_file",
  directory: "run_directory",
  dataset: "dataset",
};

const API_TO_UI: Record<ApiInputMode, UiInputMode> = {
  single_file: "file",
  run_directory: "directory",
  dataset: "dataset",
};

export function uiToApiInputMode(mode: UiInputMode): ApiInputMode {
  return UI_TO_API[mode];
}

export function apiToUiInputMode(mode: string): UiInputMode {
  return API_TO_UI[mode as ApiInputMode] ?? "dataset";
}
