import { create } from "zustand";
import { persist } from "zustand/middleware";

const SETTINGS_VERSION = 1;

export interface DisplaySettings {
  theme: "light" | "dark";
  highContrast: boolean;
  hexBytesPerRow: 16 | 32;
  hexUpperCase: boolean;
  showAsciiColumn: boolean;
  fontSize: "xs" | "sm" | "base";
}

export interface AnalysisSettings {
  defaultAlgorithms: string[];
  entropyThreshold: number;
  autoRunOnLoad: boolean;
}

export interface GeneralSettings {
  autoSaveSession: boolean;
  keyboardShortcutsEnabled: boolean;
  confirmBeforeReset: boolean;
}

interface SettingsState {
  display: DisplaySettings;
  analysis: AnalysisSettings;
  general: GeneralSettings;

  updateDisplay: (partial: Partial<DisplaySettings>) => void;
  updateAnalysis: (partial: Partial<AnalysisSettings>) => void;
  updateGeneral: (partial: Partial<GeneralSettings>) => void;
  resetToDefaults: () => void;
  exportSettings: () => string;
  importSettings: (json: string) => boolean;
}

const DEFAULT_DISPLAY: DisplaySettings = {
  theme: "dark",
  highContrast: false,
  hexBytesPerRow: 16,
  hexUpperCase: false,
  showAsciiColumn: true,
  fontSize: "xs",
};

const DEFAULT_ANALYSIS: AnalysisSettings = {
  defaultAlgorithms: [
    "entropy_scan",
    "pattern_match",
    "change_point",
    "structure_scan",
    "user_regex",
  ],
  entropyThreshold: 4.5,
  autoRunOnLoad: false,
};

const DEFAULT_GENERAL: GeneralSettings = {
  autoSaveSession: true,
  keyboardShortcutsEnabled: true,
  confirmBeforeReset: true,
};

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set, get) => ({
      display: { ...DEFAULT_DISPLAY },
      analysis: { ...DEFAULT_ANALYSIS },
      general: { ...DEFAULT_GENERAL },

      updateDisplay: (partial) =>
        set((state) => ({ display: { ...state.display, ...partial } })),

      updateAnalysis: (partial) =>
        set((state) => ({ analysis: { ...state.analysis, ...partial } })),

      updateGeneral: (partial) =>
        set((state) => ({ general: { ...state.general, ...partial } })),

      resetToDefaults: () =>
        set({
          display: { ...DEFAULT_DISPLAY },
          analysis: { ...DEFAULT_ANALYSIS },
          general: { ...DEFAULT_GENERAL },
        }),

      exportSettings: () => {
        const { display, analysis, general } = get();
        return JSON.stringify({ display, analysis, general }, null, 2);
      },

      importSettings: (json: string): boolean => {
        try {
          const parsed = JSON.parse(json);
          const next: Partial<SettingsState> = {};
          if (parsed.display) next.display = { ...DEFAULT_DISPLAY, ...parsed.display };
          if (parsed.analysis) next.analysis = { ...DEFAULT_ANALYSIS, ...parsed.analysis };
          if (parsed.general) next.general = { ...DEFAULT_GENERAL, ...parsed.general };
          set(next);
          return true;
        } catch {
          return false;
        }
      },
    }),
    {
      name: "memdiver-settings",
      version: SETTINGS_VERSION,
    },
  ),
);
