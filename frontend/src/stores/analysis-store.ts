import { create } from "zustand";
import type { AnalysisResult } from "@/api/types";

interface AnalysisState {
  isRunning: boolean;
  progress: number;
  message: string;
  result: AnalysisResult | null;
  error: string | null;

  startAnalysis: () => void;
  setProgress: (pct: number, msg: string) => void;
  setResult: (result: AnalysisResult) => void;
  setError: (error: string) => void;
  reset: () => void;
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  isRunning: false,
  progress: 0,
  message: "",
  result: null,
  error: null,

  startAnalysis: () =>
    set({ isRunning: true, progress: 0, message: "Starting...", error: null }),
  setProgress: (pct, msg) => set({ progress: pct, message: msg }),
  setResult: (result) =>
    set({ isRunning: false, progress: 100, result, error: null }),
  setError: (error) => set({ isRunning: false, error }),
  reset: () =>
    set({
      isRunning: false,
      progress: 0,
      message: "",
      result: null,
      error: null,
    }),
}));
