import { create } from "zustand";
import type { AnalysisResult } from "@/api/types";

interface AnalysisState {
  isRunning: boolean;
  progress: number;
  message: string;
  result: AnalysisResult | null;
  error: string | null;
  /**
   * Id of the in-flight analysis task, or null when idle. Set on submit
   * so the panel can subscribe to ``/ws/tasks/{taskId}`` for progress;
   * cleared on terminal (result/error/reset).
   */
  taskId: string | null;

  startAnalysis: () => void;
  setTaskId: (taskId: string | null) => void;
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
  taskId: null,

  startAnalysis: () =>
    set({ isRunning: true, progress: 0, message: "", error: null, result: null }),
  setTaskId: (taskId) => set({ taskId }),
  setProgress: (pct, msg) => set({ progress: pct, message: msg }),
  setResult: (result) =>
    set({ isRunning: false, progress: 100, result, error: null, taskId: null }),
  setError: (error) => set({ isRunning: false, error, taskId: null }),
  reset: () =>
    set({
      isRunning: false,
      progress: 0,
      message: "",
      result: null,
      error: null,
      taskId: null,
    }),
}));
