import { create } from "zustand";

/**
 * The "run anyway?" question raised by `withMemoryBudgetOverride`.
 *
 * One question at a time: refusals that arrive while one is already on screen
 * (e.g. the N chunk fetches of one aligned-window load) JOIN it and share its
 * answer, so a single gesture never stacks up a dialog per request.
 */
export interface MemoryBudgetInfo {
  message: string;
  estimateBytes: number | null;
  budgetBytes: number | null;
}

interface PendingPrompt {
  info: MemoryBudgetInfo;
  answer: Promise<boolean>;
  resolve: (confirmed: boolean) => void;
}

interface MemoryBudgetState {
  pending: PendingPrompt | null;
  /** Ask the user; resolves `true` for "Run anyway", `false` for cancel. */
  ask: (info: MemoryBudgetInfo) => Promise<boolean>;
  /** Answer the question currently on screen. */
  answer: (confirmed: boolean) => void;
}

export const useMemoryBudgetStore = create<MemoryBudgetState>((set, get) => ({
  pending: null,
  ask: (info) => {
    const open = get().pending;
    if (open) return open.answer;
    let resolve!: (confirmed: boolean) => void;
    const answer = new Promise<boolean>((r) => {
      resolve = r;
    });
    set({ pending: { info, answer, resolve } });
    return answer;
  },
  answer: (confirmed) => {
    const open = get().pending;
    if (!open) return;
    set({ pending: null });
    open.resolve(confirmed);
  },
}));
