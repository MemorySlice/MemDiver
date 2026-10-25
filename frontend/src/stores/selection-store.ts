/**
 * Linked-views selection (plan D14): the one capture / process / location /
 * annotation every panel reads. The Image panel's process table and the Vol3
 * process tree write `pid`; the Vol3 results table and the next run's `pid`
 * argument read it.
 *
 * Imports nothing, so it cannot take part in an import cycle.
 */
import { create } from "zustand";

/** A selected coordinate (backend `Location`); `pid` qualifies process addresses. */
export interface SelectionLocation {
  space: string;
  value: number;
  pid?: number;
}

interface SelectionState {
  captureId: string | null;
  pid: number | null;
  location: SelectionLocation | null;
  annotationId: string | null;
  /**
   * Switching from one capture to ANOTHER drops the rest (a pid or address belongs
   * to one capture); learning the capture for the first time keeps a pid already picked.
   */
  setCaptureId: (captureId: string | null) => void;
  setPid: (pid: number | null) => void;
  setLocation: (location: SelectionLocation | null) => void;
  setAnnotationId: (annotationId: string | null) => void;
  clear: () => void;
}

const EMPTY = { captureId: null, pid: null, location: null, annotationId: null };

export const useSelectionStore = create<SelectionState>((set, get) => ({
  ...EMPTY,
  setCaptureId: (captureId) => {
    const previous = get().captureId;
    if (captureId === previous) return;
    set(previous === null ? { captureId } : { ...EMPTY, captureId });
  },
  setPid: (pid) => set({ pid }),
  setLocation: (location) => set({ location }),
  setAnnotationId: (annotationId) => set({ annotationId }),
  clear: () => set(EMPTY),
}));
