import { useFtueStore } from "./store";
import { findTour } from "./registry";
import type { Tour, TourStep } from "./types";

interface TourController {
  startTour: (id: string) => void;
  dismiss: () => void;
  advance: () => void;
  complete: () => void;
  isShowing: boolean;
  currentStep: TourStep | null;
  activeTour: Tour | null;
  activeStepIndex: number;
  shouldShow: (tour: Tour) => boolean;
  markSeen: (id: string, version: number, completed: boolean) => void;
}

/**
 * Hook wrapping the FTUE store. Resolves the currently active tour from the
 * registry by id so that consumers never have to juggle the lookup manually.
 */
export function useTourController(): TourController {
  const activeTourId = useFtueStore((s) => s.activeTourId);
  const activeStepIndex = useFtueStore((s) => s.activeStepIndex);
  const startTour = useFtueStore((s) => s.startTour);
  const dismiss = useFtueStore((s) => s.dismiss);
  const advance = useFtueStore((s) => s.advance);
  const complete = useFtueStore((s) => s.complete);
  const shouldShow = useFtueStore((s) => s.shouldShow);
  const markSeen = useFtueStore((s) => s.markSeen);

  const activeTour = activeTourId ? findTour(activeTourId) ?? null : null;
  const currentStep =
    activeTour && activeStepIndex < activeTour.steps.length
      ? activeTour.steps[activeStepIndex]
      : null;

  return {
    startTour,
    dismiss,
    advance,
    complete,
    isShowing: activeTour !== null && currentStep !== null,
    currentStep,
    activeTour,
    activeStepIndex,
    shouldShow,
    markSeen,
  };
}
