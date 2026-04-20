import { useEffect, type ReactNode } from "react";
import { useAppStore } from "@/stores/app-store";
import { ALL_TOURS } from "./registry";
import { useFtueStore } from "./store";
import { TourRenderer } from "./TourRenderer";
import type { Tour } from "./types";

// Sort once at module load — priority ascending, registry order as tiebreaker.
const ORDERED_TOURS: Tour[] = ALL_TOURS
  .map((tour, idx) => ({ tour, idx }))
  .sort((a, b) => {
    const pa = a.tour.priority ?? Infinity;
    const pb = b.tour.priority ?? Infinity;
    if (pa !== pb) return pa - pb;
    return a.idx - b.idx;
  })
  .map((e) => e.tour);

export function TourProvider({ children }: { children: ReactNode }) {
  const appView = useAppStore((s) => s.appView);
  const activeTourId = useFtueStore((s) => s.activeTourId);

  useEffect(() => {
    if (activeTourId) return;
    const store = useFtueStore.getState();
    for (const tour of ORDERED_TOURS) {
      if (!store.shouldShow(tour)) continue;
      if (!triggerFires(tour)) continue;
      store.startTour(tour.id);
      break;
    }
  }, [appView, activeTourId]);

  return (
    <>
      {children}
      {activeTourId !== null && <TourRenderer />}
    </>
  );
}

function triggerFires(tour: Tour): boolean {
  const t = tour.trigger;
  if (t.kind === "immediate") return true;
  try {
    return t.predicate();
  } catch {
    return false;
  }
}
