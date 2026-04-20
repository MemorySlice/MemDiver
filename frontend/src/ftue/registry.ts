import type { Tour } from "./types";
import { workspaceLayoutTour } from "./tours/workspaceLayout";
import { structureOverlayTour } from "./tours/structureOverlay";
import { pipelineTour } from "./tours/pipeline";

/** All registered tours. New tours should be added here. */
export const ALL_TOURS: Tour[] = [
  workspaceLayoutTour,
  structureOverlayTour,
  pipelineTour,
];

export function findTour(id: string): Tour | undefined {
  return ALL_TOURS.find((t) => t.id === id);
}
