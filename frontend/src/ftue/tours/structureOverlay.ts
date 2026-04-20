import { useAppStore } from "@/stores/app-store";
import { useHexStore } from "@/stores/hex-store";
import { useFtueStore } from "../store";
import type { Tour } from "../types";

/**
 * Structure-overlay tour: teaches a user how to apply a structure overlay in
 * the workspace. Runs after the workspace-layout-101 tour has been seen
 * (completed OR dismissed).
 */
export const structureOverlayTour: Tour = {
  id: "structure-overlay-101",
  version: 1,
  priority: 20,
  trigger: {
    kind: "on-condition",
    predicate: () => {
      const appStore = useAppStore.getState();
      const ftueStore = useFtueStore.getState();
      if (appStore.appView !== "workspace") return false;
      const seen = ftueStore.seenTours.find((t) => t.id === "workspace-layout-101");
      return !!seen;
    },
  },
  steps: [
    {
      id: "welcome",
      placement: "center",
      title: "Welcome to MemDiver",
      body: "Let's apply your first structure - takes 30 seconds. Click 'Next' to begin.",
    },
    {
      id: "structures-panel",
      target: "structures-panel",
      placement: "right",
      title: "Structure library",
      body: "These are structure layouts you can apply to bytes in the dump. Each one parses memory into named fields.",
    },
    {
      id: "hex-cursor",
      target: "hex-viewer",
      placement: "top",
      title: "Set the cursor",
      body: "Click any byte in this hex view to position your cursor. The structure will be applied starting there.",
      requireAction: {
        description: "Click any byte in the hex view to continue.",
        predicate: () => useHexStore.getState().cursorOffset !== null,
      },
    },
    {
      id: "apply-structure",
      target: "structure-apply-button",
      placement: "right",
      title: "Apply a structure",
      body: "Click the play icon next to any structure to apply it at the cursor.",
      requireAction: {
        description: "Click a structure's play button to continue.",
        predicate: () =>
          useHexStore.getState().activeStructureOverlay !== null,
      },
    },
    {
      id: "overlay-panel",
      target: "structure-overlay-panel",
      placement: "left",
      title: "Explore fields",
      body: "The structure's fields are now color-coded in the hex view. Click any row here to jump to that field.",
    },
    {
      id: "auto-detect",
      target: "structure-autodetect-button",
      placement: "right",
      title: "Auto-detect",
      body: "Not sure which structure fits? 'Auto-detect at cursor' tries all of them and picks the best match.",
    },
    {
      id: "done",
      placement: "center",
      title: "You're ready",
      body: "Re-run this tour anytime from Settings -> Run onboarding tour.",
    },
  ],
};
