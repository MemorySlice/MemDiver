import { useAppStore } from "@/stores/app-store";
import type { Tour } from "../types";

/**
 * Second-run tour: high-level orientation for the IDA-Pro-style workspace.
 * Shows before the structure overlay tour (priority 10 vs. 20). Deliberately
 * has NO requireAction steps — it's a passive walkthrough.
 */
export const workspaceLayoutTour: Tour = {
  id: "workspace-layout-101",
  version: 1,
  priority: 10,
  trigger: {
    kind: "on-condition",
    predicate: () => useAppStore.getState().appView === "workspace",
  },
  steps: [
    {
      id: "welcome",
      placement: "center",
      title: "Welcome to MemDiver",
      body: "Quick 30-second tour of the workspace. Press Esc anytime to dismiss.",
    },
    {
      id: "toolbar",
      target: "workspace-toolbar",
      placement: "bottom",
      title: "Toolbar",
      body: "MemDiver mode (verification vs. exploration), session controls, settings, and theme toggle live up here.",
    },
    {
      id: "sidebar",
      target: "workspace-sidebar",
      placement: "right",
      title: "Sidebar",
      body: "Browse bookmarks, dumps, binary format, structures, sessions, and file upload. Switch tabs to see each.",
    },
    {
      id: "main",
      target: "workspace-main",
      placement: "top",
      title: "Main view",
      body: "Hex viewer when a dump is loaded, or dataset overview for directory mode. This is where you inspect bytes.",
    },
    {
      id: "bottom",
      target: "workspace-bottom",
      placement: "top",
      title: "Analysis panels",
      body: "Analysis config, results, strings, entropy charts, and more. Tabs vary by mode.",
    },
    {
      id: "detail",
      target: "workspace-detail",
      placement: "left",
      title: "Detail inspector",
      body: "Shows parsed structure fields, analysis summaries, or investigation context.",
    },
    {
      id: "done",
      placement: "center",
      title: "You're set",
      body: "Next: try the 'Apply a structure' tour that will start after this one.",
    },
  ],
};
