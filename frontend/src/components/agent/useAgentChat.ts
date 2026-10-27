import { useEffect } from "react";

import { useAgentStore } from "@/stores/agent-store";
import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";
import { caseDirOfView } from "@/components/isf/case-dir";
import type { StartChatBody } from "@/api/agent";

/** Chat scope from the workspace: the case dir (image store, else the active view's case) and open dumps. */
export function chatScope(): StartChatBody {
  const { dumps, activeDumpId } = useDumpStore.getState();
  const active = dumps.find((d) => d.id === activeDumpId);
  const caseDir = useImageStore.getState().caseDir || caseDirOfView(active?.path ?? "");
  const paths = dumps.map((d) => d.path);
  return { ...(caseDir ? { case_dir: caseDir } : {}), ...(paths.length ? { dump_paths: paths } : {}) };
}

/** Loads status + settings once and exposes the chat store; the socket outlives the panel. */
export function useAgentChat() {
  const store = useAgentStore();
  const loadStatus = useAgentStore((s) => s.loadStatus);
  const loadSettings = useAgentStore((s) => s.loadSettings);
  useEffect(() => {
    void loadStatus();
    loadSettings().catch(() => { /* the status banner already explains an unavailable backend */ });
  }, [loadStatus, loadSettings]);
  return { ...store, start: () => store.startChat(chatScope()) };
}
