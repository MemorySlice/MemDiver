import { useCallback, useEffect } from "react";
import { useShallow } from "zustand/react/shallow";

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

/**
 * Loads status + settings once and exposes the slice of the chat store the panel renders;
 * the socket outlives the panel. Selecting only these fields keeps unrelated store writes
 * (e.g. chatId, result) from re-rendering the panel.
 */
export function useAgentChat() {
  const chat = useAgentStore(
    useShallow((s) => ({
      items: s.items,
      state: s.state,
      usage: s.usage,
      status: s.status,
      statusError: s.statusError,
      bundle: s.bundle,
      connectionError: s.connectionError,
      saveSettings: s.saveSettings,
      endChat: s.endChat,
      sendMessage: s.sendMessage,
      sendApproval: s.sendApproval,
      interrupt: s.interrupt,
    })),
  );
  const startChat = useAgentStore((s) => s.startChat);
  const loadStatus = useAgentStore((s) => s.loadStatus);
  const loadSettings = useAgentStore((s) => s.loadSettings);
  useEffect(() => {
    void loadStatus();
    loadSettings().catch(() => { /* the status banner already explains an unavailable backend */ });
  }, [loadStatus, loadSettings]);
  const start = useCallback(() => startChat(chatScope()), [startChat]);
  return { ...chat, start };
}
