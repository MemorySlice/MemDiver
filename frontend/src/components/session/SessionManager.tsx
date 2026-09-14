import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { deleteSession } from "@/api/client";
import { useSessionLoader } from "@/hooks/useSessionLoader";
import { persistSession } from "@/utils/session-persistence";

export function SessionManager() {
  const { t } = useTranslation("session");
  const { sessions, loading, refresh, loadAndRestore } = useSessionLoader();
  const [saveName, setSaveName] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const refreshSessions = useCallback(async () => {
    try {
      await refresh();
    } catch {
      // silently ignore — sessions may not be available
    }
  }, [refresh]);

  useEffect(() => { refreshSessions(); }, [refreshSessions]);

  const handleSave = async () => {
    try {
      // Via persistSession so a manual save also marks the workspace clean --
      // otherwise the "unsaved work" guard would still prompt straight after.
      await persistSession(saveName || "session");
      setMessage(t("manager.saved"));
      setSaveName("");
      refreshSessions();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : t("manager.saveFailed"));
    }
  };

  const handleLoad = async (name: string) => {
    await loadAndRestore(name, {
      onSuccess: (loaded) => setMessage(t("manager.loadedName", { name: loaded })),
      onError: (msg) => setMessage(msg || t("manager.loadFailed")),
    });
  };

  const handleDelete = async (name: string) => {
    try {
      await deleteSession(name);
      refreshSessions();
    } catch {
      // ignore
    }
  };

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("manager.title")}</h3>

      <div className="flex gap-1">
        <input
          value={saveName}
          onChange={(e) => setSaveName(e.target.value)}
          placeholder={t("manager.namePlaceholder")}
          className="flex-1 px-1.5 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
        />
        <button onClick={handleSave}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          {t("common:save")}
        </button>
      </div>

      {message && <p className="md-text-muted">{message}</p>}

      {loading ? (
        <p className="md-text-muted">{t("manager.loadingSessions")}</p>
      ) : sessions.length === 0 ? (
        <p className="md-text-muted">{t("manager.noSessions")}</p>
      ) : (
        <div className="space-y-1">
          {sessions.map((s) => (
            <div key={s.path} className="flex items-center justify-between p-1.5 rounded hover:bg-[var(--md-bg-hover)]">
              <div className="flex-1 min-w-0">
                <div className="font-medium truncate" title={s.display_name || s.name}>{s.display_name || s.name}</div>
                <div className="md-text-muted truncate" title={`${s.created_at} | ${s.mode}`}>{s.created_at} | {s.mode}</div>
              </div>
              <div className="flex gap-1 ml-2 shrink-0">
                <button onClick={() => handleLoad(s.name)}
                  className="px-1 hover:text-[var(--md-accent-blue)]">
                  {t("common:load")}
                </button>
                <button onClick={() => handleDelete(s.name)}
                  className="px-1 hover:text-[var(--md-accent-red)]">
                  x
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
