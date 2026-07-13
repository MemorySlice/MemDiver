import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { deleteSession } from "@/api/client";
import { useAppStore } from "@/stores/app-store";
import { useSessionLoader } from "@/hooks/useSessionLoader";
import { ThemeToggle } from "@/components/ThemeToggle";

const MODE_LABEL_KEYS: Record<string, string> = {
  single_file: "modeLabels.single_file",
  run_directory: "modeLabels.run_directory",
  dataset: "modeLabels.dataset",
};

function formatDate(iso: string): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function SessionLanding() {
  const { t } = useTranslation("landing");
  const { sessions, loading, refresh, loadAndRestore } = useSessionLoader();
  const [loadingSession, setLoadingSession] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const setAppView = useAppStore((s) => s.setAppView);

  const refreshSessions = useCallback(async () => {
    setError(null);
    try {
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadSessionsError"));
    }
  }, [refresh, t]);

  useEffect(() => { refreshSessions(); }, [refreshSessions]);

  const handleLoad = async (name: string) => {
    setLoadingSession(name);
    try {
      await loadAndRestore(name, {
        onError: (msg) => setError(msg),
      });
    } finally {
      // Clear the spinner state regardless of outcome. On success this
      // component is normally unmounted by restoreSession, but clearing
      // here ensures the spinner never sticks if that contract changes.
      setLoadingSession(null);
    }
  };

  const handleDelete = async (name: string) => {
    if (!window.confirm(t("deleteConfirm", { name }))) return;
    try {
      await deleteSession(name);
      refreshSessions();
    } catch {
      // ignore
    }
  };

  return (
    <div className="h-screen flex flex-col" style={{ background: "var(--md-bg-primary)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--md-border)]">
        <div className="flex items-center gap-3">
          <img src="/memdiver-logo.svg" alt="" className="h-8 w-8" />
          <span className="text-xl font-bold md-text-accent">MemDiver</span>
        </div>
        <ThemeToggle />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto flex items-start justify-center pt-12 px-4">
        <div className="w-full max-w-2xl space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">{t("sessions")}</h2>
            <button
              onClick={() => setAppView("wizard")}
              className="px-4 py-2 rounded text-white text-sm font-medium transition-opacity hover:opacity-90"
              style={{ background: "var(--md-accent-blue)" }}
            >
              {t("newSession")}
            </button>
          </div>

          {loading ? (
            <p className="text-sm md-text-muted py-8 text-center">{t("loadingSessions")}</p>
          ) : error ? (
            <div className="text-center py-8 space-y-2">
              <p className="text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>
              <button onClick={refreshSessions} className="text-xs px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
                {t("common:retry")}
              </button>
            </div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-12 space-y-3">
              <p className="text-sm md-text-muted">{t("noSessions")}</p>
              <p className="text-xs md-text-muted">{t("noSessionsHint")}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sessions.map((s) => (
                <div
                  key={s.path}
                  className="md-panel p-3 flex items-center gap-3 hover:bg-[var(--md-bg-hover)] transition-colors rounded"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm truncate">{s.display_name || s.name}</span>
                      {s.input_mode && (
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0"
                          style={{
                            background: "var(--md-accent-blue)",
                            color: "white",
                            opacity: 0.8,
                          }}
                        >
                          {MODE_LABEL_KEYS[s.input_mode] ? t(MODE_LABEL_KEYS[s.input_mode]) : s.input_mode}
                        </span>
                      )}
                      {s.mode && (
                        <span className="text-[10px] md-text-muted shrink-0">{s.mode}</span>
                      )}
                    </div>
                    {s.input_path && (
                      <p className="text-xs md-text-muted font-mono truncate mt-0.5" title={s.input_path}>
                        {s.input_path}
                      </p>
                    )}
                    {s.created_at && (
                      <p className="text-[10px] md-text-muted mt-0.5">{formatDate(s.created_at)}</p>
                    )}
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => handleLoad(s.name)}
                      disabled={loadingSession === s.name}
                      className="px-3 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-accent-blue)] hover:text-white transition-colors disabled:opacity-50"
                    >
                      {loadingSession === s.name ? t("loadingSpinner") : t("common:load")}
                    </button>
                    <button
                      onClick={() => handleDelete(s.name)}
                      className="px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-accent-red)] hover:text-white transition-colors"
                    >
                      {t("common:delete")}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
